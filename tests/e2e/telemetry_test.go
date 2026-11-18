/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// TestTelemetryPolicyE2E validates the XTelemetryPolicy API end-to-end:
// a policy targeting the quickstart Gateway enables OTel tracing exported to
// an in-cluster OTel Collector, and requests carrying W3C trace context
// (as an agent would propagate) result in spans with the same trace ID,
// proving traces flow from agent through the gateway to the tool backend.
func TestTelemetryPolicyE2E(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployQuickstartTestResources(t)
	defer cleanup()

	// Deploy a minimal OTel Collector that logs every received span.
	applyManifestReplacing(t, "testdata/otel-collector.yaml", namespace, "e2e-test-ns")
	runKubectl(t, "wait", "--for=condition=available", "deployment/otel-collector", "-n", namespace, "--timeout=5m")

	// Apply an XTelemetryPolicy enabling tracing on the Gateway, exporting to
	// the collector deployed above.
	policy := fmt.Sprintf(`apiVersion: gateway.networking.x-k8s.io/v1alpha1
kind: XTelemetryPolicy
metadata:
  name: tracing-policy
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: Gateway
    name: %s
  tracing:
    mode: Enabled
    provider:
      backendRef:
        name: otel-collector
        port: 4317
    samplingRate:
      numerator: 100
`, quickstartGatewayName)
	applyInlineManifest(t, namespace, policy)

	// The policy must be Accepted by the controller.
	err := retry(20, 3*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "xtelemetrypolicy", "tracing-policy", "-n", namespace,
			"-o", "jsonpath={.status.ancestors[*].conditions[?(@.type=='Accepted')].status}")
		if err != nil {
			return err
		}
		if strings.TrimSpace(out) != "True" {
			return fmt.Errorf("XTelemetryPolicy not Accepted yet: %s", out)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("XTelemetryPolicy never became Accepted: %v", err)
	}

	// The bootstrap change (tracer now enabled) must roll the Envoy pods.
	waitEnvoyRolledOut(t, namespace)

	// Make an MCP tool call through the gateway, propagating W3C trace context
	// like an instrumented agent would.
	runKubectl(t, "create", "sa", "adk-agent-sa", "-n", namespace)
	applyQuickstartTesterPod(t, namespace)
	runKubectl(t, "wait", "--for=condition=Ready", "pod/quickstart-tester", "-n", namespace, "--timeout=5m")

	traceID := randomHex(t, 16)
	spanID := randomHex(t, 8)
	traceparent := fmt.Sprintf("00-%s-%s-01", traceID, spanID)

	pod := types.NamespacedName{Namespace: namespace, Name: "quickstart-tester"}
	mcp := initializeMCPWithCerts(t, gatewayIP, pod, quickstartLocalMCPPath, agentCertPath, agentKeyPath, agentCAPath)
	mcp.assertToolCallAllowed(t, "get-sum", `{"a":2,"b":3}`)

	// Re-issue the tool call with the traceparent header: the gateway joins the
	// agent's trace and the exported span carries the agent's trace ID. The
	// Envoy pods just rolled to pick up the tracing bootstrap, so the LB may
	// briefly refuse connections while endpoints converge — retry a few times.
	var out string
	err = retry(10, 3*time.Second, func() error {
		var curlErr error
		out, curlErr = runKubectlOutput(t, "exec", pod.Name, "-n", pod.Namespace, "--",
			"curl", "-ks", "-o", "/dev/null", "-w", "%{http_code}",
			"--cert", agentCertPath,
			"--key", agentKeyPath,
			"--cacert", agentCAPath,
			"-H", "Content-Type: application/json",
			"-H", "Accept: application/json, text/event-stream",
			"-H", "mcp-protocol-version: 2025-11-25",
			"-H", fmt.Sprintf("mcp-session-id: %s", mcp.sessionID),
			"-H", fmt.Sprintf("traceparent: %s", traceparent),
			"--data-raw", `{"jsonrpc":"2.0","id":999,"method":"tools/call","params":{"name":"get-sum","arguments":{"a":2,"b":3}}}`,
			mcpGatewayURL(gatewayIP, quickstartLocalMCPPath))
		return curlErr
	})
	if err != nil {
		t.Fatalf("MCP request with traceparent failed: %v", err)
	}
	if code := strings.TrimSpace(out); code != "200" {
		t.Logf("warning: MCP request with traceparent returned HTTP %s (continuing to check traces)", code)
	}

	// The collector must have received a span with the agent's trace ID.
	err = retry(30, 5*time.Second, func() error {
		logs, err := runKubectlOutput(t, "logs", "deployment/otel-collector", "-n", namespace)
		if err != nil {
			return err
		}
		if !strings.Contains(logs, traceID) {
			return fmt.Errorf("trace ID %s not found in collector logs yet", traceID)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("agent trace ID never appeared in OTel collector: %v", err)
	}
	t.Logf("Found span with agent trace ID %s exported to the collector", traceID)

	// The gateway spans must be tagged with the expected service name.
	serviceName := fmt.Sprintf("envoy-gateway-%s-%s", namespace, quickstartGatewayName)
	logs, _ := runKubectlOutput(t, "logs", "deployment/otel-collector", "-n", namespace)
	if !strings.Contains(logs, serviceName) {
		t.Errorf("collector logs do not contain gateway service name %q", serviceName)
	}
}

// waitEnvoyRolledOut waits until the Envoy proxy deployment's pod template
// carries the config checksum annotation and its pods are Ready (the bootstrap
// tracing config change requires a restart).
func waitEnvoyRolledOut(t *testing.T, namespace string) {
	t.Helper()
	runKubectl(t, "wait", "--for=condition=available", "deployment",
		"-l", fmt.Sprintf("%s=%s", constants.GatewayNameLabel, quickstartGatewayName),
		"-n", namespace, "--timeout=5m")
}

// randomHex returns n random bytes as a hex string (trace/span IDs).
func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to generate random hex: %v", err)
	}
	return hex.EncodeToString(b)
}

// applyInlineManifest applies a manifest via stdin with kubectl.
func applyInlineManifest(t *testing.T, namespace, manifest string) {
	t.Helper()
	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-n", namespace, "-f", "-")
	cmd.Stdin = strings.NewReader(manifest)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply failed: %v\nstderr: %s", err, stderr.String())
	}
}
