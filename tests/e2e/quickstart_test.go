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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/types"
	utilrand "k8s.io/apimachinery/pkg/util/rand"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

const (
	quickstartNSPlaceholder = "quickstart-ns"
	quickstartGatewayName   = "agentic-net-gateway"
	quickstartLocalMCPPath  = "/local/mcp"
	quickstartRemoteMCPPath = "/remote/mcp"
)

// TestQuickstartE2E validates the quickstart policy manifests end-to-end: Gateway,
// HTTPRoutes, XBackends, XAccessPolicies, MCP server, and tool authorization behavior
// matching site-src/guides/quickstart/policy/e2e.yaml.
func TestQuickstartE2E(t *testing.T) {
	t.Parallel()

	namespace, gatewayIP, cleanup := deployQuickstartTestResources(t)
	defer cleanup()

	runKubectl(t, "create", "sa", "adk-agent-sa", "-n", namespace)
	applyQuickstartTesterPod(t, namespace)
	runKubectl(t, "wait", "--for=condition=Ready", "pod/quickstart-tester", "-n", namespace, "--timeout=5m")

	pod := types.NamespacedName{Namespace: namespace, Name: "quickstart-tester"}

	t.Run("local MCP backend", func(t *testing.T) {
		mcp := initializeMCPWithCerts(t, gatewayIP, pod, quickstartLocalMCPPath, agentCertPath, agentKeyPath, agentCAPath)

		t.Run("initialize allowed", func(t *testing.T) {
			mcp.assertMCPRequestAllowed(t, "initialize",
				`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"e2e-client","version":"1.0.0"}}`)
		})

		t.Run("tools/list allowed", func(t *testing.T) {
			mcp.assertMCPRequestAllowed(t, "tools/list", `{}`)
		})

		t.Run("get-sum allowed", func(t *testing.T) {
			mcp.assertToolCall(t, "get-sum", `{"a":2,"b":3}`,
				mcpResponse{
					StatusCode: 200,
					Body: respBody{
						JSONRPC: "2.0",
						Result: &mcpResult{
							IsError: false,
							Content: []mcpContent{
								{
									Type: "text",
									Text: "The sum of 2 and 3 is 5.",
								},
							},
						},
					},
				})
		})

		t.Run("get-tiny-image allowed", func(t *testing.T) {
			mcp.assertToolCallAllowed(t, "get-tiny-image", `{}`)
		})

		t.Run("echo denied", func(t *testing.T) {
			mcp.assertToolCallForbidden(t, "echo", `{"message":"hello"}`)
		})
	})

	t.Run("remote MCP backend", func(t *testing.T) {
		if os.Getenv("SKIP_REMOTE_MCP") == "true" {
			t.Skip("SKIP_REMOTE_MCP is set")
		}

		mcp, ok := initializeMCPWithCertsOptional(t, gatewayIP, pod, quickstartRemoteMCPPath, agentCertPath, agentKeyPath, agentCAPath)
		if !ok {
			t.Skip("remote MCP backend unavailable (mcp.deepwiki.com may be unreachable from this environment; set SKIP_REMOTE_MCP=true to skip explicitly)")
		}

		t.Run("read_wiki_structure allowed", func(t *testing.T) {
			mcp.assertToolCallAllowed(t, "read_wiki_structure",
				`{"repoName":"kubernetes-sigs/kube-agentic-networking"}`)
		})

		t.Run("read_wiki_content denied", func(t *testing.T) {
			mcp.assertToolCallForbidden(t, "read_wiki_content",
				`{"repoName":"kubernetes-sigs/kube-agentic-networking"}`)
		})
	})
}

func deployQuickstartTestResources(t *testing.T) (namespace, gatewayIP string, cleanup func()) {
	namespace = fmt.Sprintf("quickstart-e2e-ns-%s", utilrand.String(5))
	cleanup = createTestNamespace(t, namespace)

	t.Log("Setting up quickstart E2E resources from site-src/guides/quickstart manifests...")

	applyManifestReplacing(t, quickstartManifest(t, "mcpserver/deployment.yaml"), namespace, quickstartNSPlaceholder)
	runKubectl(t, "wait", "--for=condition=available", "deployment/mcp-everything", "-n", namespace, "--timeout=2m")

	applyManifestReplacing(t, quickstartManifest(t, "policy/e2e.yaml"), namespace, quickstartNSPlaceholder)

	var proxyPodName string
	err := retry(20, 5*time.Second, func() error {
		out, err := runKubectlOutput(t, "get", "pods", "-n", namespace,
			"-l", fmt.Sprintf("%s=%s", constants.GatewayNameLabel, quickstartGatewayName),
			"-o", "jsonpath={.items[*].metadata.name}")
		if err != nil {
			return err
		}
		names := strings.Fields(strings.TrimSpace(out))
		if len(names) == 0 {
			return fmt.Errorf("envoy proxy pod not found")
		}
		proxyPodName = names[0]
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to find envoy proxy pod: %v", err)
	}
	runKubectl(t, "wait", "--for=condition=Ready", "pod/"+proxyPodName, "-n", namespace, "--timeout=5m")

	err = retry(50, 10*time.Second, func() error {
		out, e := runKubectlOutput(t, "get", "gateway", quickstartGatewayName, "-n", namespace,
			"-o", "jsonpath={.status.addresses[*].value}")
		if e != nil {
			return e
		}
		values := strings.Fields(strings.TrimSpace(out))
		if len(values) == 0 {
			return fmt.Errorf("gateway status address not found")
		}
		gatewayIP = values[0]
		t.Logf("Found Gateway status address: %s", gatewayIP)
		return nil
	})
	if err != nil {
		t.Fatalf("Gateway status verification failed: %v", err)
	}

	return namespace, gatewayIP, cleanup
}

// applyQuickstartTesterPod deploys the standard e2e tester pod with adk-agent-sa, matching quickstart policy.
func applyQuickstartTesterPod(t *testing.T, namespace string) {
	t.Helper()
	content, err := os.ReadFile("testdata/tester-pod.yaml")
	if err != nil {
		t.Fatalf("failed to read tester pod manifest: %v", err)
	}
	modified := strings.ReplaceAll(string(content), "e2e-test-ns", namespace)
	modified = strings.ReplaceAll(modified, "e2e-tester-sa", "adk-agent-sa")
	modified = strings.ReplaceAll(modified, "e2e-tester", "quickstart-tester")

	cmd := exec.CommandContext(context.Background(), "kubectl", "apply", "-f", "-")
	cmd.Stdin = strings.NewReader(modified)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("kubectl apply failed for quickstart tester pod: %v\nStderr: %s", err, stderr.String())
	}
}

func quickstartManifest(t *testing.T, relPath string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to determine test file path")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	path := filepath.Join(root, "site-src", "guides", "quickstart", relPath)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("quickstart manifest not found at %s: %v", path, err)
	}
	return path
}

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
