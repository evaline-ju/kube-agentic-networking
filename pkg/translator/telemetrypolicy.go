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

package translator

import (
	"fmt"
	"sort"

	tracingv3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha1 "sigs.k8s.io/gateway-api/apisx/v1alpha1"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// TracingSettings is the resolved tracing configuration for a Gateway,
// derived from the XTelemetryPolicy targeting it (or implementation defaults).
type TracingSettings struct {
	// Enabled controls whether the HCM emits tracing configuration at all.
	Enabled bool
	// SamplingPercent is the percent of new (parentless) requests to sample, 0-100.
	SamplingPercent float64
	// ClientSamplingPercent is the percent of requests carrying downstream trace
	// context to sample, 0-100. 100 honors every incoming sampled traceparent.
	ClientSamplingPercent float64
	// CustomTags holds span attributes derived from policy attributes (Literal and
	// Header source types). Attribute-source tags are not supported yet.
	CustomTags []*tracingv3.CustomTag
}

// TelemetryBootstrap carries the pieces of the resolved telemetry configuration
// that must be rendered into the static Envoy bootstrap (tracer provider config).
// Changes here require an Envoy proxy rollout.
type TelemetryBootstrap struct {
	TracingEnabled   bool
	ServiceName      string
	CollectorAddress string
	CollectorPort    int
}

// resolveXTelemetryPolicyForGateway returns the single XTelemetryPolicy that
// targets the given Gateway, applying the precedence rules from the API:
// at most one policy per Gateway; the older policy wins (creation timestamp,
// then name). It returns nil when no policy targets the Gateway.
func (t *Translator) resolveXTelemetryPolicyForGateway(gw *gatewayv1.Gateway) *gatewayapiv1alpha1.XTelemetryPolicy {
	if t.xTelemetryPolicyLister == nil {
		return nil
	}
	policies, err := t.xTelemetryPolicyLister.XTelemetryPolicies(gw.Namespace).List(labels.Everything())
	if err != nil {
		klog.Errorf("failed to list XTelemetryPolicies: %v", err)
		return nil
	}

	var winner *gatewayapiv1alpha1.XTelemetryPolicy
	for _, policy := range policies {
		if !telemetryPolicyTargetsGateway(policy, gw) {
			continue
		}
		if winner == nil || isMoreSeniorTelemetryPolicy(policy, winner) {
			winner = policy
		}
	}
	return winner
}

// telemetryPolicyTargetsGateway returns true if any targetRef of the policy
// references the given Gateway. XTelemetryPolicy targetRefs are local (same
// namespace) references.
func telemetryPolicyTargetsGateway(policy *gatewayapiv1alpha1.XTelemetryPolicy, gw *gatewayv1.Gateway) bool {
	for _, ref := range policy.Spec.TargetRefs {
		if ref.Group == gatewayv1.Group(gatewayv1.GroupName) && ref.Kind == gatewayv1.Kind("Gateway") && ref.Name == gatewayv1.ObjectName(gw.Name) {
			return true
		}
	}
	return false
}

// isMoreSeniorTelemetryPolicy returns true if p1 wins precedence over p2:
// older creation timestamp first, then lexicographically smaller name.
func isMoreSeniorTelemetryPolicy(p1, p2 *gatewayapiv1alpha1.XTelemetryPolicy) bool {
	if !p1.CreationTimestamp.Equal(&p2.CreationTimestamp) {
		return p1.CreationTimestamp.Before(&p2.CreationTimestamp)
	}
	return p1.Name < p2.Name
}

// resolveTracingForGateway computes the tracing settings applied to a Gateway's
// Envoy listeners:
//   - No policy: implementation default (flag-configured sampling, parent-based
//     sampling honored).
//   - Policy with mode Enabled: policy sampling rate, parent-based sampling,
//     and custom span attributes.
//   - Policy with mode Disabled: tracing off.
//   - Policy with mode ImplementationDefault: implementation default sampling.
func (t *Translator) resolveTracingForGateway(gw *gatewayv1.Gateway) TracingSettings {
	defaults := TracingSettings{
		Enabled:               t.defaultTracingSampleRate > 0,
		SamplingPercent:       t.defaultTracingSampleRate,
		ClientSamplingPercent: 100.0, // honor incoming sampled traceparent by default
	}
	policy := t.resolveXTelemetryPolicyForGateway(gw)
	if policy == nil {
		return defaults
	}

	switch policy.Spec.Tracing.Mode {
	case gatewayapiv1alpha1.TracingModeDisabled:
		return TracingSettings{Enabled: false}
	case gatewayapiv1alpha1.TracingModeEnabled:
		settings := TracingSettings{
			Enabled:               true,
			SamplingPercent:       defaults.SamplingPercent,
			ClientSamplingPercent: defaults.ClientSamplingPercent,
		}
		if rate := policy.Spec.Tracing.SamplingRate; rate != nil {
			settings.SamplingPercent = fractionToPercent(rate)
		}
		settings.ClientSamplingPercent = resolveParentBasedSampling(policy.Spec.Tracing.ParentBasedSampling, defaults.ClientSamplingPercent)
		settings.CustomTags = buildCustomTagsFromAttributes(policy.Spec.Tracing.Attributes)
		return settings
	default: // ImplementationDefault
		return defaults
	}
}

// resolveParentBasedSampling maps the ParentBasedSampling config to the
// downstream-sampling percent. When Enabled, the parent's sampling decision is
// honored, optionally downsampled by the configured fraction. When Disabled,
// the parent decision is ignored (0% of traced requests are kept).
func resolveParentBasedSampling(pbs gatewayapiv1alpha1.ParentBasedSampling, defaultPercent float64) float64 {
	switch pbs.Mode {
	case gatewayapiv1alpha1.ParentBasedSamplingModeEnabled:
		if pbs.SamplingRate != nil {
			return fractionToPercent(pbs.SamplingRate)
		}
		return 100.0
	case gatewayapiv1alpha1.ParentBasedSamplingModeDisabled:
		return 0.0
	default: // ImplementationDefault
		return defaultPercent
	}
}

// fractionToPercent converts a Fraction (e.g. 10/100) to a percent (10.0).
func fractionToPercent(f *gatewayv1.Fraction) float64 {
	denominator := int64(100)
	if f.Denominator != nil {
		//nolint:gosec // G115: denominator is a positive int32 in practice.
		denominator = int64(*f.Denominator)
	}
	if denominator <= 0 {
		return 0.0
	}
	//nolint:gosec // G115: Fraction validation guarantees numerator >= 0.
	percent := float64(int64(f.Numerator)) / float64(denominator) * 100.0
	if percent > 100.0 {
		return 100.0
	}
	return percent
}

// buildCustomTagsFromAttributes converts XTelemetryPolicy tracing attributes
// into Envoy custom tags. Literal and Header source types are supported;
// Attribute-sourced tags are skipped (not yet supported by this implementation).
func buildCustomTagsFromAttributes(attrs []gatewayapiv1alpha1.Attribute) []*tracingv3.CustomTag {
	if len(attrs) == 0 {
		return nil
	}
	tags := make([]*tracingv3.CustomTag, 0, len(attrs))
	// Emit in a stable order for deterministic config snapshots.
	sorted := make([]gatewayapiv1alpha1.Attribute, len(attrs))
	copy(sorted, attrs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, attr := range sorted {
		var tag *tracingv3.CustomTag
		switch attr.SourceType {
		case gatewayapiv1alpha1.AttributeSourceLiteral:
			tag = &tracingv3.CustomTag{
				Tag: string(attr.Name),
				Type: &tracingv3.CustomTag_Literal_{
					Literal: &tracingv3.CustomTag_Literal{Value: attr.LiteralValue},
				},
			}
		case gatewayapiv1alpha1.AttributeSourceHeader:
			tag = &tracingv3.CustomTag{
				Tag: string(attr.Name),
				Type: &tracingv3.CustomTag_RequestHeader{
					RequestHeader: &tracingv3.CustomTag_Header{
						Name: string(attr.HeaderName),
					},
				},
			}
		default:
			klog.V(2).InfoS("Skipping unsupported telemetry attribute sourceType (not yet supported)",
				"attribute", attr.Name, "sourceType", attr.SourceType)
			continue
		}
		tags = append(tags, tag)
	}
	return tags
}

// ResolveTelemetryBootstrap resolves the XTelemetryPolicy targeting the Gateway
// into bootstrap-level telemetry options: whether the OTel tracer is included,
// its service name, and the collector destination. When a policy enables
// tracing, the collector address comes from provider.backendRef (resolved to a
// Service FQDN). Without a policy, the implementation default collector
// (otel-collector.<gateway-namespace>) is used for backward compatibility.
func (t *Translator) ResolveTelemetryBootstrap(gw *gatewayv1.Gateway) TelemetryBootstrap {
	bootstrap := TelemetryBootstrap{
		TracingEnabled:   t.defaultTracingSampleRate > 0,
		ServiceName:      fmt.Sprintf("envoy-gateway-%s-%s", gw.Namespace, gw.Name),
		CollectorAddress: fmt.Sprintf("otel-collector.%s.svc.cluster.local", gw.Namespace),
		CollectorPort:    int(constants.DefaultOTelCollectorPort),
	}

	policy := t.resolveXTelemetryPolicyForGateway(gw)
	if policy == nil {
		return bootstrap
	}

	switch policy.Spec.Tracing.Mode {
	case gatewayapiv1alpha1.TracingModeDisabled:
		bootstrap.TracingEnabled = false
		return bootstrap
	case gatewayapiv1alpha1.TracingModeEnabled:
		bootstrap.TracingEnabled = true
	default: // ImplementationDefault: keep implementation defaults
		return bootstrap
	}

	if policy.Spec.Tracing.ServiceName != "" {
		bootstrap.ServiceName = policy.Spec.Tracing.ServiceName
	}

	backendRef := policy.Spec.Tracing.Provider.BackendRef
	bootstrap.CollectorAddress = fqdnFromBackendRef(backendRef, policy.Namespace)
	if backendRef.Port != nil {
		bootstrap.CollectorPort = int(*backendRef.Port)
	}
	return bootstrap
}
