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
	"testing"
	"time"

	tracingv3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha1 "sigs.k8s.io/gateway-api/apisx/v1alpha1"
	gatewaylistersxv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/listers/apisx/v1alpha1"
)

func newTelemetryTranslator(t *testing.T, sampleRate float64, policies ...runtime.Object) *Translator {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{})
	for _, p := range policies {
		if err := indexer.Add(p); err != nil {
			t.Fatalf("failed to add policy to indexer: %v", err)
		}
	}
	return &Translator{
		xTelemetryPolicyLister:   gatewaylistersxv1alpha1.NewXTelemetryPolicyLister(indexer),
		defaultTracingSampleRate: sampleRate,
	}
}

func telemetryGateway() *gatewayv1.Gateway {
	return &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "quickstart-ns", Name: "agentic-net-gateway"},
	}
}

func policyForGateway(mode gatewayapiv1alpha1.TracingMode, mutate func(*gatewayapiv1alpha1.XTelemetryPolicy)) *gatewayapiv1alpha1.XTelemetryPolicy {
	p := &gatewayapiv1alpha1.XTelemetryPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: "quickstart-ns", Name: "tracing-policy"},
		Spec: gatewayapiv1alpha1.TelemetryPolicySpec{
			TargetRefs: []gatewayv1.LocalObjectReference{
				{Group: gatewayv1.Group(gatewayv1.GroupName), Kind: gatewayv1.Kind("Gateway"), Name: gatewayv1.ObjectName("agentic-net-gateway")},
			},
			Tracing: gatewayapiv1alpha1.TracingConfig{
				Mode: mode,
				Provider: gatewayapiv1alpha1.TracingProvider{
					BackendRef: gatewayv1.BackendObjectReference{
						Name: gatewayv1.ObjectName("otel-collector"),
						Port: ptr.To[gatewayv1.PortNumber](4317),
					},
				},
			},
		},
	}
	if mutate != nil {
		mutate(p)
	}
	return p
}

func TestResolveTracingForGateway_NoPolicy(t *testing.T) {
	tr := newTelemetryTranslator(t, 50.0)
	got := tr.resolveTracingForGateway(telemetryGateway())
	if !got.Enabled || got.SamplingPercent != 50.0 || got.ClientSamplingPercent != 100.0 {
		t.Errorf("resolveTracingForGateway() = %+v, want enabled with 50%% sampling and 100%% client sampling", got)
	}
}

func TestResolveTracingForGateway_DefaultDisabledWhenSampleRateZero(t *testing.T) {
	tr := newTelemetryTranslator(t, 0.0)
	got := tr.resolveTracingForGateway(telemetryGateway())
	if got.Enabled {
		t.Errorf("resolveTracingForGateway() = %+v, want disabled when implementation default sample rate is 0", got)
	}
}

func TestResolveTracingForGateway_ModeDisabled(t *testing.T) {
	tr := newTelemetryTranslator(t, 100.0, policyForGateway(gatewayapiv1alpha1.TracingModeDisabled, nil))
	got := tr.resolveTracingForGateway(telemetryGateway())
	if got.Enabled {
		t.Errorf("resolveTracingForGateway() = %+v, want disabled", got)
	}
}

func TestResolveTracingForGateway_ModeEnabled(t *testing.T) {
	tr := newTelemetryTranslator(t, 100.0, policyForGateway(gatewayapiv1alpha1.TracingModeEnabled, func(p *gatewayapiv1alpha1.XTelemetryPolicy) {
		p.Spec.Tracing.SamplingRate = &gatewayv1.Fraction{Numerator: 25}
		p.Spec.Tracing.ParentBasedSampling = gatewayapiv1alpha1.ParentBasedSampling{
			Mode:         gatewayapiv1alpha1.ParentBasedSamplingModeDisabled,
			SamplingRate: nil,
		}
	}))
	got := tr.resolveTracingForGateway(telemetryGateway())
	if !got.Enabled || got.SamplingPercent != 25.0 {
		t.Errorf("resolveTracingForGateway() = %+v, want enabled with 25%% sampling", got)
	}
	if got.ClientSamplingPercent != 0.0 {
		t.Errorf("ClientSamplingPercent = %v, want 0 when parent-based sampling is disabled", got.ClientSamplingPercent)
	}
}

func TestResolveTracingForGateway_ModeImplementationDefault(t *testing.T) {
	tr := newTelemetryTranslator(t, 75.0, policyForGateway(gatewayapiv1alpha1.TracingModeImplementationDefault, nil))
	got := tr.resolveTracingForGateway(telemetryGateway())
	if !got.Enabled || got.SamplingPercent != 75.0 {
		t.Errorf("resolveTracingForGateway() = %+v, want implementation default 75%% sampling", got)
	}
}

func TestResolveXTelemetryPolicyForGateway_OldestWins(t *testing.T) {
	older := policyForGateway(gatewayapiv1alpha1.TracingModeDisabled, func(p *gatewayapiv1alpha1.XTelemetryPolicy) {
		p.Name = "a-older"
		p.CreationTimestamp = metav1.NewTime(metav1.Now().Add(-time.Minute))
	})
	newer := policyForGateway(gatewayapiv1alpha1.TracingModeEnabled, func(p *gatewayapiv1alpha1.XTelemetryPolicy) {
		p.Name = "b-newer"
		p.CreationTimestamp = metav1.Now()
	})
	tr := newTelemetryTranslator(t, 100.0, newer, older)
	got := tr.resolveXTelemetryPolicyForGateway(telemetryGateway())
	if got == nil || got.Name != "a-older" {
		t.Errorf("resolveXTelemetryPolicyForGateway() = %v, want oldest policy a-older to win", got)
	}
}

func TestResolveXTelemetryPolicyForGateway_IgnoresOtherGateways(t *testing.T) {
	p := policyForGateway(gatewayapiv1alpha1.TracingModeDisabled, nil)
	p.Spec.TargetRefs[0].Name = gatewayv1.ObjectName("other-gateway")
	tr := newTelemetryTranslator(t, 100.0, p)
	if got := tr.resolveXTelemetryPolicyForGateway(telemetryGateway()); got != nil {
		t.Errorf("resolveXTelemetryPolicyForGateway() = %v, want nil for policy targeting another Gateway", got)
	}
}

func TestResolveTelemetryBootstrap_NoPolicyDefaults(t *testing.T) {
	tr := newTelemetryTranslator(t, 100.0)
	got := tr.ResolveTelemetryBootstrap(telemetryGateway())
	if !got.TracingEnabled {
		t.Error("TracingEnabled = false, want true with non-zero default sample rate")
	}
	if want := "envoy-gateway-quickstart-ns-agentic-net-gateway"; got.ServiceName != want {
		t.Errorf("ServiceName = %q, want %q", got.ServiceName, want)
	}
	if want := "otel-collector.quickstart-ns.svc.cluster.local"; got.CollectorAddress != want {
		t.Errorf("CollectorAddress = %q, want %q", got.CollectorAddress, want)
	}
	if got.CollectorPort != 4317 {
		t.Errorf("CollectorPort = %d, want 4317", got.CollectorPort)
	}
}

func TestResolveTelemetryBootstrap_PolicyBackendRef(t *testing.T) {
	tr := newTelemetryTranslator(t, 100.0, policyForGateway(gatewayapiv1alpha1.TracingModeEnabled, func(p *gatewayapiv1alpha1.XTelemetryPolicy) {
		p.Spec.Tracing.ServiceName = "custom-gateway"
		ns := gatewayv1.Namespace("observability")
		p.Spec.Tracing.Provider.BackendRef.Namespace = &ns
		p.Spec.Tracing.Provider.BackendRef.Port = ptr.To[gatewayv1.PortNumber](43170)
	}))
	got := tr.ResolveTelemetryBootstrap(telemetryGateway())
	if got.ServiceName != "custom-gateway" {
		t.Errorf("ServiceName = %q, want custom-gateway", got.ServiceName)
	}
	if want := "otel-collector.observability.svc.cluster.local"; got.CollectorAddress != want {
		t.Errorf("CollectorAddress = %q, want %q", got.CollectorAddress, want)
	}
	if got.CollectorPort != 43170 {
		t.Errorf("CollectorPort = %d, want 43170", got.CollectorPort)
	}
}

func TestResolveTelemetryBootstrap_ModeDisabled(t *testing.T) {
	tr := newTelemetryTranslator(t, 100.0, policyForGateway(gatewayapiv1alpha1.TracingModeDisabled, nil))
	if got := tr.ResolveTelemetryBootstrap(telemetryGateway()); got.TracingEnabled {
		t.Error("TracingEnabled = true, want false for mode Disabled")
	}
}

func TestFractionToPercent(t *testing.T) {
	tests := []struct {
		name string
		frac gatewayv1.Fraction
		want float64
	}{
		{name: "simple percent", frac: gatewayv1.Fraction{Numerator: 10}, want: 10.0},
		{name: "fraction", frac: gatewayv1.Fraction{Numerator: 1, Denominator: ptr.To[int32](1000)}, want: 0.1},
		{name: "over 100 clamped", frac: gatewayv1.Fraction{Numerator: 200}, want: 100.0},
		{name: "zero denominator", frac: gatewayv1.Fraction{Numerator: 1, Denominator: ptr.To[int32](0)}, want: 0.0},
		{name: "zero numerator", frac: gatewayv1.Fraction{Numerator: 0}, want: 0.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			frac := tc.frac
			if got := fractionToPercent(&frac); got != tc.want {
				t.Errorf("fractionToPercent(%+v) = %v, want %v", tc.frac, got, tc.want)
			}
		})
	}
}

func TestBuildCustomTagsFromAttributes(t *testing.T) {
	attrs := []gatewayapiv1alpha1.Attribute{
		{Name: "zzz-literal", SourceType: gatewayapiv1alpha1.AttributeSourceLiteral, LiteralValue: "static"},
		{Name: "aaa-header", SourceType: gatewayapiv1alpha1.AttributeSourceHeader, HeaderName: "x-agent-id"},
		{Name: "mmm-attribute", SourceType: gatewayapiv1alpha1.AttributeSourceAttribute, AttributeKey: "http.request.method"},
	}
	tags := buildCustomTagsFromAttributes(attrs)
	if len(tags) != 2 {
		t.Fatalf("len(tags) = %d, want 2 (Attribute source skipped)", len(tags))
	}
	// Sorted by name for determinism.
	if tags[0].Tag != "aaa-header" || tags[1].Tag != "zzz-literal" {
		t.Errorf("tags = [%s %s], want sorted [aaa-header zzz-literal]", tags[0].Tag, tags[1].Tag)
	}
	if lit, ok := tags[1].Type.(*tracingv3.CustomTag_Literal_); !ok || lit.Literal.Value != "static" {
		t.Errorf("literal tag = %+v, want value static", tags[1].Type)
	}
	if hdr, ok := tags[0].Type.(*tracingv3.CustomTag_RequestHeader); !ok || hdr.RequestHeader.Name != "x-agent-id" {
		t.Errorf("header tag = %+v, want x-agent-id", tags[0].Type)
	}
}
