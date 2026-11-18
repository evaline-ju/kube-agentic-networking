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
	"context"
	"testing"
	"time"

	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	rbacv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/rbac/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	tlsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	tracingv3 "github.com/envoyproxy/go-control-plane/envoy/type/tracing/v3"
	envoyproxytypes "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha1 "sigs.k8s.io/gateway-api/apisx/v1alpha1"
	gatewayclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayinformers "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions"
	gatewaylistersxv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/listers/apisx/v1alpha1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticv1alpha1 "sigs.k8s.io/kube-agentic-networking/api/v1alpha1"
	agenticclient "sigs.k8s.io/kube-agentic-networking/k8s/client/clientset/versioned/fake"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

type expectedResult struct {
	// listeners is the set of expected Envoy Listeners and their corresponding K8s Gateway listener statuses.
	listeners []expectedListener
	// routes is the set of expected Envoy RouteConfigurations and their corresponding K8s HTTPRoute parent statuses.
	routes []expectedRoute
	// clusters is the list of expected Envoy Cluster names.
	clusters []string
	// secrets is the list of expected Envoy Secret names.
	secrets []string
}

type expectedListener struct {
	// envoyName is the expected name of the Envoy Listener resource (e.g., "listener-10001").
	envoyName string
	// k8sName is the name of the listener in the Gateway spec used to find the corresponding status.
	k8sName string
	// gatewayPrincipals are the SPIFFE IDs expected in the Gateway-level RBAC filters.
	gatewayPrincipals []string
	// maxBackendPolicies is the expected number of placeholder backend-level RBAC filters in the HCM.
	maxBackendPolicies int
	// conditions are the expected status conditions for this listener.
	conditions []metav1.Condition
	// attachedRoutes is the expected number of attached routes.
	attachedRoutes int32
	// expectedIdentitySDS is the expected name of the identity SDS secret config.
	expectedIdentitySDS string
	// expectedTrustSDS is the expected name of the trust SDS secret config.
	expectedTrustSDS string
}

type expectedRoute struct {
	// envoyName is the expected name of the Envoy RouteConfiguration resource (e.g., "route-10001").
	envoyName string
	// k8sName is the name of the K8s HTTPRoute resource used to find the corresponding status.
	k8sName string
	// k8sNamespace is the namespace of the K8s HTTPRoute resource.
	k8sNamespace string
	// backendPrincipals are the SPIFFE IDs expected in the backend-level RBAC filter overrides.
	backendPrincipals []string
	// parentStatuses are the expected parent statuses for this HTTPRoute.
	parentStatuses []gatewayv1.RouteParentStatus
}

func TestTranslateGatewayToXDS_Full(t *testing.T) {
	ns := "quickstart-ns"
	trustDomain := "cluster.local"

	tests := []struct {
		name       string
		gw         *gatewayv1.Gateway
		backend    *agenticv0alpha0.XBackend
		routes     []*gatewayv1.HTTPRoute
		policies   []*agenticv1alpha1.XAccessPolicy
		mcpSvc     *corev1.Service
		secrets    []runtime.Object
		configMaps []runtime.Object
		expected   expectedResult
	}{
		{
			name:    "Basic mTLS and RBAC Translation",
			gw:      newTestGateway("agentic-net-gateway", ns, nil, nil),
			backend: newTestBackend("local-mcp-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("httproute-local-mcp", ns, "agentic-net-gateway", "local-mcp-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("auth-policy-local-mcp", ns, "local-mcp-backend", "XBackend", "spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa"),
			},
			mcpSvc: newTestService("local-mcp-backend-svc", ns, 3001),
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  2,
						expectedIdentitySDS: constants.SpiffeIdentitySdsConfigName,
						expectedTrustSDS:    constants.SpiffeTrustSdsConfigName,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "httproute-local-mcp",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/quickstart-ns/sa/adk-agent-sa"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "agentic-net-gateway"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-local-mcp-backend"},
			},
		},
		{
			name:    "Multiple Policies Targeting Gateway and Backend",
			gw:      newTestGateway("multi-policy-gw", ns, nil, nil),
			backend: newTestBackend("multi-policy-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("multi-policy-route", ns, "multi-policy-gw", "multi-policy-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("gw-policy", ns, "multi-policy-gw", "Gateway", "spiffe://cluster.local/ns/ns1/sa/sa1"),
				newTestAccessPolicy("backend-policy", ns, "multi-policy-backend", "XBackend", "spiffe://cluster.local/ns/ns2/sa/sa2"),
			},
			mcpSvc: &corev1.Service{
				ObjectMeta: metav1.ObjectMeta{Name: "multi-policy-backend-svc", Namespace: ns},
				Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 3001}}},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						gatewayPrincipals:   []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						maxBackendPolicies:  2,
						expectedIdentitySDS: constants.SpiffeIdentitySdsConfigName,
						expectedTrustSDS:    constants.SpiffeTrustSdsConfigName,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "multi-policy-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns2/sa/sa2"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "multi-policy-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-multi-policy-backend"},
			},
		},
		{
			name:    "Multiple Routes Attached to Same Listener",
			gw:      newTestGateway("multi-route-gw", ns, nil, nil),
			backend: newTestBackend("multi-route-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("route-1", ns, "multi-route-gw", "multi-route-backend"),
				newTestHTTPRoute("route-2", ns, "multi-route-gw", "multi-route-backend"),
			},
			policies: nil,
			mcpSvc:   newTestService("multi-route-backend-svc", ns, 3001),
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  0,
						expectedIdentitySDS: constants.SpiffeIdentitySdsConfigName,
						expectedTrustSDS:    constants.SpiffeTrustSdsConfigName,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
						},
						attachedRoutes: 2,
					},
				},
				routes: []expectedRoute{
					{
						envoyName:    "route-10001",
						k8sName:      "route-1",
						k8sNamespace: ns,
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "multi-route-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue},
								},
							},
						},
					},
					{
						envoyName:    "route-10001",
						k8sName:      "route-2",
						k8sNamespace: ns,
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "multi-route-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-multi-route-backend"},
			},
		},
		{
			name: "Listener with Unresolved References (Invalid Route Kind)",
			gw: &gatewayv1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: "invalid-gw"},
				Spec: gatewayv1.GatewaySpec{
					GatewayClassName: "agentic-net-gateway-class",
					Listeners: []gatewayv1.Listener{
						{
							Name:     "https-listener",
							Port:     10001,
							Protocol: gatewayv1.HTTPSProtocolType,
							AllowedRoutes: &gatewayv1.AllowedRoutes{
								Kinds: []gatewayv1.RouteGroupKind{
									{Kind: "TCPRoute"}, // Invalid/Unsupported
								},
							},
						},
					},
				},
			},
			backend:  nil,
			routes:   nil,
			policies: nil,
			mcpSvc:   nil,
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:          "", // No Envoy listener expected
						k8sName:            "https-listener",
						maxBackendPolicies: 0,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionResolvedRefs),
								Status: metav1.ConditionFalse,
								Reason: string(gatewayv1.ListenerReasonInvalidRouteKinds),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName: "route-10001",
						k8sName:   "", // No HTTPRoute status to check
					},
				},
				clusters: nil,
			},
		},
		{
			name:    "Listener with Unresolved Secret Refs still counts AttachedRoutes",
			gw:      newTestGateway("invalid-secret-gw", ns, []gatewayv1.SecretObjectReference{{Name: "missing-cert"}}, nil),
			backend: newTestBackend("backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("route-1", ns, "invalid-secret-gw", "backend"),
			},
			policies: nil,
			mcpSvc:   newTestService("backend-svc", ns, 3001),
			secrets:  nil, // No secrets provided, so "missing-cert" will be unresolved
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:          "", // No Envoy listener expected
						k8sName:            "https-listener",
						maxBackendPolicies: 0,
						attachedRoutes:     1, // THIS IS THE KEY CHECK
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionFalse,
								Reason: string(gatewayv1.ListenerReasonInvalid),
							},
							{
								Type:   string(gatewayv1.ListenerConditionResolvedRefs),
								Status: metav1.ConditionFalse,
								Reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:    "route-10001",
						k8sName:      "route-1",
						k8sNamespace: ns,
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "invalid-secret-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{Type: string(gatewayv1.RouteConditionAccepted), Status: metav1.ConditionTrue},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-backend"},
			},
		},
		{
			name:    "Listener programmed with only cert Ref and use default SPIFFE trust",
			gw:      newTestGateway("cert-only-gw", ns, []gatewayv1.SecretObjectReference{{Name: "my-cert"}}, nil),
			backend: newTestBackend("cert-only-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("cert-only-route", ns, "cert-only-gw", "cert-only-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("cert-only-policy", ns, "cert-only-backend", "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			mcpSvc: newTestService("cert-only-backend-svc", ns, 3001),
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: ns},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
						"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"),
					},
				},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  2,
						expectedIdentitySDS: "quickstart-ns-my-cert",
						expectedTrustSDS:    constants.SpiffeTrustSdsConfigName,
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
							{
								Type:   string(gatewayv1.ListenerConditionResolvedRefs),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonResolvedRefs),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "cert-only-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "cert-only-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-cert-only-backend"},
				secrets:  []string{"quickstart-ns-my-cert"},
			},
		},
		{
			name: "Listener programed with both cert Ref and CA Ref",
			gw: newTestGateway("cert-ca-gw", ns, []gatewayv1.SecretObjectReference{{Name: "my-cert"}}, &gatewayv1.FrontendTLSConfig{
				Default: gatewayv1.TLSConfig{
					Validation: &gatewayv1.FrontendTLSValidation{
						CACertificateRefs: []gatewayv1.ObjectReference{{Name: "my-ca", Kind: "ConfigMap"}},
					},
				},
			}),
			backend: newTestBackend("cert-ca-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("cert-ca-route", ns, "cert-ca-gw", "cert-ca-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("cert-ca-policy", ns, "cert-ca-backend", "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			mcpSvc: newTestService("cert-ca-backend-svc", ns, 3001),
			secrets: []runtime.Object{
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "my-cert", Namespace: ns},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
						"tls.key": []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIB\n-----END RSA PRIVATE KEY-----\n"),
					},
				},
			},
			configMaps: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: ns},
					Data: map[string]string{
						"ca.crt": "ca-data",
					},
				},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  2,
						expectedIdentitySDS: "quickstart-ns-my-cert",
						expectedTrustSDS:    "quickstart-ns-my-ca",
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "cert-ca-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "cert-ca-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-cert-ca-backend"},
				secrets:  []string{"quickstart-ns-my-cert", "quickstart-ns-my-ca"},
			},
		},
		{
			name: "Listener programmed with only CA Ref",
			gw: newTestGateway("ca-only-gw", ns, nil, &gatewayv1.FrontendTLSConfig{
				Default: gatewayv1.TLSConfig{
					Validation: &gatewayv1.FrontendTLSValidation{
						CACertificateRefs: []gatewayv1.ObjectReference{{Name: "my-ca", Kind: "ConfigMap"}},
					},
				},
			}),
			backend: newTestBackend("ca-only-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("ca-only-route", ns, "ca-only-gw", "ca-only-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("ca-only-policy", ns, "ca-only-backend", "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			mcpSvc: newTestService("ca-only-backend-svc", ns, 3001),
			configMaps: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: ns},
					Data: map[string]string{
						"ca.crt": "ca-data",
					},
				},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  2,
						expectedIdentitySDS: constants.SpiffeIdentitySdsConfigName,
						expectedTrustSDS:    "quickstart-ns-my-ca",
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "ca-only-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "ca-only-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-ca-only-backend"},
				secrets:  []string{"quickstart-ns-my-ca"},
			},
		},
		{
			name: "Listener programmed with only per-port CA trust",
			gw: newTestGateway("per-port-ca-gw", ns, nil, &gatewayv1.FrontendTLSConfig{
				PerPort: []gatewayv1.TLSPortConfig{
					{
						Port: 10001,
						TLS: gatewayv1.TLSConfig{
							Validation: &gatewayv1.FrontendTLSValidation{
								CACertificateRefs: []gatewayv1.ObjectReference{{Name: "my-ca", Kind: "ConfigMap"}},
							},
						},
					},
				},
			}),
			backend: newTestBackend("per-port-ca-backend", ns),
			routes: []*gatewayv1.HTTPRoute{
				newTestHTTPRoute("per-port-ca-route", ns, "per-port-ca-gw", "per-port-ca-backend"),
			},
			policies: []*agenticv1alpha1.XAccessPolicy{
				newTestAccessPolicy("per-port-ca-policy", ns, "per-port-ca-backend", "XBackend", "spiffe://cluster.local/ns/ns1/sa/sa1"),
			},
			mcpSvc: newTestService("per-port-ca-backend-svc", ns, 3001),
			configMaps: []runtime.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{Name: "my-ca", Namespace: ns},
					Data: map[string]string{
						"ca.crt": "ca-data",
					},
				},
			},
			expected: expectedResult{
				listeners: []expectedListener{
					{
						envoyName:           "listener-10001",
						k8sName:             "https-listener",
						maxBackendPolicies:  2,
						expectedIdentitySDS: constants.SpiffeIdentitySdsConfigName,
						expectedTrustSDS:    "quickstart-ns-my-ca",
						conditions: []metav1.Condition{
							{
								Type:   string(gatewayv1.ListenerConditionProgrammed),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonProgrammed),
							},
							{
								Type:   string(gatewayv1.ListenerConditionAccepted),
								Status: metav1.ConditionTrue,
								Reason: string(gatewayv1.ListenerReasonAccepted),
							},
						},
					},
				},
				routes: []expectedRoute{
					{
						envoyName:         "route-10001",
						k8sName:           "per-port-ca-route",
						k8sNamespace:      ns,
						backendPrincipals: []string{"spiffe://cluster.local/ns/ns1/sa/sa1"},
						parentStatuses: []gatewayv1.RouteParentStatus{
							{
								ParentRef:      gatewayv1.ParentReference{Name: "per-port-ca-gw"},
								ControllerName: gatewayv1.GatewayController(constants.ControllerName),
								Conditions: []metav1.Condition{
									{
										Type:   string(gatewayv1.RouteConditionAccepted),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonAccepted),
									},
									{
										Type:   string(gatewayv1.RouteConditionResolvedRefs),
										Status: metav1.ConditionTrue,
										Reason: string(gatewayv1.RouteReasonResolvedRefs),
									},
								},
							},
						},
					},
				},
				clusters: []string{"quickstart-ns-per-port-ca-backend"},
				secrets:  []string{"quickstart-ns-my-ca"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Setup Fake Clients and Informers
			ctx := context.Background()

			var k8sObjs []runtime.Object
			if tc.mcpSvc != nil {
				k8sObjs = append(k8sObjs, tc.mcpSvc)
			}
			k8sObjs = append(k8sObjs, tc.secrets...)
			k8sObjs = append(k8sObjs, tc.configMaps...)
			k8sClient := fake.NewClientset(k8sObjs...)
			var gwObjs []runtime.Object
			gwObjs = append(gwObjs, tc.gw)
			for _, r := range tc.routes {
				gwObjs = append(gwObjs, r)
			}

			gwClient := gatewayclient.NewClientset(gwObjs...)

			var agenticObjs []runtime.Object
			if tc.backend != nil {
				agenticObjs = append(agenticObjs, tc.backend)
			}
			for _, p := range tc.policies {
				agenticObjs = append(agenticObjs, p)
			}
			//nolint:staticcheck // generated clientset doesn't have NewClientset without applyconfig
			agenticClient := agenticclient.NewSimpleClientset(agenticObjs...)

			gwInformerFactory := gatewayinformers.NewSharedInformerFactory(gwClient, 0)
			agenticInformerFactory := agenticinformers.NewSharedInformerFactory(agenticClient, 0)
			coreInformerFactory := informers.NewSharedInformerFactory(k8sClient, 0)

			tr := New(
				trustDomain,
				k8sClient,
				gwClient,
				coreInformerFactory.Core().V1().Namespaces().Lister(),
				coreInformerFactory.Core().V1().Services().Lister(),
				coreInformerFactory.Discovery().V1().EndpointSlices().Lister(),
				coreInformerFactory.Core().V1().Secrets().Lister(),
				coreInformerFactory.Core().V1().ConfigMaps().Lister(),
				gwInformerFactory.Gateway().V1().Gateways().Lister(),
				gwInformerFactory.Gateway().V1().HTTPRoutes().Lister(),
				nil, // referenceGrantLister
				agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Lister(),
				agenticInformerFactory.Agentic().V0alpha0().XBackends().Lister(),
				gwInformerFactory.Experimental().V1alpha1().XTelemetryPolicies().Lister(),
				100.0,
			)

			// Populate Informer caches
			if tc.mcpSvc != nil {
				_ = coreInformerFactory.Core().V1().Services().Informer().GetIndexer().Add(tc.mcpSvc)
			}
			_ = gwInformerFactory.Gateway().V1().Gateways().Informer().GetIndexer().Add(tc.gw)
			for _, r := range tc.routes {
				_ = gwInformerFactory.Gateway().V1().HTTPRoutes().Informer().GetIndexer().Add(r)
			}
			if tc.backend != nil {
				_ = agenticInformerFactory.Agentic().V0alpha0().XBackends().Informer().GetIndexer().Add(tc.backend)
			}
			for _, p := range tc.policies {
				_ = agenticInformerFactory.Agentic().V1alpha1().XAccessPolicies().Informer().GetIndexer().Add(p)
			}
			for _, obj := range tc.secrets {
				if secret, ok := obj.(*corev1.Secret); ok {
					_ = coreInformerFactory.Core().V1().Secrets().Informer().GetIndexer().Add(secret)
				}
			}
			for _, obj := range tc.configMaps {
				if cm, ok := obj.(*corev1.ConfigMap); ok {
					_ = coreInformerFactory.Core().V1().ConfigMaps().Informer().GetIndexer().Add(cm)
				}
			}

			// Run Translation
			resources, listenerStatuses, httpRouteStatuses, _, err := tr.TranslateGatewayToXDS(ctx, tc.gw)
			if err != nil {
				t.Fatalf("Translation failed: %v", err)
			}

			// Assertions
			verifyListeners(t, resources[resourcev3.ListenerType], listenerStatuses, tc.expected.listeners)
			verifyRoutes(t, resources[resourcev3.RouteType], httpRouteStatuses, tc.expected.routes)
			verifyClusters(t, resources[resourcev3.ClusterType], tc.expected.clusters)
			verifySecrets(t, resources[resourcev3.SecretType], tc.expected.secrets)
		})
	}
}

func verifyListeners(t *testing.T, got []envoyproxytypes.Resource, gotStatuses []gatewayv1.ListenerStatus, expected []expectedListener) {
	expectedEnvoyListeners := 0
	for _, exp := range expected {
		if exp.envoyName != "" {
			expectedEnvoyListeners++
		}
	}
	if len(got) != expectedEnvoyListeners {
		t.Errorf("expected %d envoy listeners, got %d", expectedEnvoyListeners, len(got))
	}
	for _, exp := range expected {
		// Verify Envoy Listener
		if exp.envoyName != "" {
			found := false
			for _, res := range got {
				lis := res.(*listenerv3.Listener)
				if lis.GetName() == exp.envoyName {
					found = true
					checkListenerMTLS(t, lis, exp.expectedIdentitySDS, exp.expectedTrustSDS)
					checkListenerRBAC(t, lis, exp.gatewayPrincipals, exp.maxBackendPolicies)
				}
			}
			if !found {
				t.Errorf("expected listener %s not found", exp.envoyName)
			}
		}

		// Verify Listener Status
		var ls *gatewayv1.ListenerStatus
		for i := range gotStatuses {
			if string(gotStatuses[i].Name) == exp.k8sName {
				ls = &gotStatuses[i]
				break
			}
		}
		if ls == nil {
			t.Errorf("expected listener status %s not found", exp.k8sName)
			continue
		}
		for _, expCond := range exp.conditions {
			actualCond := meta.FindStatusCondition(ls.Conditions, expCond.Type)
			if actualCond == nil {
				t.Errorf("expected condition %s not found", expCond.Type)
				continue
			}
			if actualCond.Status != expCond.Status {
				t.Errorf("expected condition %s status %v, got %v", expCond.Type, expCond.Status, actualCond.Status)
			}
			if expCond.Reason != "" && actualCond.Reason != expCond.Reason {
				t.Errorf("expected condition %s reason %s, got %s", expCond.Type, expCond.Reason, actualCond.Reason)
			}
		}
		if exp.attachedRoutes != 0 {
			if ls.AttachedRoutes != exp.attachedRoutes {
				t.Errorf("expected listener %s to have %d attached routes, got %d", exp.k8sName, exp.attachedRoutes, ls.AttachedRoutes)
			}
		}
	}
}

func verifyRoutes(t *testing.T, got []envoyproxytypes.Resource, gotStatuses map[types.NamespacedName][]gatewayv1.RouteParentStatus, expected []expectedRoute) {
	uniqueEnvoyNames := make(map[string]bool)
	for _, exp := range expected {
		uniqueEnvoyNames[exp.envoyName] = true
	}
	if len(got) != len(uniqueEnvoyNames) {
		t.Errorf("expected %d route configurations, got %d", len(uniqueEnvoyNames), len(got))
	}
	for _, exp := range expected {
		// Verify Envoy Route Configuration
		found := false
		for _, res := range got {
			rc := res.(*routev3.RouteConfiguration)
			if rc.GetName() == exp.envoyName {
				found = true
				checkRouteRBAC(t, rc, exp.backendPrincipals)
			}
		}
		if !found {
			t.Errorf("expected route configuration %s not found", exp.envoyName)
		}

		// Verify HTTPRoute Status
		if exp.k8sName == "" {
			continue
		}
		key := types.NamespacedName{Namespace: exp.k8sNamespace, Name: exp.k8sName}
		actualStatuses, ok := gotStatuses[key]
		if !ok {
			t.Errorf("expected http route status for %s", key)
			continue
		}
		if len(actualStatuses) != len(exp.parentStatuses) {
			t.Errorf("expected %d route parent statuses for %s, got %d", len(exp.parentStatuses), key, len(actualStatuses))
			continue
		}
		for i, expStatus := range exp.parentStatuses {
			got := actualStatuses[i]
			if got.ParentRef.Name != expStatus.ParentRef.Name {
				t.Errorf("expected parent ref name %s for %s, got %s", expStatus.ParentRef.Name, key, got.ParentRef.Name)
			}
			if got.ControllerName != expStatus.ControllerName {
				t.Errorf("expected controller name %s for %s, got %s", expStatus.ControllerName, key, got.ControllerName)
			}
			for _, expCond := range expStatus.Conditions {
				actualCond := meta.FindStatusCondition(got.Conditions, expCond.Type)
				if actualCond == nil {
					t.Errorf("expected condition %s not found on route %s", expCond.Type, key)
					continue
				}
				if actualCond.Status != expCond.Status {
					t.Errorf("expected route %s condition %s status %v, got %v", key, expCond.Type, expCond.Status, actualCond.Status)
				}
				if expCond.Reason != "" && actualCond.Reason != expCond.Reason {
					t.Errorf("expected route %s condition %s reason %s, got %s", key, expCond.Type, expCond.Reason, actualCond.Reason)
				}
			}
		}
	}
}

func verifyClusters(t *testing.T, got []envoyproxytypes.Resource, expected []string) {
	if len(got) != len(expected) {
		t.Errorf("expected %d clusters, got %d", len(expected), len(got))
	}
	for _, expectedName := range expected {
		found := false
		for _, res := range got {
			cl := res.(*clusterv3.Cluster)
			if cl.GetName() == expectedName {
				found = true
			}
		}
		if !found {
			t.Errorf("expected cluster %s not found", expectedName)
		}
	}
}

func verifySecrets(t *testing.T, got []envoyproxytypes.Resource, expected []string) {
	if len(got) != len(expected) {
		t.Errorf("expected %d secrets, got %d", len(expected), len(got))
	}
	for _, expectedName := range expected {
		found := false
		for _, res := range got {
			s := res.(*tlsv3.Secret)
			if s.GetName() == expectedName {
				found = true
			}
		}
		if !found {
			t.Errorf("expected secret %s not found", expectedName)
		}
	}
}

func checkListenerMTLS(t *testing.T, lis *listenerv3.Listener, expectedIdentity, expectedTrust string) {
	foundTLS := false
	for _, fc := range lis.GetFilterChains() {
		if fc.GetTransportSocket() == nil || fc.GetTransportSocket().GetName() != "envoy.transport_sockets.tls" {
			continue
		}
		foundTLS = true
		tlsContext := &tlsv3.DownstreamTlsContext{}
		if err := fc.GetTransportSocket().GetTypedConfig().UnmarshalTo(tlsContext); err != nil {
			t.Fatalf("failed to unmarshal TLS context: %v", err)
		}
		common := tlsContext.GetCommonTlsContext()
		if common.GetTlsCertificateSdsSecretConfigs()[0].GetName() != expectedIdentity {
			t.Errorf("Identity SDS config name mismatch: got %s, want %s", common.GetTlsCertificateSdsSecretConfigs()[0].GetName(), expectedIdentity)
		}
		if !tlsContext.GetRequireClientCertificate().GetValue() {
			t.Error("RequireClientCertificate should be true for mTLS")
		}
		if common.GetValidationContextSdsSecretConfig().GetName() != expectedTrust {
			t.Errorf("Trust SDS config name mismatch: got %s, want %s", common.GetValidationContextSdsSecretConfig().GetName(), expectedTrust)
		}
	}
	if !foundTLS {
		t.Errorf("TLS transport socket configuration not found in listener %s", lis.GetName())
	}
}

// checkRouteRBAC verifies the RBAC configuration at the route level.
// It checks that all provided principals are present in the BackendAllow filter override.
func checkRouteRBAC(t *testing.T, rc *routev3.RouteConfiguration, expectedPrincipals []string) {
	for _, vh := range rc.GetVirtualHosts() {
		for _, r := range vh.GetRoutes() {
			if routeAction := r.GetRoute(); routeAction != nil {
				if weightedClusters := routeAction.GetWeightedClusters(); weightedClusters != nil {
					for _, wc := range weightedClusters.GetClusters() {
						filterName := constants.BackendAllowRBACFilterName
						rbacTypedConfig, ok := wc.GetTypedPerFilterConfig()[filterName]
						if ok != (len(expectedPrincipals) > 0) {
							t.Errorf("Backend Allow RBAC filter %s presence mismatch: expected to have policies=%v, found filter=%v", filterName, len(expectedPrincipals) > 0, ok)
							continue
						}
						if !ok {
							continue
						}

						rbacPerRoute := &rbacv3.RBACPerRoute{}
						if err := rbacTypedConfig.UnmarshalTo(rbacPerRoute); err != nil {
							t.Fatalf("failed to unmarshal RBACPerRoute: %v", err)
						}

						actualPrincipals := getPrincipals(rbacPerRoute.GetRbac())
						expPrincipals := sortedCopy(expectedPrincipals)

						if !compareSlices(actualPrincipals, expPrincipals) {
							t.Errorf("RBAC policy for cluster %s filter %s: expected principals %v, got %v", wc.GetName(), filterName, expPrincipals, actualPrincipals)
						}
					}
				}
			}
		}
	}
}

// checkListenerRBAC verifies the RBAC configuration at the listener level.
// It checks that:
// 1. The HTTP Connection Manager has the expected Gateway Allow filter if principals are expected.
// 2. The HTTP Connection Manager has both Backend ExtAuth and Allow filters if backend policies are expected.
func checkListenerRBAC(t *testing.T, lis *listenerv3.Listener, expectedGWPrincipals []string, expectedBackendFilters int) {
	for _, fc := range lis.GetFilterChains() {
		for _, filter := range fc.GetFilters() {
			if filter.GetName() == wellknown.HTTPConnectionManager {
				hcmConfig := &hcm.HttpConnectionManager{}
				if err := filter.GetTypedConfig().UnmarshalTo(hcmConfig); err != nil {
					t.Fatalf("failed to unmarshal HCM config: %v", err)
				}

				foundGatewayAllow := false
				foundBackendExtAuth := false
				foundBackendAllow := false

				for _, httpFilter := range hcmConfig.GetHttpFilters() {
					switch httpFilter.GetName() {
					case constants.GatewayAllowRBACFilterName:
						foundGatewayAllow = true
						rbacConfig := &rbacv3.RBAC{}
						if err := httpFilter.GetTypedConfig().UnmarshalTo(rbacConfig); err != nil {
							t.Fatalf("failed to unmarshal RBAC config from listener: %v", err)
						}
						actualPrincipals := getPrincipals(rbacConfig)
						expPrincipals := sortedCopy(expectedGWPrincipals)

						if !compareSlices(actualPrincipals, expPrincipals) {
							t.Errorf("Listener %s Gateway Allow filter: expected principals %v, got %v", lis.GetName(), expPrincipals, actualPrincipals)
						}
					case constants.BackendExtAuthRBACFilterName:
						foundBackendExtAuth = true
					case constants.BackendAllowRBACFilterName:
						foundBackendAllow = true
					}
				}

				if (len(expectedGWPrincipals) > 0) != foundGatewayAllow {
					t.Errorf("Gateway Allow filter presence mismatch: expected to have policies=%v, found filter=%v", len(expectedGWPrincipals) > 0, foundGatewayAllow)
				}

				if expectedBackendFilters > 0 {
					if !foundBackendExtAuth {
						t.Errorf("expected Backend ExtAuth filter %s not found", constants.BackendExtAuthRBACFilterName)
					}
					if !foundBackendAllow {
						t.Errorf("expected Backend Allow filter %s not found", constants.BackendAllowRBACFilterName)
					}
				}
			}
		}
	}
}

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
