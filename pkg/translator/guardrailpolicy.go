/*
Copyright 2025 The Kubernetes Authors.

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

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/klog/v2"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// extProcClusterName returns the Envoy cluster name for an ext-proc processor.
func extProcClusterName(processorName string) string {
	return fmt.Sprintf(constants.ExtProcClusterNameFormat, processorName)
}

// findGuardrailPoliciesForBackend returns all XGuardrailPolicy resources that target the given backend.
func (t *Translator) findGuardrailPoliciesForBackend(backend *agenticv0alpha0.XBackend) ([]*agenticv0alpha0.XGuardrailPolicy, error) {
	allPolicies, err := t.guardrailPolicyLister.XGuardrailPolicies(backend.Namespace).List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list GuardrailPolicies in namespace %s: %w", backend.Namespace, err)
	}

	var matching []*agenticv0alpha0.XGuardrailPolicy
	for _, policy := range allPolicies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if targetRef.Group == agenticv0alpha0.GroupName && targetRef.Kind == "XBackend" && string(targetRef.Name) == backend.Name {
				matching = append(matching, policy)
				break
			}
		}
	}
	return matching, nil
}

// collectExtProcessors gathers all ExtProcessorRef entries from guardrail policies
// that target the given backends. It deduplicates by processor name.
func (t *Translator) collectExtProcessors(backends []*agenticv0alpha0.XBackend) ([]agenticv0alpha0.ExtProcessorRef, error) {
	seen := make(map[string]bool)
	var processors []agenticv0alpha0.ExtProcessorRef

	for _, backend := range backends {
		policies, err := t.findGuardrailPoliciesForBackend(backend)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies {
			for _, proc := range policy.Spec.ExtProcessors {
				if !seen[proc.Name] {
					seen[proc.Name] = true
					// Resolve namespace: default to the policy's namespace if not specified.
					if proc.ServiceRef.Namespace == "" {
						proc.ServiceRef.Namespace = policy.Namespace
					}
					processors = append(processors, proc)
				}
			}
		}
	}
	return processors, nil
}

// extProcServiceFQDN returns the fully qualified DNS name for an ext-proc service.
func extProcServiceFQDN(ref agenticv0alpha0.ServiceReference) string {
	return fmt.Sprintf("%s.%s.svc.cluster.local", ref.Name, ref.Namespace)
}

// collectBackendsForGateway returns all unique XBackend resources referenced by
// HTTPRoutes attached to the given gateway. This is used to find GuardrailPolicy
// resources that target those backends.
func (t *Translator) collectBackendsForGateway(gateway *gatewayv1.Gateway) []*agenticv0alpha0.XBackend {
	seen := make(map[string]bool)
	var backends []*agenticv0alpha0.XBackend

	routes := t.getHTTPRoutesForGateway(gateway)
	for _, route := range routes {
		for _, rule := range route.Spec.Rules {
			for _, backendRef := range rule.BackendRefs {
				ns := route.Namespace
				if backendRef.Namespace != nil {
					ns = string(*backendRef.Namespace)
				}
				key := fmt.Sprintf("%s/%s", ns, backendRef.Name)
				if seen[key] {
					continue
				}
				seen[key] = true

				backend, err := t.fetchBackend(ns, backendRef.BackendRef)
				if err != nil {
					klog.V(4).Infof("skipping backend %s for guardrail policy resolution: %v", key, err)
					continue
				}
				backends = append(backends, backend)
			}
		}
	}
	return backends
}
