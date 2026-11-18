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

package controller

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"k8s.io/utils/ptr"

	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiv1alpha1 "sigs.k8s.io/gateway-api/apisx/v1alpha1"
	gatewayinformersxv1alpha1 "sigs.k8s.io/gateway-api/pkg/client/informers/externalversions/apisx/v1alpha1"

	"sigs.k8s.io/kube-agentic-networking/pkg/constants"
)

// TelemetryPolicyTargetRefIndex is the index name for looking up XTelemetryPolicies
// by target ref (namespace/name of Gateway).
const TelemetryPolicyTargetRefIndex = "telemetryPolicyTargetRef"

// telemetryPolicyTargetRefIndexFunc indexes XTelemetryPolicies by each Gateway
// targetRef (namespace/name), so Service and Gateway events can find affected
// policies without listing everything.
func telemetryPolicyTargetRefIndexFunc(obj interface{}) ([]string, error) {
	policy, ok := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if !ok {
		return nil, nil
	}
	var keys []string
	for _, targetRef := range policy.Spec.TargetRefs {
		if !isTelemetryGatewayTargetRef(targetRef) {
			continue
		}
		keys = append(keys, policy.Namespace+"/"+string(targetRef.Name))
	}
	return keys, nil
}

func isTelemetryGatewayTargetRef(targetRef gwapiv1.LocalObjectReference) bool {
	return targetRef.Group == gwapiv1.Group(gwapiv1.GroupName) && targetRef.Kind == gwapiv1.Kind("Gateway")
}

func (c *Controller) setupTelemetryPolicyEventHandlers(telemetryPolicyInformer gatewayinformersxv1alpha1.XTelemetryPolicyInformer) error {
	if err := telemetryPolicyInformer.Informer().AddIndexers(cache.Indexers{
		TelemetryPolicyTargetRefIndex: telemetryPolicyTargetRefIndexFunc,
	}); err != nil {
		return fmt.Errorf("add XTelemetryPolicy targetRef index: %w", err)
	}
	_, err := telemetryPolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onTelemetryPolicyAdd,
		UpdateFunc: c.onTelemetryPolicyUpdate,
		DeleteFunc: c.onTelemetryPolicyDelete,
	})
	return err
}

func (c *Controller) onTelemetryPolicyAdd(obj interface{}) {
	policy := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	klog.V(4).InfoS("Adding XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(policy))
	c.reconcileTelemetryPolicies(context.Background(), policy.Namespace)
}

func (c *Controller) onTelemetryPolicyUpdate(old, newObj interface{}) {
	oldPolicy := old.(*gatewayapiv1alpha1.XTelemetryPolicy)
	newPolicy := newObj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if newPolicy.Generation != oldPolicy.Generation || newPolicy.DeletionTimestamp != oldPolicy.DeletionTimestamp {
		klog.V(4).InfoS("Updating XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(newPolicy))
		c.reconcileTelemetryPolicies(context.Background(), newPolicy.Namespace)
	}
}

func (c *Controller) onTelemetryPolicyDelete(obj interface{}) {
	policy, ok := obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		policy, ok = tombstone.Obj.(*gatewayapiv1alpha1.XTelemetryPolicy)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not an XTelemetryPolicy %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting XTelemetryPolicy", "xtelemetrypolicy", klog.KObj(policy))
	// Deleting the winning policy may resolve a conflict for another policy, so
	// re-evaluate every telemetry policy in the namespace.
	c.reconcileTelemetryPolicies(context.Background(), policy.Namespace)
}

// reconcileTelemetryPolicies re-evaluates all XTelemetryPolicies in a namespace:
// it resolves conflicts (at most one policy per Gateway, oldest wins), validates
// targetRefs and provider backendRefs, updates policy statuses, and enqueues the
// Gateways targeted by any policy so their Envoy config is regenerated.
func (c *Controller) reconcileTelemetryPolicies(ctx context.Context, namespace string) {
	policies, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(namespace).List(labels.Everything())
	if err != nil {
		runtime.HandleError(fmt.Errorf("failed to list XTelemetryPolicies: %w", err))
		return
	}

	// Track the winning policy per targeted Gateway (namespace/name).
	gatewayKeyToWinningPolicy := make(map[string]*gatewayapiv1alpha1.XTelemetryPolicy)
	for _, policy := range policies {
		if policy.DeletionTimestamp != nil {
			continue
		}
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isTelemetryGatewayTargetRef(targetRef) {
				continue
			}
			key := policy.Namespace + "/" + string(targetRef.Name)
			if winner, ok := gatewayKeyToWinningPolicy[key]; !ok || isMoreSeniorTelemetryPolicy(policy, winner) {
				gatewayKeyToWinningPolicy[key] = policy
			}
		}
	}

	for _, policy := range policies {
		c.validateTelemetryPolicy(ctx, policy, gatewayKeyToWinningPolicy)
	}

	// Enqueue every Gateway targeted by any policy (winners pick up new config;
	// losers and deletes fall back to defaults).
	targeted := sets.New[string]()
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if !isTelemetryGatewayTargetRef(targetRef) {
				continue
			}
			targeted.Insert(policy.Namespace + "/" + string(targetRef.Name))
		}
	}
	for key := range targeted {
		c.gatewayqueue.Add(key)
	}
}

// isMoreSeniorTelemetryPolicy returns true if p1 wins precedence over p2:
// older creation timestamp first, then lexicographically smaller name.
func isMoreSeniorTelemetryPolicy(p1, p2 *gatewayapiv1alpha1.XTelemetryPolicy) bool {
	if !p1.CreationTimestamp.Equal(&p2.CreationTimestamp) {
		return p1.CreationTimestamp.Before(&p2.CreationTimestamp)
	}
	return p1.Name < p2.Name
}

// validateTelemetryPolicy validates one XTelemetryPolicy and updates its status.
// It checks: valid Gateway targetRefs, supported attribute source types,
// conflict resolution against the winning policy map, and provider backendRef
// resolution (Service existence and cross-namespace ReferenceGrant permission).
func (c *Controller) validateTelemetryPolicy(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKeyToWinningPolicy map[string]*gatewayapiv1alpha1.XTelemetryPolicy) {
	type targetStatus struct {
		accepted bool
		reason   gwapiv1.PolicyConditionReason
		message  string
	}
	statuses := make(map[string]targetStatus, len(policy.Spec.TargetRefs))

	for _, targetRef := range policy.Spec.TargetRefs {
		key := policy.Namespace + "/" + string(targetRef.Name)
		accepted := true
		reason := gwapiv1.PolicyReasonAccepted
		message := "XTelemetryPolicy accepted for target"

		switch {
		case !isTelemetryGatewayTargetRef(targetRef):
			accepted = false
			reason = gwapiv1.PolicyReasonInvalid
			message = fmt.Sprintf("Unsupported targetRef group/kind %s/%s: only Gateway is supported", targetRef.Group, targetRef.Kind)
		default:
			if winner, ok := gatewayKeyToWinningPolicy[key]; ok && winner.Name != policy.Name {
				accepted = false
				reason = gwapiv1.PolicyReasonConflicted
				message = fmt.Sprintf("Another XTelemetryPolicy (%s) already targets Gateway %s; only one policy per Gateway is allowed", winner.Name, targetRef.Name)
			}
		}
		statuses[key] = targetStatus{accepted, reason, message}
	}

	// Validate tracing attributes: only Literal and Header source types are supported.
	for _, attr := range policy.Spec.Tracing.Attributes {
		if attr.SourceType == gatewayapiv1alpha1.AttributeSourceAttribute {
			for key := range statuses {
				s := statuses[key]
				s.accepted = false
				s.reason = gwapiv1.PolicyReasonInvalid
				s.message = fmt.Sprintf("Attribute %q uses sourceType Attribute, which is not yet supported by this implementation", attr.Name)
				statuses[key] = s
			}
		}
	}

	// Validate the provider backendRef when tracing is enabled: it must be a
	// Service that exists and is permitted by ReferenceGrant for cross-namespace refs.
	if policy.Spec.Tracing.Mode == gatewayapiv1alpha1.TracingModeEnabled {
		backendRef := policy.Spec.Tracing.Provider.BackendRef
		kind := gwapiv1.Kind("Service")
		if backendRef.Kind != nil {
			kind = *backendRef.Kind
		}
		group := gwapiv1.Group("")
		if backendRef.Group != nil {
			group = *backendRef.Group
		}

		resolvedRef := true
		switch {
		case group != gwapiv1.Group("") || kind != gwapiv1.Kind("Service"):
			for key := range statuses {
				c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "InvalidKind",
					fmt.Sprintf("Tracing provider backendRef must reference a Service, got %s/%s", group, kind))
			}
			resolvedRef = false
		default:
			backendNamespace := policy.Namespace
			if backendRef.Namespace != nil {
				backendNamespace = string(*backendRef.Namespace)
			}
			if _, err := c.core.svcLister.Services(backendNamespace).Get(string(backendRef.Name)); err != nil {
				if apierrors.IsNotFound(err) {
					for key := range statuses {
						c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "BackendNotFound",
							fmt.Sprintf("Tracing provider backendRef Service %s/%s not found", backendNamespace, backendRef.Name))
					}
				} else {
					runtime.HandleError(fmt.Errorf("failed to get Service %s/%s for XTelemetryPolicy %s: %w", backendNamespace, backendRef.Name, policy.Name, err))
				}
				resolvedRef = false
			} else if !allowedByReferenceGrantForTelemetry(backendNamespace, policy.Namespace, string(backendRef.Name), c) {
				for key := range statuses {
					c.updateTelemetryPolicyResolvedRefs(ctx, policy, key, false, "RefNotPermitted",
						fmt.Sprintf("Tracing provider backendRef Service %s/%s is not permitted by a ReferenceGrant", backendNamespace, backendRef.Name))
				}
				resolvedRef = false
			}
		}
		if !resolvedRef {
			// An unresolved backend also invalidates acceptance of the policy.
			for key, s := range statuses {
				if s.accepted {
					s.accepted = false
					s.reason = gwapiv1.PolicyReasonInvalid
					s.message = "Tracing provider backendRef could not be resolved"
					statuses[key] = s
				}
			}
		}
	}

	for key, s := range statuses {
		if err := c.updateTelemetryPolicyStatus(ctx, policy, key, s.accepted, s.reason, s.message); err != nil {
			runtime.HandleError(fmt.Errorf("failed to update XTelemetryPolicy status: %w", err))
		}
	}
}

// allowedByReferenceGrantForTelemetry checks whether the policy's namespace is
// permitted to reference a Service in backendNamespace.
func allowedByReferenceGrantForTelemetry(backendNamespace, policyNamespace, serviceName string, c *Controller) bool {
	if backendNamespace == policyNamespace {
		return true
	}
	grants, err := c.gateway.referenceGrantLister.ReferenceGrants(backendNamespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list ReferenceGrants", "namespace", backendNamespace)
		return false
	}
	for _, g := range grants {
		for _, from := range g.Spec.From {
			if string(from.Namespace) != policyNamespace || string(from.Group) != gwapiv1.GroupName || string(from.Kind) != "XTelemetryPolicy" {
				continue
			}
			for _, to := range g.Spec.To {
				if to.Group != gwapiv1.Group(corev1.GroupName) || to.Kind != gwapiv1.Kind("Service") {
					continue
				}
				if to.Name != nil && string(*to.Name) != serviceName {
					continue
				}
				return true
			}
		}
	}
	return false
}

// updateTelemetryPolicyStatus sets the Accepted condition for the given target
// (namespace/name of a Gateway) on the policy status.
func (c *Controller) updateTelemetryPolicyStatus(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKey string, accepted bool, reason gwapiv1.PolicyConditionReason, message string) error {
	_, gwName, _ := strings.Cut(gatewayKey, "/")
	parentRef := gwapiv1.ParentReference{
		Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
		Kind:      ptr.To(gwapiv1.Kind("Gateway")),
		Namespace: ptr.To(gwapiv1.Namespace(policy.Namespace)),
		Name:      gwapiv1.ObjectName(gwName),
	}
	conditionStatus := metav1.ConditionFalse
	if accepted {
		conditionStatus = metav1.ConditionTrue
	}
	return c.updateTelemetryPolicyConditions(ctx, policy, parentRef, []metav1.Condition{{
		Type:               string(gwapiv1.PolicyConditionAccepted),
		Status:             conditionStatus,
		Reason:             string(reason),
		Message:            message,
		ObservedGeneration: policy.Generation,
	}})
}

// updateTelemetryPolicyResolvedRefs sets the ResolvedRefs condition for the given
// target on the policy status.
func (c *Controller) updateTelemetryPolicyResolvedRefs(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, gatewayKey string, resolved bool, reason, message string) error {
	_, gwName, _ := strings.Cut(gatewayKey, "/")
	parentRef := gwapiv1.ParentReference{
		Group:     ptr.To(gwapiv1.Group(gwapiv1.GroupName)),
		Kind:      ptr.To(gwapiv1.Kind("Gateway")),
		Namespace: ptr.To(gwapiv1.Namespace(policy.Namespace)),
		Name:      gwapiv1.ObjectName(gwName),
	}
	conditionStatus := metav1.ConditionFalse
	if resolved {
		conditionStatus = metav1.ConditionTrue
	}
	return c.updateTelemetryPolicyConditions(ctx, policy, parentRef, []metav1.Condition{{
		Type:               "ResolvedRefs",
		Status:             conditionStatus,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: policy.Generation,
	}})
}

// updateTelemetryPolicyConditions applies conditions to the policy status for the
// ancestor matching parentRef, creating the ancestor entry if needed.
func (c *Controller) updateTelemetryPolicyConditions(ctx context.Context, policy *gatewayapiv1alpha1.XTelemetryPolicy, parentRef gwapiv1.ParentReference, conditions []metav1.Condition) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(policy.Namespace).Get(policy.Name)
		if err != nil {
			return err
		}
		policyCopy := fresh.DeepCopy()

		var ancestorStatus *gwapiv1.PolicyAncestorStatus
		for i := range policyCopy.Status.Ancestors {
			if reflect.DeepEqual(policyCopy.Status.Ancestors[i].AncestorRef, parentRef) {
				ancestorStatus = &policyCopy.Status.Ancestors[i]
				break
			}
		}
		if ancestorStatus == nil {
			if len(policyCopy.Status.Ancestors) >= 16 {
				return nil // status list is full; API max is 16 ancestors
			}
			policyCopy.Status.Ancestors = append(policyCopy.Status.Ancestors, gwapiv1.PolicyAncestorStatus{
				AncestorRef:    parentRef,
				ControllerName: gwapiv1.GatewayController(constants.ControllerName),
			})
			ancestorStatus = &policyCopy.Status.Ancestors[len(policyCopy.Status.Ancestors)-1]
		}
		for _, cond := range conditions {
			meta.SetStatusCondition(&ancestorStatus.Conditions, cond)
		}

		if reflect.DeepEqual(fresh.Status, policyCopy.Status) {
			return nil
		}
		_, err = c.gateway.client.ExperimentalV1alpha1().XTelemetryPolicies(policy.Namespace).UpdateStatus(ctx, policyCopy, metav1.UpdateOptions{})
		return err
	})
}

// hasTelemetryPoliciesTargetingGateway returns true if any XTelemetryPolicy has a
// targetRef to the given Gateway. Used to block Gateway finalizer removal until
// all targeting telemetry policies are removed (avoids dangling refs).
func hasTelemetryPoliciesTargetingGateway(c *Controller, gw *gwapiv1.Gateway) bool {
	policies, err := c.gateway.xTelemetryPolicyLister.XTelemetryPolicies(gw.Namespace).List(labels.Everything())
	if err != nil {
		klog.V(4).ErrorS(err, "failed to list XTelemetryPolicies for Gateway finalizer")
		return true // conservatively block
	}
	for _, policy := range policies {
		for _, targetRef := range policy.Spec.TargetRefs {
			if isTelemetryGatewayTargetRef(targetRef) && string(targetRef.Name) == gw.Name {
				return true
			}
		}
	}
	return false
}

