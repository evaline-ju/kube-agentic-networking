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

package controller

import (
	"fmt"
	"reflect"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
	"k8s.io/klog/v2"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	agenticv0alpha0 "sigs.k8s.io/kube-agentic-networking/api/v0alpha0"
	agenticinformers "sigs.k8s.io/kube-agentic-networking/k8s/client/informers/externalversions/api/v0alpha0"
)

func (c *Controller) setupGuardrailPolicyEventHandlers(guardrailPolicyInformer agenticinformers.XGuardrailPolicyInformer) error {
	_, err := guardrailPolicyInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    c.onGuardrailPolicyAdd,
		UpdateFunc: c.onGuardrailPolicyUpdate,
		DeleteFunc: c.onGuardrailPolicyDelete,
	})
	return err
}

func (c *Controller) onGuardrailPolicyAdd(obj interface{}) {
	policy := obj.(*agenticv0alpha0.XGuardrailPolicy)
	klog.V(4).InfoS("Adding GuardrailPolicy", "guardrailpolicy", klog.KObj(policy))
	c.enqueueGatewaysForGuardrailPolicy(policy)
}

func (c *Controller) onGuardrailPolicyUpdate(old, new interface{}) {
	oldPolicy := old.(*agenticv0alpha0.XGuardrailPolicy)
	newPolicy := new.(*agenticv0alpha0.XGuardrailPolicy)
	if newPolicy.Generation != oldPolicy.Generation || newPolicy.DeletionTimestamp != oldPolicy.DeletionTimestamp || !reflect.DeepEqual(newPolicy.Annotations, oldPolicy.Annotations) {
		klog.V(4).InfoS("Updating GuardrailPolicy", "guardrailpolicy", klog.KObj(oldPolicy))
		c.enqueueGatewaysForGuardrailPolicy(newPolicy)
	}
}

func (c *Controller) onGuardrailPolicyDelete(obj interface{}) {
	policy, ok := obj.(*agenticv0alpha0.XGuardrailPolicy)
	if !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("couldn't get object from tombstone %#v", obj))
			return
		}
		policy, ok = tombstone.Obj.(*agenticv0alpha0.XGuardrailPolicy)
		if !ok {
			runtime.HandleError(fmt.Errorf("tombstone contained object that is not a GuardrailPolicy %#v", obj))
			return
		}
	}
	klog.V(4).InfoS("Deleting GuardrailPolicy", "guardrailpolicy", klog.KObj(policy))
	c.enqueueGatewaysForGuardrailPolicy(policy)
}

// enqueueGatewaysForGuardrailPolicy looks up the backends targeted by the policy
// and enqueues the gateways that serve those backends for reconciliation.
func (c *Controller) enqueueGatewaysForGuardrailPolicy(policy *agenticv0alpha0.XGuardrailPolicy) {
	for _, targetRef := range policy.Spec.TargetRefs {
		if !isGuardrailXBackendTargetRef(targetRef) {
			klog.InfoS("GuardrailPolicy targets an unsupported resource", "guardrailpolicy", klog.KObj(policy), "targetRef", targetRef)
			continue
		}

		backend, err := c.agentic.backendLister.XBackends(policy.Namespace).Get(string(targetRef.Name))
		if err != nil {
			if apierrors.IsNotFound(err) {
				klog.InfoS("GuardrailPolicy targets a non-existent Backend", "guardrailpolicy", klog.KObj(policy), "backend", types.NamespacedName{Namespace: policy.Namespace, Name: string(targetRef.Name)})
			} else {
				runtime.HandleError(fmt.Errorf("failed to get backend %s/%s targeted by guardrail policy %s: %w", policy.Namespace, targetRef.Name, policy.Name, err))
			}
			continue
		}
		c.enqueueGatewaysForBackend(backend)
	}
}

func isGuardrailXBackendTargetRef(targetRef gwapiv1.LocalPolicyTargetReferenceWithSectionName) bool {
	return targetRef.Group == agenticv0alpha0.GroupName && targetRef.Kind == "XBackend"
}
