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

// IMPORTANT: Run "make generate" to regenerate code after modifying this file

package v0alpha0

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// GuardrailPolicySpec defines the desired state of a GuardrailPolicy.
type GuardrailPolicySpec struct {
	// TargetRefs specifies the targets of the GuardrailPolicy.
	// A GuardrailPolicy must target at least one resource.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(x, x.group == 'agentic.prototype.x-k8s.io' && x.kind == 'XBackend')",message="TargetRef must have group agentic.prototype.x-k8s.io and kind XBackend"
	TargetRefs []gwapiv1.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// ExtProcessors defines the list of external processing services to apply
	// to traffic targeting the referenced backends.
	// +required
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=10
	// +listType=atomic
	// +kubebuilder:validation:XValidation:rule="self.all(p, self.filter(x, x.name == p.name).size() == 1)",message="ExtProcessor names must be unique"
	ExtProcessors []ExtProcessorRef `json:"extProcessors"`
}

// ExtProcessorRef specifies a reference to an ext_proc gRPC service and its configuration.
type ExtProcessorRef struct {
	// Name is a unique identifier for this processor within the policy.
	// It is used to generate the Envoy cluster and filter names.
	// +required
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Name string `json:"name"`

	// ServiceRef references the Kubernetes Service that implements the ext_proc gRPC API.
	// +required
	ServiceRef ServiceReference `json:"serviceRef"`

	// ProcessingMode controls which request/response phases are sent to this processor.
	// If not specified, defaults to buffered request/response bodies with headers sent.
	// +optional
	ProcessingMode *ProcessingModeSpec `json:"processingMode,omitempty"`

	// Timeout is the maximum duration for a gRPC call to the ext_proc service.
	// Defaults to 5s.
	// +optional
	Timeout *metav1.Duration `json:"timeout,omitempty"`

	// FailureModeAllow controls what happens when the ext_proc service is unreachable.
	// If true, traffic is allowed through. If false (default), traffic is rejected.
	// +optional
	FailureModeAllow bool `json:"failureModeAllow,omitempty"`
}

// ServiceReference identifies a Kubernetes Service.
type ServiceReference struct {
	// Name is the name of the Kubernetes Service.
	// +required
	Name string `json:"name"`

	// Namespace is the namespace of the Service.
	// If not specified, the namespace of the GuardrailPolicy is used.
	// +optional
	Namespace string `json:"namespace,omitempty"`

	// Port is the port on which the ext_proc gRPC service is listening.
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ProcessingModeSpec controls which request/response phases are sent to the ext_proc service.
type ProcessingModeSpec struct {
	// RequestHeaders controls whether request headers are sent.
	// Valid values are SEND and SKIP.
	// Defaults to SEND.
	// +optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	RequestHeaders *HeaderProcessingMode `json:"requestHeaders,omitempty"`

	// ResponseHeaders controls whether response headers are sent.
	// Valid values are SEND and SKIP.
	// Defaults to SEND.
	// +optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	ResponseHeaders *HeaderProcessingMode `json:"responseHeaders,omitempty"`

	// RequestBody controls how the request body is sent.
	// Valid values are BUFFERED, STREAMED, and SKIP.
	// Defaults to BUFFERED.
	// +optional
	// +kubebuilder:validation:Enum=BUFFERED;STREAMED;SKIP
	RequestBody *BodyProcessingMode `json:"requestBody,omitempty"`

	// ResponseBody controls how the response body is sent.
	// Valid values are BUFFERED, STREAMED, and SKIP.
	// Defaults to BUFFERED.
	// +optional
	// +kubebuilder:validation:Enum=BUFFERED;STREAMED;SKIP
	ResponseBody *BodyProcessingMode `json:"responseBody,omitempty"`
}

// HeaderProcessingMode specifies how headers are processed.
// +kubebuilder:validation:Enum=SEND;SKIP
type HeaderProcessingMode string

const (
	HeaderProcessingModeSend HeaderProcessingMode = "SEND"
	HeaderProcessingModeSkip HeaderProcessingMode = "SKIP"
)

// BodyProcessingMode specifies how bodies are processed.
// +kubebuilder:validation:Enum=BUFFERED;STREAMED;SKIP
type BodyProcessingMode string

const (
	BodyProcessingModeBuffered BodyProcessingMode = "BUFFERED"
	BodyProcessingModeStreamed BodyProcessingMode = "STREAMED"
	BodyProcessingModeSkip     BodyProcessingMode = "SKIP"
)

// GuardrailPolicyStatus defines the observed state of a GuardrailPolicy.
type GuardrailPolicyStatus struct {
	// Ancestors is a list of ancestor resources (usually Backend) that are
	// associated with the policy, and the status of the policy with respect to
	// each ancestor.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Ancestors []gwapiv1.PolicyAncestorStatus `json:"ancestors"`
}

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// XGuardrailPolicy is the Schema for the guardrailpolicies API.
type XGuardrailPolicy struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is a standard object metadata.
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// spec defines the desired state of GuardrailPolicy.
	// +required
	Spec GuardrailPolicySpec `json:"spec"`

	// status defines the observed state of GuardrailPolicy.
	// +optional
	Status GuardrailPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// XGuardrailPolicyList contains a list of GuardrailPolicy.
type XGuardrailPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	// metadata is a standard list metadata.
	// +optional
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []XGuardrailPolicy `json:"items"`
}
