// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// HealthCheck configuration to decide which endpoints
// are healthy and can be used for routing.
type HealthCheck struct {
	// Active health check configuration
	// +optional
	Active *ActiveHealthCheck `json:"active,omitempty"`

	// Passive passive check configuration
	// +optional
	Passive *PassiveHealthCheck `json:"passive,omitempty"`

	// When number of unhealthy endpoints for a backend reaches this threshold
	// Envoy will disregard health status and balance across all endpoints.
	// It's designed to prevent a situation in which host failures cascade throughout the cluster
	// as load increases. If not set, the default value is 50%. To disable panic mode, set value to `0`.
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	// +optional
	PanicThreshold *uint32 `json:"panicThreshold,omitempty"`
}

// PassiveHealthCheck defines the configuration for passive health checks in the context of Envoy's Outlier Detection,
// see https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/upstream/outlier
type PassiveHealthCheck struct {
	// SplitExternalLocalOriginErrors enables splitting of errors between external and local origin.
	//
	// +kubebuilder:default=false
	// +optional
	SplitExternalLocalOriginErrors *bool `json:"splitExternalLocalOriginErrors,omitempty"`

	// Interval defines the time between passive health checks.
	//
	// +kubebuilder:validation:Format=duration
	// +kubebuilder:default="3s"
	// +optional
	Interval *metav1.Duration `json:"interval,omitempty"`

	// ConsecutiveLocalOriginFailures sets the number of consecutive local origin failures triggering ejection.
	// Parameter takes effect only when split_external_local_origin_errors is set to true.
	//
	// +kubebuilder:default=5
	// +optional
	ConsecutiveLocalOriginFailures *uint32 `json:"consecutiveLocalOriginFailures,omitempty"`

	// ConsecutiveGatewayErrors sets the number of consecutive gateway errors triggering ejection.
	//
	// +kubebuilder:default=0
	// +optional
	ConsecutiveGatewayErrors *uint32 `json:"consecutiveGatewayErrors,omitempty"`

	// Consecutive5xxErrors sets the number of consecutive 5xx errors triggering ejection.
	//
	// +kubebuilder:default=5
	// +optional
	Consecutive5xxErrors *uint32 `json:"consecutive5XxErrors,omitempty"`

	// BaseEjectionTime defines the base duration for which a host will be ejected on consecutive failures.
	//
	// +kubebuilder:validation:Format=duration
	// +kubebuilder:default="30s"
	// +optional
	BaseEjectionTime *metav1.Duration `json:"baseEjectionTime,omitempty"`

	// MaxEjectionPercent sets the maximum percentage of hosts in a cluster that can be ejected.
	//
	// +kubebuilder:default=10
	// +optional
	MaxEjectionPercent *int32 `json:"maxEjectionPercent,omitempty"`
}

// ActiveHealthCheck defines the active health check configuration.
// EG supports various types of active health checking including HTTP, TCP.
// +union
//
// +kubebuilder:validation:XValidation:rule="self.type == 'HTTP' ? has(self.http) : !has(self.http)",message="If Health Checker type is HTTP, http field needs to be set."
// +kubebuilder:validation:XValidation:rule="self.type == 'TCP' ? has(self.tcp) : !has(self.tcp)",message="If Health Checker type is TCP, tcp field needs to be set."
// +kubebuilder:validation:XValidation:rule="has(self.grpc) ? self.type == 'GRPC' : true", message="The grpc field can only be set if the Health Checker type is GRPC."
type ActiveHealthCheck struct {
	// Timeout defines the time to wait for a health check response.
	//
	// +kubebuilder:validation:Format=duration
	// +kubebuilder:default="1s"
	// +optional
	Timeout *metav1.Duration `json:"timeout"`

	// Interval defines the time between active health checks.
	//
	// +kubebuilder:validation:Format=duration
	// +kubebuilder:default="3s"
	// +optional
	Interval *metav1.Duration `json:"interval"`

	// InitialJitter defines the maximum time Envoy will wait before the first health check.
	// Envoy will randomly select a value between 0 and the initial jitter value.
	//
	// +kubebuilder:validation:Format=duration
	// +optional
	InitialJitter *gwapiv1.Duration `json:"initialJitter,omitempty"`

	// UnhealthyThreshold defines the number of unhealthy health checks required before a backend host is marked unhealthy.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=3
	// +optional
	UnhealthyThreshold *uint32 `json:"unhealthyThreshold"`

	// HealthyThreshold defines the number of healthy health checks required before a backend host is marked healthy.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:default=1
	// +optional
	HealthyThreshold *uint32 `json:"healthyThreshold"`

	// Type defines the type of health checker.
	// +kubebuilder:validation:Enum=HTTP;TCP;GRPC
	// +unionDiscriminator
	Type ActiveHealthCheckerType `json:"type" yaml:"type"`

	// HTTP defines the configuration of http health checker.
	// It's required while the health checker type is HTTP.
	// +optional
	HTTP *HTTPActiveHealthChecker `json:"http,omitempty" yaml:"http,omitempty"`

	// TCP defines the configuration of tcp health checker.
	// It's required while the health checker type is TCP.
	// +optional
	TCP *TCPActiveHealthChecker `json:"tcp,omitempty" yaml:"tcp,omitempty"`

	// GRPC defines the configuration of the GRPC health checker.
	// It's optional, and can only be used if the specified type is GRPC.
	// +optional
	GRPC *GRPCActiveHealthChecker `json:"grpc,omitempty" yaml:"grpc,omitempty"`
}

// ActiveHealthCheckerType is the type of health checker.
// +kubebuilder:validation:Enum=HTTP;TCP;GRPC
type ActiveHealthCheckerType string

const (
	// ActiveHealthCheckerTypeHTTP defines the HTTP type of health checking.
	ActiveHealthCheckerTypeHTTP ActiveHealthCheckerType = "HTTP"
	// ActiveHealthCheckerTypeTCP defines the TCP type of health checking.
	ActiveHealthCheckerTypeTCP ActiveHealthCheckerType = "TCP"
	// ActiveHealthCheckerTypeGRPC defines the GRPC type of health checking.
	ActiveHealthCheckerTypeGRPC ActiveHealthCheckerType = "GRPC"
)

// HTTPActiveHealthChecker defines the settings of http health check.
type HTTPActiveHealthChecker struct {
	// Hostname defines the HTTP host that will be requested during health checking.
	// Default: HTTPRoute or GRPCRoute hostname.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
	// +optional
	Hostname *string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// Path defines the HTTP path that will be requested during health checking.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Path string `json:"path" yaml:"path"`
	// Method defines the HTTP method used for health checking.
	// Defaults to GET
	// +optional
	Method *string `json:"method,omitempty" yaml:"method,omitempty"`
	// ExpectedStatuses defines a list of HTTP response statuses considered healthy.
	// Defaults to 200 only
	// +optional
	ExpectedStatuses []HTTPStatus `json:"expectedStatuses,omitempty" yaml:"expectedStatuses,omitempty"`
	// ExpectedResponse defines a list of HTTP expected responses to match.
	// +optional
	ExpectedResponse *ActiveHealthCheckPayload `json:"expectedResponse,omitempty" yaml:"expectedResponse,omitempty"`
}

// TCPActiveHealthChecker defines the settings of tcp health check.
type TCPActiveHealthChecker struct {
	// Send defines the request payload.
	// +optional
	Send *ActiveHealthCheckPayload `json:"send,omitempty" yaml:"send,omitempty"`
	// Receive defines the expected response payload.
	// +optional
	Receive *ActiveHealthCheckPayload `json:"receive,omitempty" yaml:"receive,omitempty"`
}

// GRPCActiveHealthChecker defines the settings of the GRPC health check.
type GRPCActiveHealthChecker struct {
	// Service to send in the health check request.
	// If this is not specified, then the health check request applies to the entire
	// server and not to a specific service.
	// +optional
	Service *string `json:"service,omitempty" yaml:"service,omitempty"`
}

// ActiveHealthCheckPayloadType is the type of the payload.
// +kubebuilder:validation:Enum=Text;Binary
type ActiveHealthCheckPayloadType string

const (
	// ActiveHealthCheckPayloadTypeText defines the Text type payload.
	ActiveHealthCheckPayloadTypeText ActiveHealthCheckPayloadType = "Text"
	// ActiveHealthCheckPayloadTypeBinary defines the Binary type payload.
	ActiveHealthCheckPayloadTypeBinary ActiveHealthCheckPayloadType = "Binary"
)

// ActiveHealthCheckPayload defines the encoding of the payload bytes in the payload.
// +union
// +kubebuilder:validation:XValidation:rule="self.type == 'Text' ? has(self.text) : !has(self.text)",message="If payload type is Text, text field needs to be set."
// +kubebuilder:validation:XValidation:rule="self.type == 'Binary' ? has(self.binary) : !has(self.binary)",message="If payload type is Binary, binary field needs to be set."
type ActiveHealthCheckPayload struct {
	// Type defines the type of the payload.
	// +kubebuilder:validation:Enum=Text;Binary
	// +unionDiscriminator
	Type ActiveHealthCheckPayloadType `json:"type" yaml:"type"`
	// Text payload in plain text.
	// +optional
	Text *string `json:"text,omitempty" yaml:"text,omitempty"`
	// Binary payload base64 encoded.
	// +optional
	Binary []byte `json:"binary,omitempty" yaml:"binary,omitempty"`
}
