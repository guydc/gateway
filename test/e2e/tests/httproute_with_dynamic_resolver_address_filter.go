// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build e2e

package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apimachinery/pkg/types"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	tlog "sigs.k8s.io/gateway-api/conformance/utils/tlog"

	egv1a1 "github.com/envoyproxy/gateway/api/v1alpha1"
	"github.com/envoyproxy/gateway/test/utils/prometheus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func init() {
	ConformanceTests = append(ConformanceTests, DynamicResolverAddressFilterTest)
}

// DynamicResolverAddressFilterTest verifies that resolved_address_filter on a DynamicResolver
// backend blocks traffic to the filtered service while leaving other services reachable,
// and that the dns_address_filter_out counter is incremented.
var DynamicResolverAddressFilterTest = suite.ConformanceTest{
	ShortName:   "DynamicResolverAddressFilter",
	Description: "DynamicResolver backend with resolvedAddressFilter blocks a specific service ClusterIP",
	Manifests: []string{
		"testdata/httproute-with-dynamic-resolver-address-filter.yaml",
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := ConformanceInfraNamespace
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}

		// Look up the ClusterIP of test-service-filtered to use as the filter target.
		filteredNN := types.NamespacedName{Name: "test-service-filtered", Namespace: ns}
		filteredSvc, err := GetService(suite.Client, filteredNN)
		if err != nil {
			t.Fatalf("failed to get service %s: %v", filteredNN, err)
		}
		filteredClusterIP := filteredSvc.Spec.ClusterIP
		if filteredClusterIP == "" {
			t.Fatalf("test-service-filtered has no ClusterIP")
		}
		t.Logf("test-service-filtered ClusterIP: %s", filteredClusterIP)

		// Create a DynamicResolver Backend that blocks test-service-filtered's ClusterIP.
		blockedCIDR := fmt.Sprintf("%s/32", filteredClusterIP)
		invert := false
		backendNN := types.NamespacedName{Name: "backend-dynamic-resolver-address-filter", Namespace: ns}
		backend := &egv1a1.Backend{
			ObjectMeta: metav1.ObjectMeta{
				Name:      backendNN.Name,
				Namespace: backendNN.Namespace,
			},
			Spec: egv1a1.BackendSpec{
				Type: backendTypePtr(egv1a1.BackendTypeDynamicResolver),
				DynamicResolver: &egv1a1.DynamicResolverConfig{
					ResolvedAddressFilter: &egv1a1.ResolvedAddressFilter{
						CIDRRanges: []egv1a1.CIDR{egv1a1.CIDR(blockedCIDR)},
						Invert:     &invert,
					},
				},
			},
		}
		if err := suite.Client.Create(context.Background(), backend); err != nil {
			t.Fatalf("failed to create backend %s: %v", backendNN, err)
		}
		t.Cleanup(func() {
			if err := DeleteBackend(suite.Client, backendNN); err != nil {
				t.Errorf("failed to delete backend %s: %v", backendNN, err)
			}
		})

		BackendMustBeAccepted(t, suite.Client, backendNN)

		routeNN := types.NamespacedName{Name: "httproute-with-dynamic-resolver-address-filter", Namespace: ns}
		gwAddr := kubernetes.GatewayAndRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), &gwapiv1.HTTPRoute{}, false, routeNN)

		t.Run("filtered service returns 503", func(t *testing.T) {
			// test-service-filtered's ClusterIP is in the filter — Envoy drops the resolved address.
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Host: fmt.Sprintf("test-service-filtered.%s.svc.cluster.local", ns),
					Path: "/",
				},
				Response: http.Response{
					StatusCodes: []int{503},
				},
				Namespace: ns,
			})
		})

		t.Run("allowed service returns 200", func(t *testing.T) {
			// test-service-allowed's ClusterIP is not in the filter — traffic flows normally.
			http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, http.ExpectedResponse{
				Request: http.Request{
					Host: fmt.Sprintf("test-service-allowed.%s.svc.cluster.local", ns),
					Path: "/",
				},
				Response: http.Response{
					StatusCodes: []int{200},
				},
				Namespace: ns,
			})
		})

		t.Run("dns_address_filter_out counter is non-zero", func(t *testing.T) {
			// dns_cache.<cache_name>.dns_address_filter_out increments each time Envoy drops
			// a resolved address due to the filter. The cache name for a DynamicResolver backend
			// with default DNS settings is envoy-gateway-dfp-cache-all-30000ms-default.
			// In Prometheus format, dots and dashes become underscores.
			pql := `envoy_dns_cache_envoy_gateway_dfp_cache_all_30000ms_default_dns_address_filter_out{` +
				`app_kubernetes_io_component="proxy",` +
				`app_kubernetes_io_managed_by="envoy-gateway",` +
				`app_kubernetes_io_name="envoy"}`

			if err := wait.PollUntilContextTimeout(context.TODO(), time.Second, suite.TimeoutConfig.MaxTimeToConsistency, true,
				func(_ context.Context) (bool, error) {
					v, err := prometheus.QueryPrometheus(suite.Client, pql)
					if err != nil {
						tlog.Logf(t, "dns_address_filter_out not yet available: %v", err)
						return false, nil
					}
					tlog.Logf(t, "dns_address_filter_out value: %v", v)
					return true, nil
				}); err != nil {
				t.Errorf("dns_address_filter_out counter never became non-zero: %v", err)
			}
		})
	},
}

func backendTypePtr(t egv1a1.BackendType) *egv1a1.BackendType {
	return &t
}
