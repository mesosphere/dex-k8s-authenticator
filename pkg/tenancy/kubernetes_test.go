package tenancy_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"

	"github.com/mesosphere/dex-k8s-authenticator/pkg/tenancy"
)

func TestK8sTenantsExists(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		objs     []runtime.Object
		tenantId tenancy.TenantId
		hasError bool
		exists   bool
	}{
		{
			name:     "no tenants",
			tenantId: tenancy.TenantId("foo"),
			hasError: false,
			exists:   false,
		},
		{
			name:     "no tenant id",
			tenantId: tenancy.TenantId("foo"),
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
					},
				},
			},
			hasError: false,
			exists:   false,
		},
		{
			name:     "existing tenant id",
			tenantId: tenancy.TenantId("ws-1"),
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
					},
				},
			},
			hasError: false,
			exists:   true,
		},
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			cl := fake.NewSimpleDynamicClient(runtime.NewScheme(), tc.objs...)
			tenants := tenancy.NewK8sTenants(cl)
			exists, err := tenants.Exists(context.Background(), tc.tenantId)

			if tc.hasError {
				require.Error(tt, err)
			} else {
				require.NoError(tt, err)
			}

			assert.Equal(tt, tc.exists, exists)
		})
	}
}

func TestK8sTenantsFilterClusterNames(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name          string
		objs          []runtime.Object
		tenantId      tenancy.TenantId
		errorContains string
		clusterNames  []string
		expectedNames []string
	}{
		{
			name:          "no workspace",
			tenantId:      tenancy.TenantId("ws-1"),
			errorContains: "not found",
		},
		{
			name: "no namespace ref",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
					},
				},
			},
			tenantId:      tenancy.TenantId("ws-1"),
			errorContains: "namespaceRef.name not populated on workspace: ws-1",
		},
		{
			name: "no cluster in ns",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
						"status": map[string]interface{}{
							"namespaceRef": map[string]interface{}{
								"name": "ns-1",
							},
						},
					},
				},
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
					},
				},
			},
			tenantId:      tenancy.TenantId("ws-1"),
			expectedNames: []string{},
		},
		{
			name: "no matching cluster name",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
						"status": map[string]interface{}{
							"namespaceRef": map[string]interface{}{
								"name": "ns-1",
							},
						},
					},
				},
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
						"metadata": map[string]interface{}{
							"name":      "kc-1",
							"namespace": "ns-1",
						},
					},
				},
			},
			tenantId:      tenancy.TenantId("ws-1"),
			clusterNames:  []string{"kc-2"},
			expectedNames: []string{},
		},
		{
			name: "filter only cluster in workspace",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "ws-1",
						},
						"status": map[string]interface{}{
							"namespaceRef": map[string]interface{}{
								"name": "ns-1",
							},
						},
					},
				},
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
						"metadata": map[string]interface{}{
							"name":      "kc-1",
							"namespace": "ns-1",
						},
					},
				},
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
						"metadata": map[string]interface{}{
							"name":      "kc-2",
							"namespace": "ns-2",
						},
					},
				},
			},
			tenantId:      tenancy.TenantId("ws-1"),
			clusterNames:  []string{"kc-1", "kc-2"},
			expectedNames: []string{"kc-1"},
		},
		{
			name: "it keeps management cluster in cluster name",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "kommander-workspace",
						},
						"status": map[string]interface{}{
							"namespaceRef": map[string]interface{}{
								"name": "kommander-workspace",
							},
						},
					},
				},
				// KommanderCluster for the management cluster; must be in the "kommander"
				// namespace and carry the host label so getManagementClusterName finds it.
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
						"metadata": map[string]interface{}{
							"name":      "my-custom-host-cluster",
							"namespace": "kommander",
							"labels": map[string]interface{}{
								"kommander.d2iq.io/host": "true",
							},
						},
					},
				},
				// The workspace-scoped KommanderCluster (same name, different namespace)
				// is what appears in kcNames for the workspace list.
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "kommander.mesosphere.io/v1beta1",
						"kind":       "KommanderCluster",
						"metadata": map[string]interface{}{
							"name":      "my-custom-host-cluster",
							"namespace": "kommander-workspace",
						},
					},
				},
			},
			tenantId:      tenancy.TenantId("kommander-workspace"),
			clusterNames:  []string{"kubernetes-cluster", "kc-2"},
			expectedNames: []string{"kubernetes-cluster"},
		},
		{
			name: "management cluster not found returns error",
			objs: []runtime.Object{
				&unstructured.Unstructured{
					Object: map[string]interface{}{
						"apiVersion": "workspaces.kommander.mesosphere.io/v1alpha1",
						"kind":       "Workspace",
						"metadata": map[string]interface{}{
							"name": "kommander-workspace",
						},
						"status": map[string]interface{}{
							"namespaceRef": map[string]interface{}{
								"name": "kommander-workspace",
							},
						},
					},
				},
				// No KommanderCluster with the host label exists.
			},
			tenantId:      tenancy.TenantId("kommander-workspace"),
			clusterNames:  []string{"kubernetes-cluster"},
			errorContains: "no management KommanderCluster found with label kommander.d2iq.io/host=true in namespace kommander",
		},
	}

	// Pre-register all GVRs used by FilterClusterNames so the fake client can
	// handle List calls even when no objects of that type are in the fixture.
	gvrToListKind := map[schema.GroupVersionResource]string{
		{Group: "workspaces.kommander.mesosphere.io", Version: "v1alpha1", Resource: "workspaces"}:   "WorkspaceList",
		{Group: "kommander.mesosphere.io", Version: "v1beta1", Resource: "kommanderclusters"}:        "KommanderClusterList",
	}

	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.name, func(tt *testing.T) {
			tt.Parallel()

			cl := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), gvrToListKind, tc.objs...)
			tenants := tenancy.NewK8sTenants(cl)
			filtered, err := tenants.FilterClusterNames(context.Background(), tc.tenantId, tc.clusterNames)

			if tc.errorContains != "" {
				require.ErrorContains(tt, err, tc.errorContains)
			} else {
				require.NoError(tt, err)
			}

			assert.Equal(tt, tc.expectedNames, filtered)
		})
	}
}
