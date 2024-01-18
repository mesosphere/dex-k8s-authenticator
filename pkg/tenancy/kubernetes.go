package tenancy

import (
	"context"
	"fmt"

	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/utils/strings/slices"
)

var (
	workspaceGVR = schema.GroupVersionResource{
		Group:    "workspaces.kommander.mesosphere.io",
		Version:  "v1alpha1",
		Resource: "workspaces",
	}

	kommanderClusterGVR = schema.GroupVersionResource{
		Group:    "kommander.mesosphere.io",
		Version:  "v1beta1",
		Resource: "kommanderclusters",
	}
)

const (
	workspaceNameAnnotation = "kommander.mesosphere.io/display-name"

	// DKA stores management cluster under `kubernetes-cluster` name.
	managementClusterName = "kubernetes-cluster"

	// KommanderCluster for management cluster has different name in k8s api
	// server vs in DKA config file.
	managementWorkspaceNamespaceName      = "kommander-workspace"
	managementClusterKommanderClusterName = "host-cluster"
)

var _ Tenants = &k8sTenants{}

// NewK8sFromEnvironment creates k8s tenants from in cluster configuration.
func NewK8sFromEnvironment() (*k8sTenants, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := clientcmd.NewDefaultClientConfigLoadingRules().GetDefaultFilename()
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, err
		}
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return NewK8sTenants(dynClient), nil
}

// NewK8sTenants returns tenants resolver based on a live data in a DKP k8s cluster.
func NewK8sTenants(cl dynamic.Interface) *k8sTenants {
	return &k8sTenants{
		client: cl,
	}
}

type k8sTenants struct {
	client dynamic.Interface
}

func (t *k8sTenants) Exists(ctx context.Context, tenantId TenantId) (bool, error) {
	// workspace.name is the tenant id
	_, err := t.client.Resource(workspaceGVR).
		Get(ctx, string(tenantId), metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (t *k8sTenants) Get(ctx context.Context, tenantId TenantId) (*Tenant, error) {
	// workspace.name is the tenant id
	workspace, err := t.client.Resource(workspaceGVR).
		Get(ctx, string(tenantId), metav1.GetOptions{})
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return tenantFromWorkspace(workspace), nil
}

// FilterClusterNames gets the list of KC names for given tenant (via Worksspace)
// and returns list of cluster names for clusters that are in the namespace.
func (t *k8sTenants) FilterClusterNames(ctx context.Context, tenantId TenantId, dkaConfigNames []string) ([]string, error) {
	workspace, err := t.client.Resource(workspaceGVR).
		Get(ctx, string(tenantId), metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	namespaceName, found, err := unstructured.NestedString(workspace.Object, "status", "namespaceRef", "name")
	if err != nil {
		return nil, err
	}

	if !found {
		return nil, fmt.Errorf("namespaceRef.name not populated on workspace: %s", string(tenantId))
	}

	kcList, err := t.client.Resource(kommanderClusterGVR).Namespace(namespaceName).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	kcNames := []string{}
	for _, kc := range kcList.Items {
		kcNames = append(kcNames, kc.GetName())
	}

	tenantNames := []string{}
	for _, dkaConfigClusterName := range dkaConfigNames {
		if dkaConfigClusterName == managementClusterName && tenantId == managementWorkspaceNamespaceName {
			if slices.Contains(kcNames, managementClusterKommanderClusterName) {
				tenantNames = append(tenantNames, dkaConfigClusterName)
			}
		} else {
			if slices.Contains(kcNames, dkaConfigClusterName) {
				tenantNames = append(tenantNames, dkaConfigClusterName)
			}
		}
	}

	return tenantNames, nil
}

func (t *k8sTenants) GetTenantsByCluster(ctx context.Context) (map[string]*Tenant, error) {
	kcList, err := t.client.Resource(kommanderClusterGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	wsList, err := t.client.Resource(workspaceGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	tenantsByCluster := map[string]*Tenant{}

	for _, kc := range kcList.Items {
		// No tenancy is for management cluster which is stored in the dka config
		// as kubernetes-cluster
		if kc.GetName() == managementClusterName {
			continue
		}

		for i, workspace := range wsList.Items {
			namespaceName, found, err := unstructured.NestedString(workspace.Object, "status", "namespaceRef", "name")
			if err != nil {
				return nil, err
			}

			if !found {
				continue
			}

			if namespaceName == kc.GetNamespace() {
				tenantsByCluster[kc.GetName()] = tenantFromWorkspace(&wsList.Items[i])
			}
		}
	}

	return tenantsByCluster, nil
}

func tenantFromWorkspace(u *unstructured.Unstructured) *Tenant {
	// workspace.name is the tenant id
	tenant := &Tenant{
		ID:   TenantId(u.GetName()),
		Name: u.GetName(),
	}

	if name, ok := u.GetAnnotations()[workspaceNameAnnotation]; ok {
		tenant.Name = name
	}
	return tenant
}
