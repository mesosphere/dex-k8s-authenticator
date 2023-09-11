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

// FilterClusterNames gets the list of KC names for given tenant (via Worksspace)
// and returns list of cluster names for clusters that are in the namespace.
func (t *k8sTenants) FilterClusterNames(ctx context.Context, tenantId TenantId, names []string) ([]string, error) {
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
	for _, name := range names {
		if slices.Contains(kcNames, name) {
			tenantNames = append(tenantNames, name)
		}
	}

	return tenantNames, nil
}
