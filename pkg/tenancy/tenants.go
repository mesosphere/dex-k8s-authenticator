package tenancy

import (
	"context"
)

// TenantId is identifier of a tenant.
type TenantId string

type Tenant struct {
	ID   TenantId
	Name string
}

// Tenants provides functionality for checking the existence of given tenant ID
// and filter operations.
type Tenants interface {
	// Exists checks if given tenantId exists.
	Exists(ctx context.Context, tenantId TenantId) (bool, error)
	// Retrieve Tenant for given tenantId.
	Get(ctx context.Context, tenantId TenantId) (*Tenant, error)
	// FilterClusterNames returns list of cluster names (from DKA configuration) that belong to
	// given tenant id.
	FilterClusterNames(ctx context.Context, tenantId TenantId, names []string) ([]string, error)
}
