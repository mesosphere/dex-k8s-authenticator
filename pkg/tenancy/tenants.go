package tenancy

import (
	"context"
)

// TenantId is identifier of a tenant.
type TenantId string

// Tenants provides functionality for checking the existence of given tenant ID
// and filter operations.
type Tenants interface {
	// Exists checks if givent tentant id exists.
	Exists(ctx context.Context, tenantId TenantId) (bool, error)
	// FilterClusterNames returns list of cluster names (from DKA configuration) that belong to
	// given tenant id.
	FilterClusterNames(ctx context.Context, tenantId TenantId, names []string) ([]string, error)
}
