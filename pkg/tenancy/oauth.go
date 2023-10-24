package tenancy

import (
	"golang.org/x/oauth2"
)

const (
	// TenantIdQueryParamName is the name of URL request query parameter that must
	// be carried to the Dex to filter out the connectors based on tenant id
	TenantIdQueryParamName = "tenant-id"
)

// OauthAddTenantId adds tenant-id parameter to authorization URL where the
// client is redirected.
func OauthAddTenantId(tenantId TenantId) oauth2.AuthCodeOption {
	return oauth2.SetAuthURLParam(TenantIdQueryParamName, string(tenantId))
}
