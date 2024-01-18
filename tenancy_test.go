package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/mesosphere/dex-k8s-authenticator/pkg/tenancy"
)

func TestGetTenancyTemplate(t *testing.T) {
	assert.NotNil(t, getTenancyTemplate("index-multitenant.html"))
	assert.NotNil(t, getTenancyTemplate("landing-multitenant.html"))
}

func TestTenancyHandler(t *testing.T) {
	m := &tenantsMock{
		existsCall: struct {
			exists bool
			err    error
		}{
			exists: true,
		},
		filterClusterNamesCall: struct {
			names []string
			err   error
		}{
			names: []string{"cluster-2"},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-tenant", nil)
	c := &Config{
		Clusters: []Cluster{
			{Name: "cluster-1"},
			{Name: "cluster-2"},
		},
		Web_Path_Prefix: "/",
	}

	h := NewTenancyHandler(m, c, getTenancyTemplate("index-multitenant.html"))
	r := mux.NewRouter()
	r.HandleFunc("/{tenantId}", h)
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "respbody: %s", rr.Body.String())
	assert.Contains(t, rr.Body.String(), "/login/cluster-2?tenant-id=test-tenant")
}

func TestTenancyHandler_NoClusters(t *testing.T) {
	m := &tenantsMock{
		existsCall: struct {
			exists bool
			err    error
		}{
			exists: true,
		},
		filterClusterNamesCall: struct {
			names []string
			err   error
		}{
			names: []string{},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-tenant", nil)
	c := &Config{
		Clusters: []Cluster{
			{Name: "cluster-1"},
			{Name: "cluster-2"},
		},
		Web_Path_Prefix: "/",
	}

	h := NewTenancyHandler(m, c, getTenancyTemplate("index-multitenant.html"))
	r := mux.NewRouter()
	r.HandleFunc("/{tenantId}", h)
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "respbody: %s", rr.Body.String())
	assert.NotContains(t, rr.Body.String(), "Select which cluster you require a token for:")
	assert.Contains(t, rr.Body.String(), "There are no clusters attached to the workspace.")
}

func TestLandingHandler(t *testing.T) {
	m := &tenantsMock{
		existsCall: struct {
			exists bool
			err    error
		}{
			exists: true,
		},
		getCall: struct {
			tenant *tenancy.Tenant
			err    error
		}{
			tenant: &tenancy.Tenant{
				Name: "Test Tenant name",
				ID:   tenancy.TenantId("test-tenant"),
			},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test-tenant", nil)
	c := &Config{
		Web_Path_Prefix: "/",
	}

	h := NewLandingHandler(m, c, getTenancyTemplate("landing-multitenant.html"))
	r := mux.NewRouter()
	r.HandleFunc("/{tenantId}", h)
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "respbody: %s", rr.Body.String())
	assert.Contains(t, rr.Body.String(), "/workspace/test-tenant")
	assert.Contains(t, rr.Body.String(), "/dkp/kommander/dashboard/?tenant-id=test-tenant")
	assert.Contains(t, rr.Body.String(), "Test Tenant name")
}

var _ tenancy.Tenants = &tenantsMock{}

type tenantsMock struct {
	existsCall struct {
		exists bool
		err    error
	}

	filterClusterNamesCall struct {
		names []string
		err   error
	}

	getCall struct {
		tenant *tenancy.Tenant
		err    error
	}
}

func (t *tenantsMock) Exists(ctx context.Context, tenantId tenancy.TenantId) (bool, error) {
	return t.existsCall.exists, t.existsCall.err
}

func (t *tenantsMock) Get(ctx context.Context, tenantId tenancy.TenantId) (*tenancy.Tenant, error) {
	return t.getCall.tenant, t.getCall.err
}

func (t *tenantsMock) FilterClusterNames(ctx context.Context, tenantId tenancy.TenantId, names []string) ([]string, error) {
	return t.filterClusterNamesCall.names, t.filterClusterNamesCall.err
}

func (t *tenantsMock) GetTenantsByCluster(ctx context.Context) (map[string]*tenancy.Tenant, error) {
	return nil, fmt.Errorf("not implemented")
}
