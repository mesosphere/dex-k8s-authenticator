package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"

	"github.com/mesosphere/dex-k8s-authenticator/pkg/tenancy"
)

func TestMultitenantIndex(t *testing.T) {
	assert.NotNil(t, templates.Lookup("index-multitenant.html"))
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

	h := NewTenancyHandler(m, c, templates.Lookup("index-multitenant.html"))
	r := mux.NewRouter()
	r.HandleFunc("/{tenantId}", h)
	r.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code, "respbody: %s", rr.Body.String())
	assert.Contains(t, rr.Body.String(), "/login/cluster-2?tenant-id=test-tenant")
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
}

func (t *tenantsMock) Exists(ctx context.Context, tenantId tenancy.TenantId) (bool, error) {
	return t.existsCall.exists, t.existsCall.err
}

func (t *tenantsMock) FilterClusterNames(ctx context.Context, tenantId tenancy.TenantId, names []string) ([]string, error) {
	return t.filterClusterNamesCall.names, t.filterClusterNamesCall.err
}
