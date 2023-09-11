package main

import (
	"fmt"
	"html/template"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	"k8s.io/utils/strings/slices"

	"github.com/mesosphere/dex-k8s-authenticator/pkg/tenancy"
)

// getTenancyTemplate is a workaround for deploying container without a need
// for changing the helm chart.
func getTenancyTemplate(name string) *template.Template {
	tpl := templates.Lookup(name)
	if tpl == nil {
		pathInOriginalTemplates := fmt.Sprintf("./original-templates/%s", name)
		tpl = template.Must(template.ParseFiles(pathInOriginalTemplates))
	}
	return tpl
}

// NewTenancyHandler displays a page where the user can see a list of clusters
// for given tenant.
func NewTenancyHandler(tenants tenancy.Tenants, c *Config, indexTemplate *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantId := tenancy.TenantId(mux.Vars(r)["tenantId"])
		exists, err := tenants.Exists(r.Context(), tenantId)
		if err != nil {
			log.Printf("Failed to check tenant: %s", err)
			renderHTMLError(w, c, "Failed to check for tenant", http.StatusInternalServerError)
			return
		}

		if !exists {
			msg := fmt.Sprintf("Requested tenant %q not found", tenantId)
			renderHTMLError(w, c, msg, http.StatusNotFound)
			return
		}

		allNames := []string{}
		for i := range c.Clusters {
			allNames = append(allNames, c.Clusters[i].Name)
		}
		tenantClusterNames, err := tenants.FilterClusterNames(r.Context(), tenantId, allNames)
		if err != nil {
			log.Printf("Failed to filter cluster name: %s", err)
			renderHTMLError(w, c, "Failed to check for tenant", http.StatusInternalServerError)
			return
		}

		tenantClusters := []Cluster{}
		for i := range c.Clusters {
			if slices.Contains(tenantClusterNames, c.Clusters[i].Name) {
				tenantClusters = append(tenantClusters, c.Clusters[i])
			}
		}

		data := struct {
			Web_Path_Prefix string
			Logo_Uri        string
			Clusters        []Cluster
			Tenant_Id       string
		}{
			Web_Path_Prefix: c.Web_Path_Prefix,
			Logo_Uri:        c.Logo_Uri,
			Clusters:        tenantClusters,
			Tenant_Id:       string(tenantId),
		}
		err = indexTemplate.Execute(w, data)
		if err != nil {
			renderHTMLError(w, c, "Failed to render template", http.StatusInternalServerError)
		}
	}
}

// NewLandingHandler displays a page where the user can action links for logging
// into UI or generating a kubectl token that will be limited to tenant id scope.
func NewLandingHandler(tenants tenancy.Tenants, c *Config, landingTemplate *template.Template) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantId := tenancy.TenantId(mux.Vars(r)["tenantId"])
		exists, err := tenants.Exists(r.Context(), tenantId)
		if err != nil {
			log.Printf("Failed to check tenant: %s", err)
			renderHTMLError(w, c, "Failed to check for tenant", http.StatusInternalServerError)
			return
		}

		if !exists {
			msg := fmt.Sprintf("Requested tenant %q not found", tenantId)
			renderHTMLError(w, c, msg, http.StatusNotFound)
			return
		}

		tenant, err := tenants.Get(r.Context(), tenantId)
		if err != nil {
			log.Printf("Failed to get tenant: %s", err)
			renderHTMLError(w, c, "Failed to retrieve tenant", http.StatusInternalServerError)
		}

		data := struct {
			Web_Path_Prefix string
			Logo_Uri        string
			Tenant_Id       string
			Tenant_Name     string
		}{
			Web_Path_Prefix: c.Web_Path_Prefix,
			Logo_Uri:        c.Logo_Uri,
			Tenant_Id:       string(tenantId),
			Tenant_Name:     tenant.Name,
		}
		err = landingTemplate.Execute(w, data)
		if err != nil {
			log.Printf("Failed to render template: %s", err)
			renderHTMLError(w, c, "Failed to render template", http.StatusInternalServerError)
		}
	}
}
