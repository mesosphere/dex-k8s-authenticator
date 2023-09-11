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

// getTenancyIndexTemplate is a workaround for deploying container without a need
// for changing the helm chart.
func getTenancyIndexTemplate() *template.Template {
	tpl := templates.Lookup("index-multitenant.html")
	if tpl == nil {
		tpl = template.Must(template.ParseFiles("./original-templates/index-multitenant.html"))
	}
	return tpl
}

// NewTenancyHandler displays a page where the user can see a list of clusters
// for given tenant.
func NewTenancyHandler(tenants tenancy.Tenants, c *Config, templates *template.Template) http.HandlerFunc {
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
		err = templates.Execute(w, data)
		if err != nil {
			renderHTMLError(w, c, "Failed to render template", http.StatusInternalServerError)
		}
	}
}
