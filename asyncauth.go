package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"text/template"

	"github.com/coreos/go-oidc"
	"github.com/mesosphere/konvoy-async-auth/pkg/kaal"
	asyncauth "github.com/mesosphere/konvoy-async-auth/pkg/kaal/server"
	"github.com/mesosphere/konvoy-async-auth/pkg/kaal/server/storage"
	"golang.org/x/oauth2"
)

const (
	HmacTTL            = 300
	downloadPath       = "static/downloads/"
	binaryName         = "konvoy-async-auth"
	runPath            = "konvoy/bin/" + binaryName
	installPath        = ".kube/konvoy/bin/" + binaryName
	defaultProfileName = "default-profile"
)

type TemplateData struct {
	Config       Config
	Providers    []FlatProviderMap
	AsyncAuthURL string
	KubeAPI      string
	DarwinURL    string
	LinuxURL     string
}

type ClusterJSON struct {
	Name            string `json:"name"`
	ClusterHostname string `json:"clusterHostname"`
	URL             string `json:"url"`
	CA              string `json:"ca"`
}

// FlatProviderMap is a flat
type FlatProviderMap struct {
	// Name is the hostname of the provider
	Name     string        `json:"name"`
	Url      string        `json:"url"`
	Clusters []ClusterJSON `json:"clusters"`
}

func SetupAsyncAuth(cluster *Cluster, st storage.TokenStore, basePrefix string) *asyncauth.KonvoyAsyncAuthServer {
	scopes := cluster.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "groups"}
	}
	ctx := oidc.ClientContext(context.Background(), cluster.Client)
	s := &asyncauth.KonvoyAsyncAuthServer{
		Quiet: false,
		OAuth2Config: &oauth2.Config{
			ClientID:     cluster.Client_ID,
			ClientSecret: cluster.Client_Secret,
			Endpoint:     cluster.Provider.Endpoint(),
			Scopes:       scopes,
			RedirectURL:  getAsyncRedirectURI(cluster.Redirect_URI, basePrefix),
		},
		Provider:    cluster.Provider,
		HmacTTL:     HmacTTL,
		HmacSecret:  parseSecret(&cluster.Config),
		Storage:     st,
		OIDCContext: ctx,
	}
	register("init", basePrefix, kaal.InitEndpoint, s.AsyncInit)
	register("callback", basePrefix, kaal.CallbackEndpoint, s.AuthCallback)
	register("query", basePrefix, kaal.QueryEndpoint, s.Query)
	register("check token", basePrefix, kaal.CheckEndpoint, s.CheckToken)
	register("plugin instructions", basePrefix, "/plugin", cluster.pluginController)
	register("plugin data", basePrefix, "/plugin/data/json", cluster.getInstructionDataJSON)
	register("plugin instructions update", basePrefix, "/plugin/data", cluster.Config.renderInstructions)
	register("plugin provider data", basePrefix, "/plugin/providers", cluster.Config.getClustersByProviders)
	register("kubeconfig download", basePrefix, "/plugin/kubeconfig", cluster.Config.downloadKubeConfig)

	return s
}

func getAsyncRedirectURI(u, base string) string {
	parsed, _ := url.Parse(u)
	parsed.Path = join(base, kaal.CallbackEndpoint)
	log.Printf("setting async auth redirect url to %s", parsed.String())
	return parsed.String()
}

func register(name, base, endpoint string, f func(w http.ResponseWriter, req *http.Request)) {
	e := join(base, endpoint)
	http.HandleFunc(e, f)
	log.Printf("registerd async %s endpoint at %s", name, e)
}

func join(base, endpoint string) string {
	return fmt.Sprintf("%s/%s", strings.TrimRight(base, "/"), strings.TrimLeft(endpoint, "/"))
}

// attempts to decode binary
func parseSecret(config *Config) []byte {
	b, err := hex.DecodeString(config.Hmac_Secret)
	if err != nil {
		return []byte(config.Hmac_Secret)
	}
	return b
}

func (cluster *Cluster) pluginController(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		cluster.renderHTMLError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// use the redirect url to determine base URL
	parsed, _ := url.Parse(cluster.Redirect_URI)
	appURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	asyncAuthURL := fmt.Sprintf("%s%s", appURL, cluster.Config.Web_Path_Prefix)

	data := TemplateData{
		Config:    cluster.Config,
		LinuxURL:  getDownloadURL(asyncAuthURL, "linux", cluster.Config.PluginVersion),
		DarwinURL: getDownloadURL(asyncAuthURL, "darwin", cluster.Config.PluginVersion),
	}

	if err := renderPluginInstructions(w, data); err != nil {
		log.Printf("error rendering template: %v", err)
		cluster.renderHTMLError(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func renderPluginInstructions(w http.ResponseWriter, data TemplateData) error {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	err := templates.ExecuteTemplate(w, "plugin.html", data)
	if err != nil {
		return err
	}
	return nil
}

func getDownloadURL(url, platform, version string) string {
	// TODO: make this more readable
	return fmt.Sprintf("%s%s%s/%s_%s/%s", url, downloadPath, platform, binaryName, version, binaryName)
}

func (cluster *Cluster) getInstructionDataJSON(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		cluster.renderHTMLError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	profileName := req.URL.Query().Get("profileName")
	if profileName == "" {
		profileName = defaultProfileName
	}

	// use the redirect url to determine base URL
	parsed, _ := url.Parse(cluster.Redirect_URI)
	appURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	asyncAuthURL := fmt.Sprintf("%s%s", appURL, cluster.Config.Web_Path_Prefix)

	data := map[string]string{
		"clusterName":  cluster.Name,
		"profileName":  profileName,
		"asyncAuthURL": asyncAuthURL,
	}

	j, err := json.Marshal(data)
	if err != nil {
		log.Printf("could not marshal json: %v", err)
		cluster.renderHTMLError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}

func (config *Config) renderInstructions(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		config.Clusters[0].renderHTMLError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	profileName := req.URL.Query().Get("profileName")
	if profileName == "" {
		profileName = defaultProfileName
	}

	selectCluster := req.URL.Query().Get("cluster")
	var cluster *Cluster
	if selectCluster == "" {
		cluster = config.getFirstClusterOrPanic()
	} else {
		for _, c := range config.Clusters {
			parsed, _ := url.Parse(c.K8s_Master_URI)
			if parsed.Hostname() == selectCluster {
				cluster = &c
				break
			}
		}
		if cluster == nil{
			log.Printf("requested cluster does not exist: %s", selectCluster)
			config.getFirstClusterOrPanic().renderHTMLError(w, "Bad Request", http.StatusBadRequest)
			return
		}
	}

	// Get the Kommander Cluster CA
	authCAData := ""
	if config.getFirstClusterOrPanic().K8s_Ca_Pem != "" {
		authCAData = base64.StdEncoding.EncodeToString([]byte(config.getFirstClusterOrPanic().K8s_Ca_Pem))
	}

	parsed, _ := url.Parse(config.getFirstClusterOrPanic().Redirect_URI)
	appURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	asyncAuthURL := fmt.Sprintf("%s%s", appURL, cluster.Config.Web_Path_Prefix)

	parsed, _ = url.Parse(cluster.K8s_Master_URI)
	clusterName := parsed.Hostname()

	data := map[string]string{
		"webPathPrefix": cluster.Config.Web_Path_Prefix,
		"linuxURL":      getDownloadURL(asyncAuthURL, "linux", cluster.Config.PluginVersion),
		"darwinURL":     getDownloadURL(asyncAuthURL, "darwin", cluster.Config.PluginVersion),
		"installPath":   installPath,
		"runPath":       runPath,
		"asyncAuthURL":  asyncAuthURL,
		"clusterName":   clusterName,
		"profileName":   profileName,
		"kubeAPI":       cluster.K8s_Master_URI,
		"caPem":         cluster.K8s_Ca_Pem,
		"authCAData":    authCAData,
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	err := templates.ExecuteTemplate(w, "kubectl-plugin-instructions.html", data)
	if err != nil {
		log.Printf("error getting instructions: %v", err)
		cluster.renderHTMLError(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// This handler is used to provide app javascript with JSON formatted
func (config *Config) getClustersByProviders(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		config.getFirstClusterOrPanic().renderHTMLError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	m := make(map[string][]ClusterJSON)

	for _, cluster := range config.Clusters {
		parsed, _ := url.Parse(cluster.K8s_Master_URI)
		appURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
		asyncAuthURL := fmt.Sprintf("%s%s", appURL, cluster.Config.Web_Path_Prefix)

		m[cluster.Issuer] = append(m[cluster.Issuer], ClusterJSON{
			Name:            cluster.Name,
			ClusterHostname: parsed.Hostname(),
			URL:             asyncAuthURL,
			CA:              cluster.K8s_Ca_Pem,
		})
	}

	var flat []FlatProviderMap
	for issuer, clusters := range m {
		parsed, _ := url.Parse(issuer)
		flat = append(flat, FlatProviderMap{
			Name:     parsed.Hostname(),
			Url:      issuer,
			Clusters: clusters,
		})
	}

	j, err := json.Marshal(flat)
	if err != nil {
		config.getFirstClusterOrPanic().renderHTMLError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(j)
}

type KConfigCluster struct {
	Name            string
	CertificateData string
	Server          string
}

type KConfigContext struct {
	Name    string
	Cluster string
	User    string
}

type KConfigUser struct {
	Name            string
	AuthURL         string
	CertificateData string
	Command         string
}

type KubeConfig struct {
	CurrentContext string
	Clusters       []KConfigCluster
	Contexts       []KConfigContext
	Users          []KConfigUser
}

func (config *Config) downloadKubeConfig(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		config.getFirstClusterOrPanic().renderHTMLError(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	profileName := req.URL.Query().Get("profileName")
	if profileName == "" {
		profileName = defaultProfileName
	}

	kubeconfig, err := config.renderKubeconfig(profileName)
	if err != nil {
		log.Printf("error rendering kubeconfig: %v", err)
		config.getFirstClusterOrPanic().renderHTMLError(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=kubeconfig-%s", profileName))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(kubeconfig)
}

func (config *Config) renderKubeconfig(profileName string) ([]byte, error) {
	parsed, _ := url.Parse(config.getFirstClusterOrPanic().Redirect_URI)
	appURL := fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	asyncAuthURL := fmt.Sprintf("%s%s", appURL, config.Web_Path_Prefix)

	kUser := KConfigUser{
		Name:    profileName,
		AuthURL: asyncAuthURL,
		Command: binaryName,
	}

	// In Konvoy, we assume that the first cluster in the configuration (enforced by the initContainer)
	// is also the iDP host (dex). There is also logic which accounts for custom CAs. If this string
	// is empty, we can assume that we are using a well known CA; and thus can rely on the system
	// CA pool for verification
	if config.getFirstClusterOrPanic().K8s_Ca_Pem != "" {
		kUser.CertificateData = base64.StdEncoding.EncodeToString([]byte(config.getFirstClusterOrPanic().K8s_Ca_Pem))
	}

	var kClusters []KConfigCluster
	var kContexts []KConfigContext
	for _, cluster := range config.Clusters {
		parsed, _ = url.Parse(cluster.K8s_Master_URI)
		clusterName := parsed.Hostname()
		var caData string
		if cluster.K8s_Ca_Pem != "" {
			caData = base64.StdEncoding.EncodeToString([]byte(cluster.K8s_Ca_Pem))
		}
		kClusters = append(kClusters, KConfigCluster{
			Name:            clusterName,
			CertificateData: caData,
			Server:          cluster.K8s_Master_URI,
		})
		kContexts = append(kContexts, KConfigContext{
			Name:    fmt.Sprintf("%s-%s", profileName, clusterName),
			Cluster: clusterName,
			User:    profileName,
		})
	}

	kConfig := KubeConfig{
		// Set the current context to the local cluster
		CurrentContext: kContexts[0].Name,
		Clusters:       kClusters,
		Contexts:       kContexts,
		Users:          []KConfigUser{kUser},
	}

	var output bytes.Buffer
	kt := template.Must(template.ParseFiles("./templates/kubeconfig.tmpl"))
	err := kt.Execute(&output, kConfig)
	if err != nil {
		return nil, err
	}
	return output.Bytes(), err
}
