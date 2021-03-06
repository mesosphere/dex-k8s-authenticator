package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/mesosphere/konvoy-async-auth/pkg/kaal/server/storage"
	memstorage "github.com/mesosphere/konvoy-async-auth/pkg/kaal/server/storage/memory"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	config_file string
	debug       bool
)

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

// Define each cluster
type Cluster struct {
	Name                string
	Short_Description   string
	Description         string
	Issuer              string
	Client_Secret       string
	Client_ID           string
	Scopes              []string
	K8s_Master_URI      string
	K8s_Ca_URI          string
	K8s_Ca_Pem          string
	Static_Context_Name bool

	Verifier       *oidc.IDTokenVerifier
	Provider       *oidc.Provider
	OfflineAsScope bool
	Client         *http.Client
	Redirect_URI   string
	Config         Config
}

// Define our configuration
type Config struct {
	Clusters                         []Cluster
	Listen                           string
	Web_Path_Prefix                  string
	TLS_Cert                         string
	TLS_Key                          string
	IDP_Ca_URI                       string
	IDP_Ca_Pem                       string
	IDP_Ca_Pem_File                  string
	Logo_Uri                         string
	Static_Context_Name              bool
	Trusted_Root_Ca                  []string
	Trusted_Root_Ca_File             string
	Hmac_Secret                      string
	PluginVersion                    string
	UseClusterHostnameForClusterName bool
}

func substituteEnvVars(text string) string {
	re := regexp.MustCompile("\\${([a-zA-Z0-9\\-_]+)}")
	matches := re.FindAllStringSubmatch(text, -1)
	for _, val := range matches {
		envVar := os.Getenv(val[1])
		text = strings.Replace(text, val[0], envVar, -1)
	}
	return text
}

// Start the app
// Do some config parsing
// Setup http-clients and oidc providers
// Define per-cluster handlers
func start_app(config Config) {

	// Config validation
	listenURL, err := url.Parse(config.Listen)
	if err != nil {
		log.Fatalf("parse listen address: %v", err)
	}

	if len(config.Hmac_Secret) == 0 {
		log.Fatalf("Hmac_Secret is not defined in configuration")
	}

	var s struct {
		ScopesSupported []string `json:"scopes_supported"`
	}

	log.Printf("useClusterHostname: %t", config.UseClusterHostnameForClusterName)

	certp, err := x509.SystemCertPool()
	// Load Inline CA certs
	if len(config.Trusted_Root_Ca) > 0 {
		for _, cert := range config.Trusted_Root_Ca {
			ok := certp.AppendCertsFromPEM([]byte(cert))
			if !ok {
				log.Fatalf("Failed to parse a trusted cert, pem format expected")
			}
		}
	}
	// Load CA certs from file
	if config.Trusted_Root_Ca_File != "" {
		content, err := ioutil.ReadFile(config.Trusted_Root_Ca_File)
		if err != nil {
			log.Fatalf("Failed to read file Trusted Root CA %s", config.Trusted_Root_Ca_File)
		}
		ok := certp.AppendCertsFromPEM([]byte(content))
		if !ok {
			log.Fatalf("Failed to parse a trusted cert from file %s, pem format expected", config.Trusted_Root_Ca_File)
		}
	}

	mTlsConfig := &tls.Config{}
	mTlsConfig.PreferServerCipherSuites = true
	mTlsConfig.MinVersion = tls.VersionTLS10
	mTlsConfig.MaxVersion = tls.VersionTLS12
	mTlsConfig.RootCAs = certp

	tr := &http.Transport{
		TLSClientConfig: mTlsConfig,

		// Set proxy callback for proxy support in this transport
		Proxy: http.ProxyFromEnvironment,
	}

	// Ensure trailing slash on web-path-prefix
	web_path_prefix := config.Web_Path_Prefix
	if web_path_prefix != "/" {
		web_path_prefix = fmt.Sprintf("%s/", path.Clean(web_path_prefix))
		config.Web_Path_Prefix = web_path_prefix
	}

	commonCallbackPath := path.Join(config.Web_Path_Prefix, "callback")

	// Generate handlers for each cluster
	for i, _ := range config.Clusters {
		cluster := config.Clusters[i]
		if debug {
			if cluster.Client == nil {
				cluster.Client = &http.Client{
					Transport: debugTransport{tr},
				}
			} else {
				cluster.Client.Transport = debugTransport{tr}
			}
		} else {
			cluster.Client = &http.Client{Transport: tr}
		}

		ctx := oidc.ClientContext(context.Background(), cluster.Client)
		log.Printf("Creating new provider %s", cluster.Issuer)
		provider, err := oidc.NewProvider(ctx, cluster.Issuer)

		if err != nil {
			log.Fatalf("Failed to query provider %q: %v\n", cluster.Issuer, err)
		}

		cluster.Provider = provider

		log.Printf("Verifying client %s", cluster.Client_ID)

		verifier := provider.Verifier(&oidc.Config{ClientID: cluster.Client_ID})

		cluster.Verifier = verifier

		if err := provider.Claims(&s); err != nil {
			log.Fatalf("Failed to parse provider scopes_supported: %v", err)
		}

		if len(s.ScopesSupported) == 0 {
			// scopes_supported is a "RECOMMENDED" discovery claim, not a required
			// one. If missing, assume that the provider follows the spec and has
			// an "offline_access" scope.
			cluster.OfflineAsScope = true
		} else {
			// See if scopes_supported has the "offline_access" scope.
			cluster.OfflineAsScope = func() bool {
				for _, scope := range s.ScopesSupported {
					if scope == oidc.ScopeOfflineAccess {
						return true
					}
				}
				return false
			}()
		}

		cluster.Config = config

		base_redirect_uri, err := url.Parse(cluster.Redirect_URI)

		if err != nil {
			fmt.Errorf("Parsing redirect_uri address: %v", err)
			os.Exit(1)
		}

		if base_redirect_uri.Path != commonCallbackPath {
			// Each cluster gets a different login and callback URL
			http.HandleFunc(base_redirect_uri.Path, cluster.handleCallback)
			log.Printf("Registered callback handler at: %s", base_redirect_uri.Path)
		} else {
			log.Printf("Cluster `%s` is set to common global callback, not registering handler", cluster.Name)
		}

		login_uri := path.Join(config.Web_Path_Prefix, "login", cluster.Name)
		http.HandleFunc(login_uri, cluster.handleLogin)
		log.Printf("Registered login handler at: %s", login_uri)

		config.Clusters[i] = cluster
	}

	// Index page
	http.HandleFunc(config.Web_Path_Prefix, config.handleIndex)
	// Common callback page
	http.HandleFunc(path.Join(config.Web_Path_Prefix, "callback"), config.handleCallback)

	// Serve static html assets
	fs := http.FileServer(http.Dir("html/static/"))
	static_uri := path.Join(config.Web_Path_Prefix, "static") + "/"
	log.Printf("Registered static assets handler at: %s", static_uri)

	http.Handle(static_uri, http.StripPrefix(static_uri, fs))

	// Setup async auth service and build routes
	stg := memstorage.New(false)
	gc := storage.NewGC(&stg, time.Minute, false, debug)
	if err := gc.Start(); err != nil {
		log.Fatalf("error starting GC for async auth: %v", err)
	}

	// Hack(jr): We only support one provider in konvoy and it is not necessary to identify
	// cluster scope in this context (all clusters should use the same provider).
	cluster := &config.Clusters[0]
	SetupAsyncAuth(cluster, &stg, config.Web_Path_Prefix)

	// Determine whether to use TLS or not
	switch listenURL.Scheme {
	case "http":
		log.Printf("Listening on %s", config.Listen)
		err := http.ListenAndServe(listenURL.Host, nil)
		log.Fatal(err)
	case "https":
		log.Printf("Listening on %s", config.Listen)
		err := http.ListenAndServeTLS(listenURL.Host, config.TLS_Cert, config.TLS_Key, nil)
		log.Fatal(err)

	default:
		log.Fatalf("Listen address %q is not using http or https", config.Listen)
	}
}

func substituteEnvVarsRecursive(copy, original reflect.Value) {
	switch original.Kind() {

	case reflect.Ptr:
		originalValue := original.Elem()
		if !originalValue.IsValid() {
			return
		}
		copy.Set(reflect.New(originalValue.Type()))
		substituteEnvVarsRecursive(copy.Elem(), originalValue)

	case reflect.Interface:
		originalValue := original.Elem()
		copyValue := reflect.New(originalValue.Type()).Elem()
		substituteEnvVarsRecursive(copyValue, originalValue)
		copy.Set(copyValue)

	case reflect.Struct:
		for i := 0; i < original.NumField(); i += 1 {
			substituteEnvVarsRecursive(copy.Field(i), original.Field(i))
		}

	case reflect.Slice:
		copy.Set(reflect.MakeSlice(original.Type(), original.Len(), original.Cap()))
		for i := 0; i < original.Len(); i += 1 {
			substituteEnvVarsRecursive(copy.Index(i), original.Index(i))
		}

	case reflect.Map:
		copy.Set(reflect.MakeMap(original.Type()))
		for _, key := range original.MapKeys() {
			originalValue := original.MapIndex(key)
			copyValue := reflect.New(originalValue.Type()).Elem()
			substituteEnvVarsRecursive(copyValue, originalValue)
			copy.SetMapIndex(key, copyValue)
		}

	case reflect.String:
		replacedString := substituteEnvVars(original.Interface().(string))
		copy.SetString(replacedString)

	default:
		copy.Set(original)
	}

}

var RootCmd = &cobra.Command{
	Use:   "dex-k8s-authenticator",
	Short: "Dex Kubernetes Authenticator",
	Long:  `Dex Kubernetes Authenticator provides a web-interface to generate a kubeconfig file based on a selected Kubernetes cluster. One or more clusters can be defined in the configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {

		var config Config
		err := viper.Unmarshal(&config)
		if err != nil {
			log.Fatalf("Unable to decode configuration into struct, %v", err)
		}

		original := reflect.ValueOf(config)
		copy := reflect.New(original.Type()).Elem()
		substituteEnvVarsRecursive(copy, original)

		// Start the app
		start_app(copy.Interface().(Config))

		// Fallback if no args specified
		cmd.HelpFunc()(cmd, args)

	},
}

// Read in config file
func initConfig() {

	if config_file != "" {
		//viper.SetConfigFile(config_file)
		// get the filepath
		abs, err := filepath.Abs(config_file)
		if err != nil {
			log.Fatalf("Error reading config file, %s", err)
		}

		// get the config name
		base := filepath.Base(abs)

		// get the path
		path := filepath.Dir(abs)

		viper.SetConfigName(strings.Split(base, ".")[0])
		viper.AddConfigPath(path)
		viper.SetDefault("web_path_prefix", "/")

		config, err := ioutil.ReadFile(config_file)
		if err != nil {
			log.Fatalf("Error reading config file, %s", err)
		}

		origConfigStr := bytes.NewBuffer(config).String()
		viper.ReadConfig(bytes.NewBufferString(origConfigStr))

		log.Printf("Using config file: %s", viper.ConfigFileUsed())
	}
}

// Initialization
func init() {
	cobra.OnInitialize(initConfig)

	viper.BindPFlags(RootCmd.Flags())
	RootCmd.Flags().StringVar(&config_file, "config", "", "./config.yml")
	RootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Enable debug logging")
}

// Let's go!
func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}
