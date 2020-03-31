package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"path"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
)

const (
	exampleAppState = "Vgn2lp5QnymFtLntKX5dM8k773PwcM87T4hQtiESC1q8wkUBgw5D3kH0r5qJ"

	// clusterNameCookieKey is a name of they cookie that contains cluster name
	clusterNameCookieKey = "cluster-name"
)

func (cluster *Cluster) oauth2Config(scopes []string) *oauth2.Config {

	return &oauth2.Config{
		ClientID:     cluster.Client_ID,
		ClientSecret: cluster.Client_Secret,
		Endpoint:     cluster.Provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  cluster.Redirect_URI,
	}
}

func (config *Config) handleIndex(w http.ResponseWriter, r *http.Request) {

	if len(config.Clusters) == 1 && r.URL.String() == config.Web_Path_Prefix {
		http.Redirect(w, r, path.Join(config.Web_Path_Prefix, "login", config.Clusters[0].Name), http.StatusSeeOther)
	} else {
		renderIndex(w, config)
	}
}

func (config *Config) handleCallback(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(clusterNameCookieKey)
	if err != nil {
		renderHTMLError(w, config, "Callback invoked without cluster name cookie", 400)
		log.Printf("config.handleCallback: cluster name cookie missing in request: %v", err)
		return
	}

	clusterNameBytes, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		renderHTMLError(w, config, "Failed to get cluster name from the cookie", 400)
		log.Printf("config.handleCallback: cluster name in cookie encoded incorrectly: %v", err)
		return
	}
	clusterName := string(clusterNameBytes)

	log.Printf("retrieved `%s` cluster name from cookie", clusterName)

	cluster := config.getCluster(clusterName)
	if cluster == nil {
		renderHTMLError(
			w,
			config,
			fmt.Sprintf("Cluster `%s` requested from cookie does not exists", clusterName),
			500,
		)
		log.Printf("config.handleCallback: cluster `%s` does not exists", clusterName)
		return
	}

	cluster.handleCallback(w, r)
}

func (config *Config) getCluster(name string) *Cluster {
	for _, c := range config.Clusters {
		if c.Name == name {
			return &c
		}
	}

	return nil
}

func (cluster *Cluster) handleLogin(w http.ResponseWriter, r *http.Request) {
	var scopes []string

	if len(cluster.Scopes) == 0 {
		scopes = append(scopes, "openid", "profile", "email", "offline_access", "groups")
	} else {
		scopes = cluster.Scopes
	}

	log.Printf("Handling login-uri for: %s", cluster.Name)
	authCodeURL := cluster.oauth2Config(scopes).AuthCodeURL(exampleAppState, oauth2.AccessTypeOffline)

	// Record the name of cluster
	http.SetCookie(w, &http.Cookie{
		Name:  clusterNameCookieKey,
		Value: base64.URLEncoding.EncodeToString([]byte(cluster.Name)),
		Path:  cluster.Config.Web_Path_Prefix,
	})

	log.Printf("Redirecting post-loginto: %s", authCodeURL)
	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (cluster *Cluster) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err      error
		token    *oauth2.Token
		IdpCaPem string
	)

	// An error message to that presented to the user
	userErrorMsg := "Invalid token request"

	log.Printf("Handling callback for: %s", cluster.Name)

	ctx := oidc.ClientContext(r.Context(), cluster.Client)
	oauth2Config := cluster.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			cluster.renderHTMLError(w, userErrorMsg, http.StatusBadRequest)
			log.Printf("handleCallback: request error. error: %s, error_description: %s", errMsg, r.FormValue("error_description"))
			return
		}
		code := r.FormValue("code")
		if code == "" {
			cluster.renderHTMLError(w, userErrorMsg, http.StatusBadRequest)
			log.Printf("handleCallback: no code in request: %q", r.Form)
			return
		}
		if state := r.FormValue("state"); state != exampleAppState {
			cluster.renderHTMLError(w, userErrorMsg, http.StatusBadRequest)
			log.Printf("handleCallback: expected state %q got %q", exampleAppState, state)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case "POST":
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			cluster.renderHTMLError(w, userErrorMsg, http.StatusBadRequest)
			log.Printf("handleCallback: no refresh_token in request: %q", r.Form)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		// Return non-HTML error for non GET/POST requests which probably wasn't executed by browser
		http.Error(w, fmt.Sprintf("Method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		cluster.renderHTMLError(w, userErrorMsg, http.StatusInternalServerError)
		log.Printf("handleCallback: failed to get token: %v", err)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		cluster.renderHTMLError(w, userErrorMsg, http.StatusInternalServerError)
		log.Printf("handleCallback: no id_token in response: %q", token)
		return
	}

	idToken, err := cluster.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		cluster.renderHTMLError(w, userErrorMsg, http.StatusInternalServerError)
		log.Printf("handleCallback: failed to verify ID token: %q, err: %v", rawIDToken, err)
		return
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")

	if cluster.Config.IDP_Ca_Pem != "" {
		IdpCaPem = cluster.Config.IDP_Ca_Pem
	} else if cluster.Config.IDP_Ca_Pem_File != "" {
		content, err := ioutil.ReadFile(cluster.Config.IDP_Ca_Pem_File)
		if err != nil {
			log.Fatalf("Failed to load CA from file %s, %s", cluster.Config.IDP_Ca_Pem_File, err)
		}
		IdpCaPem = cast.ToString(content)
	}

	cluster.renderToken(w, rawIDToken, token.RefreshToken,
		cluster.Config.IDP_Ca_URI,
		IdpCaPem,
		cluster.Config.Logo_Uri,
		cluster.Config.Web_Path_Prefix,
		viper.GetString("kubectl_version"),
		buff.Bytes())
}
