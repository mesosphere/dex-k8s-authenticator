package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc"
	"github.com/mesosphere/konvoy-async-auth/pkg/kaal"
	asyncauth "github.com/mesosphere/konvoy-async-auth/pkg/kaal/server"
	"github.com/mesosphere/konvoy-async-auth/pkg/kaal/server/storage"
	"golang.org/x/oauth2"
)

const (
	HmacTTL = 300
)

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
