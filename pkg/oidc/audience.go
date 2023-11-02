package oidc

import "strings"

// getClusterAudiences returns list of expected audiences in the OIDC token. The
// DKA OIDC client is requesting tokens for TFA client. The verifier should make
// sure that all requested audiences are in the token.
func GetClusterAudiences(clientID string, scopes []string) []string {
	audiences := []string{clientID}
	for _, scope := range scopes {
		if strings.HasPrefix(scope, "audience:server:client_id:") {
			audiences = append(audiences, strings.TrimPrefix(scope, "audience:server:client_id:"))
		}
	}
	return audiences
}
