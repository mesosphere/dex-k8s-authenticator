package oidc

import (
	"context"
	"fmt"

	"github.com/coreos/go-oidc"
)

type Verifier interface {
	Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error)
}

type audienceVerifier struct {
	audiences []string
	verifier  *oidc.IDTokenVerifier
}

func NewAudienceVerifier(verifier *oidc.IDTokenVerifier, audiences []string) Verifier {
	return &audienceVerifier{
		verifier:  verifier,
		audiences: audiences,
	}
}

func (v *audienceVerifier) Verify(ctx context.Context, rawIDToken string) (*oidc.IDToken, error) {
	idToken, err := v.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return idToken, err
	}

	for _, expectedAudience := range v.audiences {
		if !contains(idToken.Audience, expectedAudience) {
			return nil, fmt.Errorf("oidc: expected audience %q got %q", expectedAudience, idToken.Audience)
		}
	}

	return idToken, nil
}

func contains(sli []string, ele string) bool {
	for _, s := range sli {
		if s == ele {
			return true
		}
	}
	return false
}
