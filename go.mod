module github.com/mesosphere/dex-k8s-authenticator

go 1.13

require (
	github.com/coreos/go-oidc v2.2.1+incompatible
	github.com/mesosphere/konvoy-async-auth v0.1.3
	github.com/spf13/cast v1.5.0
	github.com/spf13/cobra v1.4.0
	github.com/spf13/viper v1.11.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/oauth2 v0.8.0
	k8s.io/apimachinery v0.28.1
	k8s.io/client-go v0.28.1
	k8s.io/utils v0.0.0-20230406110748-d93618cff8a2
)
