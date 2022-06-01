# Developing and Running

## Building a binary

    make 
    
Creates `./bin/$(go env GOOS)/$(go env GOARCH)/dex-k8s-authenticator`

## Building a container

    make container

## Running it

### Start a Dex Server instance

You must have a `dex` instance running before starting `dex-k8s-authenticator`.

Follow the example here: https://dexidp.io/docs/getting-started/

Start `dex` locally using the config in `examples/dex-server-config-dex.yaml`

```bash
dex serve examples/dex-server-config-dev.yaml
```

### Start Dex K8s Authenticator

    ./bin/dex-k8s-authenticator --config ./examples/config.yaml

* Browse to http://localhost:5555
* Click 'Example Cluster'
* Click 'Log in with Email'
* Login with `admin@example.com` followed by the password `password`
* You should be redirected back to the dex-k8s-authenticator

### Configuration Options

Additional configuration options are explained [here](config.md)
