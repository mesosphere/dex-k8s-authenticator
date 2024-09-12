# Dex K8s Authenticator

A helper web-app which talks to one or more [Dex Identity services](https://github.com/coreos/dex) to generate
`kubectl` commands for creating and modifying a `kubeconfig`.

The Web UI supports generating tokens against multiple cluster such as Dev / Staging / Production.


## Also provides
* Helm Charts
* SSL Support
* Linux/Mac/Windows instructions

## Documentation

- [Developing and Running](docs/develop.md)
- [Configuration Options](docs/config.md)
- [Using the Helm Charts](docs/helm.md)
- [SSL Support](docs/ssl.md)

## Release

### Creating a release PR

This project uses [release-please] to automate changelog updates per release. Due to security restrictions[^1] in the
`nutanix-cloud-native` GitHub organization, the release process is a little more complex than just using the
[release-please-action].

When a release has been cut, a new release PR can be created manually using the `release-please` CLI locally. This needs
to be run by someone with write permissions to the repository. Create the `release-please` branch and PR:

```shell
make release-please
```

This will create the branch and release PR. From this point on until a release is ready, the `release-please-action`
will keep the PR up to date (GHA workflows are only not allowed to create the original PR, they can keep the PR up to
date).

## Screen shots

![Index Page](examples/index-page.png)

![Kubeconfig Page](examples/kubeconfig-page.png)


## Contributing

Feel free to raise feature-requests and bugs. PR's are also very welcome.

## Alternatives

- https://github.com/heptiolabs/gangway
- https://github.com/micahhausler/k8s-oidc-helper
- https://github.com/negz/kuberos
- https://github.com/negz/kubehook
- https://github.com/fydrah/loginapp

This application is based on the original [example-app](https://github.com/coreos/dex/tree/master/cmd/example-app
) available in the CoreOS Dex repo.

[^1]: Specifically, GitHub Actions workflows are not allowed to create or approve PRs due to a potential security flaw.
    See [this blog post][cider-sec] for more details, as well as the [Security Hardening for GitHub Actions
    docs][gha-security-hardening].

[release-please]: https://github.com/googleapis/release-please/
[release-please-action]: https://github.com/googleapis/release-please-action

