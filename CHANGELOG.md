# Changelog
All notable changes to this project will be documented in this file.

## 1.4.5-d2iq (2026-05-04)

## What's Changed
* build(deps): bump cachix/install-nix-action from V28 to 30 by @dependabot[bot] in https://github.com/mesosphere/dex-k8s-authenticator/pull/55
* fix: replace login screen DKP with NKP by @arthurchang-x in https://github.com/mesosphere/dex-k8s-authenticator/pull/57
* fix(dependabot): ignore private dependency by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/58
* fix(dependabot): ingore private depds by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/60
* fix: bump go deps by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/61
* build(deps): bump jetify-com/devbox-install-action from 0.11.0 to 0.12.0 by @dependabot[bot] in https://github.com/mesosphere/dex-k8s-authenticator/pull/59

## New Contributors
* @arthurchang-x made their first contribution in https://github.com/mesosphere/dex-k8s-authenticator/pull/57

**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.4.4-d2iq...v1.4.5-d2iq

## 1.4.4-d2iq (2024-09-17)

## What's Changed
* fix: bump kaas 0.2.3 by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/52


**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.4.3-d2iq...v1.4.4-d2iq

## 1.4.3-d2iq (2024-09-17)

## What's Changed
* chore: bump kaas 0.2.2 by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/50
* build(deps): bump cachix/install-nix-action from 27 to 28 by @dependabot in https://github.com/mesosphere/dex-k8s-authenticator/pull/49


**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.4.2-d2iq...v1.4.3-d2iq

## 1.4.2-d2iq (2024-09-13)

## What's Changed
* fix: release workflow name by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/45
* chore: bump go to 1.23.1 by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/47
* chore: bump kaas 0.2.1 by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/48


**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.4.1-d2iq...v1.4.2-d2iq

## 1.4.1-d2iq (2024-09-12)

## What's Changed
* release(mesosphere):  v1.4.0-d2iq by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/42
* chore: add docs for creating release please pr by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/43


**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.4.0-d2iq...v1.4.1-d2iq

## 1.4.0-d2iq (2024-09-09)

## What's Changed
* feat: bump kaas to v0.2.0 and support arm macOS cli by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/33
* chore: add dependaboto config by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/35
* chore: switch to devbox by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/36
* chore: add tests on PR run by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/37
* build(deps): bump docker/login-action from 1 to 3 by @dependabot in https://github.com/mesosphere/dex-k8s-authenticator/pull/38
* build(deps): bump actions/checkout from 2 to 4 by @dependabot in https://github.com/mesosphere/dex-k8s-authenticator/pull/39
* feat: add release please action for mesosphere branch by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/34
* fix: add empty .release-please-manifest.json by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/40
* fix: add initial release version by @mhrabovcin in https://github.com/mesosphere/dex-k8s-authenticator/pull/41

## New Contributors
* @dependabot made their first contribution in https://github.com/mesosphere/dex-k8s-authenticator/pull/38

**Full Changelog**: https://github.com/mesosphere/dex-k8s-authenticator/compare/v1.3.4-d2iq...v1.4.0-d2iq

## [v1.1.0]

### Added

- Documentation on `web_path_prefix`

- Helm charts now add a checksum annotation on the configmap to roll-deployments when configuration changes

- Added IDPCaPem option to support displaying of idp-ca inline


### Changed

- Bump dex version to `v2.13.0` and pull from new repo at quay.io/dexidp/dex

- Documentation improvements

### Fixed

- Fixes to some css to use relative paths

## [v1.0.0]
### Added

- New tabbed layout with clipboard copy options. Key driver for this is to
enable Windows specific instructions.

- Added envar substitutions. Can now generate a config based on values in the
environment (useful for the `client_secret`).

- Added `nodePort` support to Helm charts.

- Added `kubectl_version` option in config. Used to construct a download link to `kubectl` which may be useful.

- Added `web_path_prefix` config option to set url-prefix for serving requests and assets.

- Added `trusted_root_ca` config option to specifiy 1 more root CA's.

- Added `k8s_ca_pem` config option to provide abililty to specify the Kubernetes CA inline.

### Changed

- Use `ClusterName` in preference to `ClientID` when generating k8s context commands

- Bump dex version to `v2.10.0`

- Bump base image to `alpine 3.8`

- Documentation updates.

- Helm chart for dex-k8s-authenticator would fail when caCerts were specified due to breaking naming conventions on and Secret and Volume resources. Introduce a required `filename` option which lets us separate out the filename of the cert and the name of the k8s resource created.

- Slim down final docker container size.

### Fixed

- `update-ca-certificates` only accepts *.crt (only attempt to copy these)

## [v0.4.0]
### Added
- Abililty to provide K8s cert file content in configuration via k8s_ca_pem
cluster option.

### Fixed
- Explicitly define the CA certificate path using ${HOME}

## [v0.3.0]
### Added
- Allow self-signed certs to be used

### Changed
- Bump to golang:1.9.4-alpine3.7

### Fixed
- Fixed helm-chart ingress servicePort

## [v0.2.0]
### Added
- Helm chart serviceAccountName
- Documentation improvements

### Changed
- Helm chart RBAC (renamed some vars).

## [v0.1.0]
### Added
- Initial release
