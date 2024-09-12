{
  description = "Useful flakes for golang and Kubernetes projects";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      with nixpkgs.legacyPackages.${system}; {
        packages = {
           release-please = buildNpmPackage rec {
            pname = "release-please";
            version = "16.12.0";
            src = fetchFromGitHub {
              owner = "googleapis";
              repo = "release-please";
              rev = "v${version}";
              hash = "sha256-M4wsk0Vpkl6JAOM2BdSu8Uud7XA+iRHAaQOxHLux+VE=";
            };
            npmDepsHash = "sha256-UXWzBUrZCIklITav3VShL+whiWmvLkFw+/i/k0s13k0=";
            dontNpmBuild = true;
          };

        };

        formatter = alejandra;
      }
    );
}
