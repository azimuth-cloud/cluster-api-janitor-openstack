{ pkgs ? import ./nixpkgs.nix }:

let
  # Build the manager binary for a given package set (native or cross).
  buildManager = p: p.buildGoModule {
    pname = "cluster-api-janitor-openstack";
    version = "0.0.0-dev";
    src = ../.;
    subPackages = [ "cmd" ];
    CGO_ENABLED = "0";
    ldflags = [ "-s" "-w" ];
    # Run `nix-build nix -A manager` once; it will fail and print the real hash.
    vendorHash = pkgs.lib.fakeHash;
    postInstall = ''
      mv $out/bin/cmd $out/bin/manager
    '';
    meta.mainProgram = "manager";
  };

  # Build a layered OCI image for a given package set.
  buildImage = p: m: p.dockerTools.buildLayeredImage {
    name = "ghcr.io/azimuth-cloud/cluster-api-janitor-openstack";
    tag = "latest";
    contents = [ pkgs.cacert m ];
    config = {
      Entrypoint = [ "/bin/manager" ];
      ExposedPorts."8081/tcp" = {};
      User = "65532:65532";
      Labels = {
        "org.opencontainers.image.source" =
          "https://github.com/azimuth-cloud/cluster-api-janitor-openstack";
        "org.opencontainers.image.licenses" = "Apache-2.0";
      };
    };
  };

  manager = buildManager pkgs;
  image   = buildImage pkgs manager;

  # arm64 cross-compiled on an amd64 host.
  crossPkgs   = pkgs.pkgsCross.aarch64-multiplatform;
  manager-arm64 = buildManager crossPkgs;
  image-arm64   = buildImage crossPkgs manager-arm64;

  # SBOM — reads Go build-info embedded in the static binary (survives -s -w).
  sbom = pkgs.runCommand "sbom.cdx.json" {
    nativeBuildInputs = [ pkgs.syft ];
  } ''
    syft scan ${manager}/bin/manager \
      --output cyclonedx-json \
      --file $out
  '';

in { inherit manager image image-arm64 sbom; }
