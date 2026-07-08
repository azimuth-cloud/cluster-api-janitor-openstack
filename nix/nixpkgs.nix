import (builtins.fetchTarball {
  # nixos-26.05 — require Go 1.26+
  # To update: nix-prefetch-url --unpack https://github.com/NixOS/nixpkgs/archive/<rev>.tar.gz
  url = "https://github.com/NixOS/nixpkgs/archive/refs/heads/nixos-26.05.tar.gz";
}) {}
