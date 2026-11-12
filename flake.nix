# Development shell for go-better-auth.
#
#   nix develop          enter the shell
#   nix flake update     move every tool to the current nixpkgs
#
# Pinned by flake.lock, so every contributor and CI get the same versions.
{
  description = "go-better-auth development environment";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            # Go toolchain and the checks PLAN.md section 7 requires.
            go
            gopls
            gotools # goimports
            go-tools # staticcheck
            delve

            # Scratch databases for pgstore and the differential harness.
            postgresql_17

            # Fixture generator (testdata/gen) drives the real better-auth.
            nodejs_24
            bun
          ];

          # Never let `go` download a different toolchain behind the flake's back.
          GOTOOLCHAIN = "local";

          shellHook = ''
            export PATH="$PWD/scripts:$PATH"
            echo "go-better-auth dev shell: $(go version | cut -d' ' -f3), postgres $(postgres --version | awk '{print $3}'), node $(node --version), bun $(bun --version)" >&2
          '';
        };
      });

      formatter = forAll (pkgs: pkgs.nixfmt-rfc-style);
    };
}
