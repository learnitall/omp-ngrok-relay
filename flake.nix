{
  description = "Content-blind relay for omp collab sessions";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    devshell = {
      url = "github:numtide/devshell";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      devshell,
      treefmt-nix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ devshell.overlays.default ];
        };
        inherit (pkgs) lib;

        treefmt = treefmt-nix.lib.evalModule pkgs ./treefmt.nix;

        # Single source of truth; `bun run build` reads git describe instead.
        version = (lib.importJSON ./package.json).version;

        # `bun install` resolves platform-specific optional deps (@ngrok/ngrok
        # ships per-platform napi prebuilds), so the vendored tree — and its
        # hash — differ per system. Add yours with the hash `nix build` reports.
        nodeModulesHash = {
          aarch64-darwin = "sha256-WQDAQU9d2XFic0T3Rf0ra/B/NKxukFG7yQGGAJ6Gazc=";
        };

        nodeModules = pkgs.stdenvNoCC.mkDerivation {
          pname = "omp-collab-relay-node-modules";
          inherit version;
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./package.json
              ./bun.lock
            ];
          };
          nativeBuildInputs = [ pkgs.bun ];
          dontConfigure = true;
          buildPhase = ''
            export HOME=$TMPDIR
            bun install --frozen-lockfile --no-progress
          '';
          installPhase = "cp -R node_modules $out";

          outputHashAlgo = "sha256";
          outputHashMode = "recursive";
          outputHash =
            nodeModulesHash.${system}
              or (throw "no node_modules hash for ${system}: build once with lib.fakeHash and record what nix reports");
        };
      in
      {
        packages = rec {
          default = relay;

          # The browser client is deliberately absent: building it needs a
          # network fetch of a pinned oh-my-pi commit (`bun run client`), which
          # a pure derivation cannot do. The relay serves nothing at `/` here.
          relay = pkgs.stdenvNoCC.mkDerivation {
            pname = "omp-collab-relay";
            inherit version;
            src = lib.fileset.toSource {
              root = ./.;
              fileset = lib.fileset.unions [
                ./relay.ts
                ./policy.ts
                ./package.json
                ./scripts
              ];
            };
            nativeBuildInputs = [ pkgs.bun ];
            buildPhase = ''
              runHook preBuild
              export HOME=$TMPDIR
              ln -s ${nodeModules} node_modules
              bun scripts/embed-dist.ts
              bun build ./relay.ts --compile --minify \
                --define BUILD_VERSION="\"${version}\"" \
                --outfile omp-collab-relay
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 omp-collab-relay $out/bin/omp-collab-relay
              runHook postInstall
            '';

            meta = {
              description = "Content-blind relay for omp collab sessions";
              mainProgram = "omp-collab-relay";
              license = lib.licenses.mit;
              platforms = lib.platforms.unix;
            };
          };

        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          # OCI image; `docker load < result`. Linux only: dockerTools would
          # otherwise package the host's Mach-O binary into a Linux image.
          # On macOS, cross-compile instead:
          #   bun build ./relay.ts --compile --target=bun-linux-arm64 ...
          container = pkgs.dockerTools.buildLayeredImage {
            name = "omp-collab-relay";
            tag = version;
            contents = [
              self.packages.${system}.relay
              pkgs.cacert
            ];
            config = {
              Entrypoint = [ (lib.getExe self.packages.${system}.relay) ];
              # 0.0.0.0 so the port is reachable from outside the container.
              Cmd = [
                "--hostname"
                "0.0.0.0"
              ];
              ExposedPorts."7466/tcp" = { };
            };
          };
        };

        devShells.default = pkgs.devshell.mkShell {
          name = "omp-collab-relay";
          packages = with pkgs; [
            bun
            typos
            git
          ];
          commands = [
            {
              name = "dev";
              help = "run the relay from source on :7466";
              command = "bun relay.ts \"$@\"";
            }
            {
              name = "client";
              help = "build the pinned collab-web client into dist/";
              command = "bun run client";
            }
            {
              name = "check";
              help = "typecheck, lint, spellcheck, test";
              command = ''
                set -e
                bun run typecheck
                bun run lint
                typos
                bun run test
              '';
            }
          ];
        };

        formatter = treefmt.config.build.wrapper;
        checks.formatting = treefmt.config.build.check self;
      }
    );
}
