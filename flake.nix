{
  description = "Content-blind relay for omp collab sessions, published through ngrok";

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

        # The pinned collab-web client, shared with `bun run client`.
        client = lib.importJSON ./client.json;

        # Blobless partial clone + cone-mode sparse checkout: fetchgit sets
        # `remote.origin.partialclonefilter = blob:none` and checks out only
        # these directories, so a 235 MB monorepo lands as ~5 MB of source.
        # The list is the client plus every workspace member bun.lock resolves
        # its deps to (`@oh-my-pi/pi-{utils,wire}` and pi-utils' own
        # `pi-natives`), plus the two paths the root manifest names outright:
        # `python/robomp/web` is a literal workspace entry and `patches` holds
        # patch files bun reads during resolution. Miss any and bun install
        # either falls back to the registry or refuses to resolve at all.
        ompSrc = pkgs.fetchFromGitHub {
          inherit (client) owner repo;
          rev = client.commit;
          inherit (client) sparseCheckout;
          hash = client.srcHash;
        };

        # Fixed-output: `bun install` needs the network. The hash covers the
        # built client, so it also pins bundler output — bump `distHash` when
        # the pin or nixpkgs' bun moves and nix reports a mismatch.
        clientDist = pkgs.stdenvNoCC.mkDerivation {
          pname = "omp-collab-web";
          version = builtins.substring 0 12 client.commit;
          src = ompSrc;
          nativeBuildInputs = [ pkgs.bun ];
          dontConfigure = true;
          buildPhase = ''
            runHook preBuild
            export HOME=$TMPDIR
            # Only the client's closure (93 packages, not 394). Frozen would
            # fail: the workspace members left out of the checkout read as drift.
            bun install --no-progress --filter ./${client.path}
            (cd ${client.path} && bun run build)
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            cp -R ${client.path}/dist $out
            runHook postInstall
          '';

          outputHashAlgo = "sha256";
          outputHashMode = "recursive";
          outputHash = client.distHash;
        };

        # `bun install` resolves platform-specific optional deps (@ngrok/ngrok
        # ships per-platform napi prebuilds), so the vendored tree — and its
        # hash — differ per system. Add yours with the hash `nix build` reports.
        # The linux pair came from `nixos/nix` containers under podman, the
        # x86_64 one through qemu emulation on arm64 hardware.
        nodeModulesHash = {
          aarch64-darwin = "sha256-ZbdVOxVrDx/kMZroIehkGL4lYTuo8+IwUoDRGrVAf7k=";
          aarch64-linux = "sha256-mszI37tuvPxbE60f2qgTwmuc21KlEJTnCzNCWSNRSDc=";
          x86_64-linux = "sha256-MwA0SOUCgevosmZbEfGEh49V4olk5QZKWQ5V6AsBmJk=";
        };

        nodeModules = pkgs.stdenvNoCC.mkDerivation {
          pname = "omp-ngrok-relay-node-modules";
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

          # The browser guest client, built from the pin in `client.json`.
          client = clientDist;

          relay = pkgs.stdenvNoCC.mkDerivation {
            pname = "omp-ngrok-relay";
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
              # Copied, not symlinked: through a symlink bun leaves @ngrok/ngrok's
              # napi prebuild out of the binary and bakes an absolute store path
              # for it instead, so the tunnel dies on `Cannot require module`.
              cp -R ${nodeModules} node_modules
              chmod -R u+w node_modules
              ln -s ${clientDist} dist
              bun scripts/embed-dist.ts
              bun build ./relay.ts --compile --minify \
                --define BUILD_VERSION="\"${version}\"" \
                --outfile omp-ngrok-relay
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              install -Dm755 omp-ngrok-relay $out/bin/omp-ngrok-relay
              runHook postInstall
            '';

            meta = {
              description = "Content-blind relay for omp collab sessions, published through ngrok";
              mainProgram = "omp-ngrok-relay";
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
            name = "omp-ngrok-relay";
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
          name = "omp-ngrok-relay";
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
