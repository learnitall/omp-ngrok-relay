{ lib, ... }:
{
  projectRootFile = "flake.nix";

  programs.nixfmt.enable = true;

  programs.biome = {
    enable = true;
    # biome.json is the single source of truth. Without this, treefmt-nix
    # generates its own config from `settings` (default: biome's defaults) and
    # passes `--config-path`, so `nix fmt` and `bun run fmt` fight each other.
    # Keep the pinned @biomejs/biome in package.json matching pkgs.biome.
    settings = lib.importJSON ./biome.json;
    # treefmt-nix validates against a schema that lags pkgs.biome.
    validate.enable = false;
  };

  # Spelling: biome has no typo rule, so crate-ci/typos covers prose and identifiers.
  programs.typos.enable = true;

  settings.global.excludes = [
    "*.lock"
    "bin/**"
    "dist/**"
    ".cache/**"
    "dist-embed.generated.ts"
    "LICENSE"
  ];
}
