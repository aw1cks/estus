{ ... }:
{
  perSystem = { config, pkgs, lib, ... }:
    let
      # Latest stable releases, pinned to their full commit IDs.
      checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"; # v7.0.1
      lixInstaller = "samueldr/lix-gha-installer-action@a0fee77b2a98bb7c5c0ed7ae6d6ad4903dbdad0d"; # v2026-06-15
      nixCache = "nix-community/cache-nix-action@7df957e333c1e5da7721f60227dbba6d06080569"; # v7.0.2
      cachePrefix = "nix-\${{ runner.os }}-\${{ runner.arch }}-";
      workflows = {
        "ssh-baseline.yml" = {
          name = "SSH baseline";
          on = {
            pull_request = { };
            push.branches = [ "main" ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          concurrency = {
            group = "\${{ github.workflow }}-\${{ github.ref }}";
            # Let main finish seeding its cache; superseded PRs can stop.
            cancel-in-progress = "\${{ github.event_name != 'push' }}";
          };
          jobs.verify = {
            name = "\${{ matrix.name }}";
            runs-on = "\${{ matrix.runner }}";
            strategy = {
              fail-fast = false;
              matrix.include = [
                {
                  # Preserve the existing required-check name.
                  name = "ssh-baseline-linux";
                  runner = "ubuntu-26.04";
                }
                {
                  name = "ssh-baseline-linux-arm64";
                  runner = "ubuntu-26.04-arm";
                }
                {
                  name = "ssh-native-macos-arm64";
                  runner = "macos-26";
                }
              ];
            };
            timeout-minutes = 45;
            permissions = {
              contents = "read";
              # cache-nix-action needs this for same-ref cache purging.
              actions = "write";
            };
            steps = [
              {
                uses = checkout;
                "with".persist-credentials = false;
              }
              {
                uses = lixInstaller;
                "with" = {
                  github_access_token = "\${{ secrets.GITHUB_TOKEN }}";
                  # Lix's .links optimisation conflicts with store-cache restore.
                  extra_nix_config = "auto-optimise-store = false\n";
                };
              }
              {
                uses = nixCache;
                "with" = {
                  # Rust changes must refresh immutable caches, not just Nix changes.
                  primary-key = cachePrefix + "\${{ hashFiles('**/*.nix', 'flake.lock', '**/Cargo.toml', 'Cargo.lock', '**/*.rs') }}";
                  restore-prefixes-first-match = cachePrefix;
                  save = true;
                  # Fork tokens are read-only; builds still restore/save PR caches.
                  purge = "\${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}";
                  purge-prefixes = cachePrefix;
                  purge-created = 0;
                  purge-primary-key = "never";
                  gc-max-store-size-linux = "2G";
                  gc-max-store-size-macos = "2G";
                };
              }
              {
                name = "Run flake checks";
                run = "nix flake check -L --no-update-lock-file --keep-going";
              }
              {
                name = "Run packaged native SSH acceptance";
                "if" = "runner.os == 'macOS'";
                run = ''
                  runtime=$(mktemp -d "$HOME/.ssh-mcp-native.XXXXXXXX")
                  trap 'rm -rf -- "$runtime"' EXIT
                  XDG_RUNTIME_DIR="$runtime" nix run -L --no-update-lock-file .#ssh-native
                '';
              }
              {
                name = "Run packaged Linux acceptance";
                "if" = "runner.os == 'Linux'";
                env.DOCKER_HOST = "unix:///var/run/docker.sock";
                run = "nix run -L --no-update-lock-file .#ci";
              }
            ];
          };
        };
        "cache-cleanup.yml" = {
          name = "Cache Cleanup";
          # Closed fork PRs need a write token too. Never check out PR code here.
          on.pull_request_target.types = [ "closed" ];
          permissions.actions = "write";
          jobs.cleanup = {
            name = "Cleanup PR caches";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 5;
            steps = [
              {
                name = "Delete PR-scoped caches";
                env = {
                  GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                  REPO = "\${{ github.repository }}";
                  PR_REF = "refs/pull/\${{ github.event.pull_request.number }}/merge";
                };
                run = ''
                  for prefix in nix- lix-installer-; do
                    gh cache list \
                      --repo "$REPO" --ref "$PR_REF" \
                      --key "$prefix" --limit 10000 \
                      --json key --jq '.[].key' |
                      while read -r key; do
                        [ -n "$key" ] || continue
                        gh cache delete "$key" --repo "$REPO" --ref "$PR_REF"
                      done
                  done
                '';
              }
            ];
          };
        };
      };
      rendered = lib.mapAttrs (name: workflow:
        pkgs.writeText "${name}.json" (builtins.toJSON workflow)
      ) workflows;
      generated = pkgs.runCommand "github-workflows" {
        nativeBuildInputs = [ pkgs.remarshal ];
      } ''
        mkdir -p "$out"
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: file: ''
          printf '%s\n' '# Generated from nix/ci.nix. Run: nix run .#generate-workflows' > "$out/${name}"
          remarshal --from json --to yaml-1.1 --yaml-style-newline '|' --width inf ${file} >> "$out/${name}"
        '') rendered)}
      '';
      generateWorkflows = pkgs.writeShellApplication {
        name = "generate-workflows";
        runtimeInputs = [ pkgs.git pkgs.coreutils ];
        text = ''
          root=$(git rev-parse --show-toplevel)
          mkdir -p "$root/.github/workflows"
          install -m644 ${generated}/* "$root/.github/workflows/"
        '';
      };
      ci = pkgs.writeShellApplication {
        name = "ci";
        text = ''
          : "''${DOCKER_HOST:?set DOCKER_HOST to the Docker-compatible Unix socket}"
          export SSH_MCP_TEST_FIXTURE=${config.packages.ssh-fixture-image}
          ${config.packages.ssh-acceptance}/bin/ssh-stdio
          exec ${config.packages.ssh-acceptance}/bin/ssh-baseline
        '';
      };
    in
    {
      packages.github-workflows = generated;
      checks.workflows = pkgs.runCommand "github-workflows-current" {
        nativeBuildInputs = [ pkgs.diffutils ];
      } ''
        diff -ru ${generated} ${../.github/workflows}
        touch "$out"
      '';
      apps = {
        generate-workflows = {
          type = "app";
          program = lib.getExe generateWorkflows;
        };
      } // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        ci = {
          type = "app";
          program = lib.getExe ci;
        };
      };
    };
}
