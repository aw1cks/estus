{ ... }:
{
  perSystem = { config, pkgs, lib, ... }:
    let
      # Latest stable releases, pinned to their full commit IDs.
      checkout = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"; # v7.0.1
      lixInstaller = "samueldr/lix-gha-installer-action@a0fee77b2a98bb7c5c0ed7ae6d6ad4903dbdad0d"; # v2026-06-15
      nixCache = "nix-community/cache-nix-action@7df957e333c1e5da7721f60227dbba6d06080569"; # v7.0.2
      uploadArtifact = "actions/upload-artifact@50769540e7f4bd5e21e526ee35c689e35e0d6874"; # v4.4.0
      cachePrefix = "nix-\${{ runner.os }}-\${{ runner.arch }}-";
      # Must not start with cachePrefix: SSH baseline restores, and purges, any key
      # with that prefix, and would otherwise pick up the release toolchain store.
      releaseCachePrefix = "nix-release-\${{ runner.os }}-\${{ runner.arch }}-";
      releasePlease = "googleapis/release-please-action@45996ed1f6d02564a971a2fa1b5860e934307cf7"; # v5.0.0
      downloadArtifact = "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"; # v8.0.2
      pypiPublish = "pypa/gh-action-pypi-publish@7245906fb61fa33a13554f9d5fb856fe61758086"; # v1.14.3
      cratesIoAuth = "rust-lang/crates-io-auth-action@3268eb413133e2960fa4ae0e963ca76380c54cd9"; # v1.0.6
      uploadSarif = "github/codeql-action/upload-sarif@915412ff23e8b7659517e607487dbeae018f2934"; # v4.39.5
      scorecardAction = "ossf/scorecard-action@23f22cd43608bae7a1f1fa2603d7314dee9538a5"; # v2.6.0
      attest = "actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6"; # v4.2.2
      codecov = "codecov/codecov-action@303a32d7a59b442fa8d48b6a1cc6825c09c847a5"; # v7.1.1
      coverageCachePrefix = "nix-coverage-\${{ runner.os }}-\${{ runner.arch }}-";
      # The store cache for jobs that build the Rust code. Each job family has
      # its own prefix, so none restores, or purges, another's store.
      rustStoreCache = prefix: {
        uses = nixCache;
        "with" = {
          # Rust changes must refresh immutable caches, not just Nix changes.
          primary-key = prefix + "\${{ hashFiles('**/*.nix', 'flake.lock', '**/Cargo.toml', 'Cargo.lock', '**/*.rs') }}";
          restore-prefixes-first-match = prefix;
          save = true;
          # Fork tokens are read-only; builds still restore/save PR caches.
          purge = "\${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}";
          purge-prefixes = prefix;
          purge-created = 0;
          purge-primary-key = "never";
          gc-max-store-size-linux = "2G";
          gc-max-store-size-macos = "2G";
        };
      };
      # Every target a release ships: one SBOM attestation each. Publish checks
      # this against the SBOMs `release.py sbom` actually wrote.
      releaseTargets = [
        "x86_64-unknown-linux-gnu"
        "aarch64-unknown-linux-gnu"
        "x86_64-unknown-linux-musl"
        "aarch64-unknown-linux-musl"
        "aarch64-apple-darwin"
      ];
      # A fork's token can't write security events, and fork PRs must not get one.
      sameRepository = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository";
      # Checkout and Nix: the start of every job that runs inside the release dev
      # shell. Jobs that publish use this alone, never the Actions cache.
      nixInstall = [
        {
          uses = checkout;
          "with".persist-credentials = false;
        }
        {
          uses = lixInstaller;
          "with" = {
            github_access_token = "\${{ secrets.GITHUB_TOKEN }}";
            extra_nix_config = "auto-optimise-store = false\n";
          };
        }
      ];
      # nixInstall plus the shared store cache, for jobs that only build.
      nixSetup = nixInstall ++ [
        {
          # Never restore build state from the Actions cache when building a
          # release. Publishing runs on a tag, and so does release-artifacts.yml
          # when publish.yml calls it, so a cache any other run wrote cannot reach
          # a published artifact; Nix fetches from the signed binary cache instead.
          "if" = "\${{ !startsWith(github.ref, 'refs/tags/') }}";
          uses = nixCache;
          "with" = {
            primary-key = releaseCachePrefix + "\${{ hashFiles('**/*.nix', 'flake.lock') }}";
            restore-prefixes-first-match = releaseCachePrefix;
            save = true;
            purge = "\${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}";
            purge-prefixes = releaseCachePrefix;
            purge-created = 0;
            purge-primary-key = "never";
            gc-max-store-size-linux = "2G";
            gc-max-store-size-macos = "2G";
          };
        }
      ];
      releaseShell = "nix develop --no-update-lock-file .#release --command";
      # The last job of a workflow that GitHub sometimes fails to run (macOS
      # runners in particular). If any job it waits on failed or was cancelled,
      # it asks ci-retry.yml, from main, to look at this run once it has
      # finished; a run cannot re-run itself while it is in progress. ci-retry
      # only re-runs jobs that GitHub never ran or whose runner died.
      retryDispatch = { needs, condition ? "true" }: {
        name = "Request a retry of infrastructure failures";
        inherit needs;
        "if" = "\${{ always() && (contains(needs.*.result, 'failure') || contains(needs.*.result, 'cancelled')) && (github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository) && ${condition} }}";
        runs-on = "ubuntu-26.04";
        timeout-minutes = 5;
        permissions.actions = "write";
        steps = [
          {
            name = "Dispatch ci-retry.yml for this run";
            env = {
              GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
              GH_REPO = "\${{ github.repository }}";
              RUN_ID = "\${{ github.run_id }}";
            };
            run = ''gh workflow run ci-retry.yml --ref main -f run_id="$RUN_ID"'';
          }
        ];
      };
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
            # Every push to main gets its own group, so each commit is tested and
            # none is cancelled or skipped while another run is queued. Pull
            # requests and manual runs still share one group per ref, and a newer
            # run supersedes the older one.
            group = "\${{ github.workflow }}-\${{ github.event_name == 'push' && github.sha || github.ref }}";
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
            # A run with a cold Nix store takes 35-40 minutes; leave room for a
            # slow runner rather than failing on the clock.
            timeout-minutes = 75;
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
              (rustStoreCache cachePrefix)
              {
                name = "Run flake checks";
                run = "nix flake check -L --no-update-lock-file --keep-going";
              }
              {
                name = "Run packaged MSRV native and controller acceptance";
                run = ''
                  runtime=$(mktemp -d "$HOME/.estus-native.XXXXXXXX")
                  trap 'rm -rf -- "$runtime"' EXIT
                  export XDG_RUNTIME_DIR="$runtime"
                  nix run -L --no-update-lock-file .#ssh-native-msrv
                  nix run -L --no-update-lock-file .#controller-scripts-msrv
                  nix run -L --no-update-lock-file .#doctor-acceptance-msrv
                  nix run -L --no-update-lock-file .#progress-acceptance-msrv
                  nix run -L --no-update-lock-file .#wheel-acceptance
                  nix run -L --no-update-lock-file .#sdist-acceptance
                '';
              }
              {
                name = "Run packaged MSRV bundle acceptance";
                shell = "bash";
                run = ''
                  nix run -L --no-update-lock-file .#bundle-acceptance-msrv
                '';
              }
              {
                name = "Run packaged Linux acceptance";
                "if" = "runner.os == 'Linux'";
                env.DOCKER_HOST = "unix:///var/run/docker.sock";
                run = ''
                  nix run -L --no-update-lock-file .#ci
                  nix run -L --no-update-lock-file .#ci-msrv
                '';
              }
            ];
          };
          jobs.retry = retryDispatch { needs = [ "verify" ]; };
        };
        "cache-cleanup.yml" = {
          name = "Cache Cleanup";
          # pull_request_target would give fork PRs a write token too, but it runs
          # with the base repository's privileges on fork-triggered events, which
          # zizmor rightly treats as unsafe. Same-repo PRs clean up here; caches
          # from fork PRs age out under GitHub's 7-day eviction.
          on.pull_request.types = [ "closed" ];
          permissions.actions = "write";
          jobs.cleanup = {
            "if" = "github.event.pull_request.head.repo.full_name == github.repository";
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
        "fuzz-corpus.yml" = {
          name = "Fuzz corpus";
          on = {
            pull_request.paths = [
              "src/**"
              "fuzz/**"
              "Cargo.toml"
              "Cargo.lock"
            ];
            schedule = [
              { cron = "17 4 * * 1"; }
            ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          jobs.fuzz = {
            name = "Build fuzzers and replay committed corpora";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 30;
            permissions = {
              contents = "read";
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
                  extra_nix_config = "auto-optimise-store = false\n";
                };
              }
              {
                uses = nixCache;
                "with" = {
                  primary-key = cachePrefix + "fuzz-\${{ hashFiles('**/*.nix', 'flake.lock', '**/Cargo.toml', '**/Cargo.lock', '**/*.rs') }}";
                  restore-prefixes-first-match = cachePrefix + "fuzz-";
                  save = true;
                  purge = "\${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}";
                  purge-prefixes = cachePrefix + "fuzz-";
                  purge-created = 0;
                  purge-primary-key = "never";
                  gc-max-store-size-linux = "2G";
                  gc-max-store-size-macos = "2G";
                };
              }
              {
                name = "Build fuzz targets";
                run = "nix develop --no-update-lock-file .#fuzz --command cargo fuzz build";
              }
              {
                name = "Replay committed seed corpora";
                shell = "bash";
                run = ''
                  set -euo pipefail
                  for target in wire_budget file_encoding filename_metadata binding_schema command_encoding; do
                    echo "::group::$target"
                    nix develop --no-update-lock-file .#fuzz --command cargo fuzz run "$target" "fuzz/corpus/$target" -- -runs=0
                    echo "::endgroup::"
                  done
                '';
              }
            ];
          };
          # Time-boxed mutation campaigns: one lane per target, corpus written to
          # the ignored generated-corpus dir, crash artifacts uploaded on failure.
          # The -runs=0 replay above stays the committed-corpus gate.
          jobs.mutate = {
            name = "\${{ matrix.target }}";
            "if" = "github.event_name != 'pull_request'";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 45;
            strategy = {
              fail-fast = false;
              matrix.target = [
                "wire_budget"
                "file_encoding"
                "filename_metadata"
                "binding_schema"
                "command_encoding"
              ];
            };
            permissions = {
              contents = "read";
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
                  extra_nix_config = "auto-optimise-store = false\n";
                };
              }
              {
                uses = nixCache;
                "with" = {
                  primary-key = cachePrefix + "fuzz-\${{ hashFiles('**/*.nix', 'flake.lock', '**/Cargo.toml', '**/Cargo.lock', '**/*.rs') }}";
                  restore-prefixes-first-match = cachePrefix + "fuzz-";
                  save = true;
                  purge = "\${{ github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository }}";
                  purge-prefixes = cachePrefix + "fuzz-";
                  purge-created = 0;
                  purge-primary-key = "never";
                  gc-max-store-size-linux = "2G";
                  gc-max-store-size-macos = "2G";
                };
              }
              {
                name = "Build fuzz targets";
                run = "nix develop --no-update-lock-file .#fuzz --command cargo fuzz build";
              }
              {
                name = "Time-boxed mutation campaign";
                shell = "bash";
                "env".TARGET = "\${{ matrix.target }}";
                run = ''
                  set -euo pipefail
                  nix develop --no-update-lock-file .#fuzz --command cargo fuzz run "$TARGET" "fuzz/generated-corpus/$TARGET" "fuzz/corpus/$TARGET" -- -max_total_time=300 -max_len=16384 -rss_limit_mb=1024 -timeout=10
                '';
              }
              {
                "if" = "failure()";
                uses = uploadArtifact;
                "with".name = "fuzz-crashes-\${{ matrix.target }}";
                "with".path = "fuzz/artifacts/\${{ matrix.target }}";
                "with".if-no-files-found = "ignore";
              }
            ];
          };
        };
        # Builds every release artifact and tests it where it is meant to run. It
        # runs on pull requests that touch the release machinery, on demand, and
        # as the first stage of a release.
        "release-artifacts.yml" = {
          name = "Release artifacts";
          on = {
            pull_request.paths = [
              "scripts/release.py"
              "nix/flake/release.nix"
              "nix/ci.nix"
              "flake.lock"
              "setup.py"
              "pyproject.toml"
              "MANIFEST.in"
              "build.rs"
              "Cargo.toml"
              "Cargo.lock"
              ".github/workflows/release*.yml"
            ];
            workflow_dispatch = { };
            workflow_call = { };
          };
          permissions.contents = "read";
          jobs = {
            build-linux = {
              name = "Build Linux binaries, wheels and sdist";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 60;
              permissions = {
                contents = "read";
                actions = "write";
              };
              steps = nixSetup ++ [
                {
                  name = "Build binaries (glibc 2.34 floor and static musl, x86_64 and aarch64)";
                  run = "${releaseShell} python3 scripts/release.py binaries --out dist";
                }
                {
                  name = "Build wheels";
                  run = "${releaseShell} python3 scripts/release.py wheels --out dist";
                }
                {
                  name = "Build the source distribution";
                  run = "${releaseShell} python3 scripts/release.py sdist --out dist";
                }
                {
                  # Every target's, macOS included: they come from Cargo.lock and
                  # the target's cfg, not from a build.
                  name = "Write an SBOM per release target";
                  run = "${releaseShell} python3 scripts/release.py sbom --out dist";
                }
                {
                  name = "Check that the crate packages and builds";
                  run = "${releaseShell} cargo publish --dry-run --locked";
                }
                {
                  uses = uploadArtifact;
                  "with" = {
                    name = "release-linux";
                    path = "dist";
                    if-no-files-found = "error";
                    retention-days = 14;
                  };
                }
              ];
            };
            build-macos = {
              name = "Build macOS binary and wheel";
              runs-on = "macos-26";
              timeout-minutes = 45;
              permissions = {
                contents = "read";
                actions = "write";
              };
              steps = nixSetup ++ [
                {
                  name = "Build binary";
                  run = "${releaseShell} python3 scripts/release.py binaries --out dist";
                }
                {
                  name = "Build wheel";
                  run = "${releaseShell} python3 scripts/release.py wheels --out dist";
                }
                {
                  uses = uploadArtifact;
                  "with" = {
                    name = "release-macos";
                    path = "dist";
                    if-no-files-found = "error";
                    retention-days = 14;
                  };
                }
              ];
            };
            # Each architecture is tested on a runner of its own kind, so nothing
            # runs under emulation.
            smoke-linux = {
              name = "Smoke test Linux (\${{ matrix.arch }})";
              needs = "build-linux";
              runs-on = "\${{ matrix.runner }}";
              timeout-minutes = 30;
              strategy = {
                fail-fast = false;
                matrix.include = [
                  {
                    arch = "x86_64";
                    runner = "ubuntu-26.04";
                  }
                  {
                    arch = "aarch64";
                    runner = "ubuntu-26.04-arm";
                  }
                ];
              };
              steps = [
                {
                  uses = checkout;
                  "with".persist-credentials = false;
                }
                {
                  uses = downloadArtifact;
                  "with" = {
                    name = "release-linux";
                    path = "dist";
                  };
                }
                {
                  name = "Install and run the artifacts in distribution containers";
                  run = "python3 scripts/release.py smoke dist --mode docker";
                }
              ];
            };
            smoke-macos = {
              name = "Smoke test macOS";
              needs = "build-macos";
              runs-on = "macos-26";
              timeout-minutes = 30;
              permissions = {
                contents = "read";
                actions = "write";
              };
              steps = nixSetup ++ [
                {
                  uses = downloadArtifact;
                  "with" = {
                    name = "release-macos";
                    path = "dist";
                  };
                }
                {
                  name = "Install and run the artifacts";
                  run = "${releaseShell} python3 scripts/release.py smoke dist --mode native";
                }
              ];
            };
            # Only for this workflow's own runs. When publish.yml calls it, the
            # caller's retry job covers the whole run.
            retry = retryDispatch {
              needs = [ "build-linux" "build-macos" "smoke-linux" "smoke-macos" ];
              condition = "github.workflow == 'Release artifacts'";
            };
          };
        };
        # release-please keeps a release pull request up to date. When that is
        # merged it tags a draft release, and this workflow hands the tag to
        # publish.yml. Nothing here builds or publishes.
        "release-please.yml" = {
          name = "Release Please";
          on = {
            push.branches = [ "main" ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          # Never run two at once, so two pushes cannot race over the release
          # pull request.
          concurrency = {
            group = "release";
            cancel-in-progress = false;
          };
          jobs.release-please = {
            name = "Release pull request";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 10;
            permissions = {
              contents = "write";
              pull-requests = "write";
              issues = "write";
              actions = "write";
            };
            steps = [
              {
                id = "release";
                uses = releasePlease;
                "with" = {
                  config-file = ".github/release-please-config.json";
                  manifest-file = ".github/release-please-manifest.json";
                };
              }
              {
                # A pull request made with GITHUB_TOKEN triggers no workflows,
                # whatever permissions the token has. A dispatch is the
                # exception, so ask for the checks explicitly; they attach to
                # the branch head, which is what the pull request shows.
                name = "Run CI on the release pull request";
                "if" = "steps.release.outputs.prs_created == 'true'";
                env = {
                  GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                  GH_REPO = "\${{ github.repository }}";
                  # Parsed in the shell: GitHub evaluates a step's env even when
                  # an earlier step failed and this one will not run, and
                  # fromJSON fails on the empty output that leaves.
                  PR_JSON = "\${{ steps.release.outputs.pr }}";
                };
                run = ''
                  branch=$(jq -r .headBranchName <<<"$PR_JSON")
                  gh workflow run ssh-baseline.yml --ref "$branch"
                  gh workflow run release-artifacts.yml --ref "$branch"
                '';
              }
              {
                # The tag was created with GITHUB_TOKEN too, so it starts no
                # workflow (checked: neither a tag push nor a published release
                # does). Dispatch publish.yml on the tag itself instead: it then
                # runs against the tag's commit, and its environments see a tag.
                name = "Start publishing";
                "if" = "steps.release.outputs.release_created == 'true'";
                env = {
                  GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                  GH_REPO = "\${{ github.repository }}";
                  TAG = "\${{ steps.release.outputs.tag_name }}";
                };
                run = ''gh workflow run publish.yml --ref "$TAG"'';
              }
            ];
          };
        };
        # Builds, tests and publishes one release. It only runs on a tag, and only
        # for a draft release whose tag is on main, which is what release-please
        # leaves behind. The release is taken out of draft last, once every
        # channel has succeeded, so nobody sees a release with missing files.
        "publish.yml" = {
          name = "Publish";
          on = {
            # release-please.yml dispatches this on the new tag. A tag pushed by
            # a person, or by release-please with a personal token, starts it
            # directly; the checks below still require a draft release.
            push.tags = [ "v*" ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          # Never cancel a publish that may be partway through.
          concurrency = {
            group = "publish-\${{ github.ref }}";
            cancel-in-progress = false;
          };
          jobs = {
            verify = {
              name = "Check the release";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 5;
              # GitHub lists draft releases only to users with push access.
              permissions.contents = "write";
              steps = [
                {
                  name = "Require an unpublished release on a tag on main";
                  env = {
                    GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                    GH_REPO = "\${{ github.repository }}";
                    REF_TYPE = "\${{ github.ref_type }}";
                    TAG = "\${{ github.ref_name }}";
                    SHA = "\${{ github.sha }}";
                  };
                  run = ''
                    set -euo pipefail
                    if [ "$REF_TYPE" != tag ]; then
                      echo "::error::Run this on a release tag, not a branch."
                      exit 1
                    fi
                    case "$TAG" in
                      v[0-9]*) ;;
                      *) echo "::error::$TAG is not a version tag."; exit 1 ;;
                    esac
                    draft=$(gh api "repos/$GH_REPO/releases" --paginate \
                      --jq ".[] | select(.tag_name == \"$TAG\") | .draft")
                    if [ "$draft" != true ]; then
                      echo "::error::There is no draft release for $TAG; only an unpublished release can be published."
                      exit 1
                    fi
                    status=$(gh api "repos/$GH_REPO/compare/main...$SHA" --jq .status)
                    case "$status" in
                      identical|behind) ;;
                      *) echo "::error::$TAG is not on main."; exit 1 ;;
                    esac
                  '';
                }
              ];
            };
            artifacts = {
              name = "Artifacts";
              needs = "verify";
              uses = "./.github/workflows/release-artifacts.yml";
              permissions = {
                contents = "read";
                actions = "write";
              };
            };
            publish-github = {
              name = "GitHub release assets";
              needs = "artifacts";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 15;
              permissions = {
                contents = "write";
                # Sigstore signing and the attestations API.
                id-token = "write";
                attestations = "write";
              };
              steps = [
                {
                  uses = checkout;
                  "with".persist-credentials = false;
                }
                {
                  uses = downloadArtifact;
                  "with" = {
                    pattern = "release-*";
                    merge-multiple = true;
                    path = "dist";
                  };
                }
                {
                  name = "Write checksums";
                  run = "python3 scripts/release.py checksums dist";
                }
                # Attest before anything is attached: if this fails, the draft
                # release is untouched and the run can simply be re-run.
                {
                  name = "Attest build provenance for every asset";
                  uses = attest;
                  "with".subject-path = "dist/*";
                }
                {
                  name = "List the files each SBOM describes";
                  run = "python3 scripts/release.py sbom-subjects dist --out sbom-subjects --expect ${lib.concatStringsSep " " releaseTargets}";
                }
              ]
              ++ map (target: {
                name = "Attest the ${target} SBOM";
                uses = attest;
                "with" = {
                  sbom-path = "dist/estus-${target}.cdx.json";
                  subject-checksums = "sbom-subjects/${target}.sha256";
                };
              }) releaseTargets
              ++ [
                {
                  name = "Attach everything to the draft release";
                  env = {
                    GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                    GH_REPO = "\${{ github.repository }}";
                    TAG = "\${{ github.ref_name }}";
                  };
                  run = ''gh release upload "$TAG" dist/* --clobber'';
                }
              ];
            };
            publish-pypi = {
              name = "PyPI";
              needs = "artifacts";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 15;
              # Trusted publishing: PyPI trusts this workflow and environment, so
              # there is no token to store.
              environment = "pypi";
              permissions = {
                contents = "read";
                id-token = "write";
              };
              steps = [
                {
                  uses = downloadArtifact;
                  "with" = {
                    pattern = "release-*";
                    merge-multiple = true;
                    path = "all";
                  };
                }
                {
                  # The binary tarballs are not Python distributions.
                  name = "Select the wheels and the sdist";
                  env.TAG = "\${{ github.ref_name }}";
                  run = ''
                    version="''${TAG#v}"
                    mkdir pypi
                    cp all/*.whl "all/estus-$version.tar.gz" pypi/
                    ls -l pypi
                  '';
                }
                {
                  uses = pypiPublish;
                  "with".packages-dir = "pypi";
                }
              ];
            };
            publish-crates = {
              name = "crates.io";
              needs = "artifacts";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 30;
              environment = "crates-io";
              # Trusted publishing: crates.io trusts this workflow and
              # environment, and the job exchanges its OIDC token for a
              # short-lived crates.io token. No secret is stored.
              permissions = {
                contents = "read";
                id-token = "write";
              };
              steps = nixInstall ++ [
                {
                  # Fetch the toolchain before asking for a token, so the
                  # short-lived token is only alive for the publish itself.
                  name = "Prepare the release shell";
                  run = "${releaseShell} cargo --version";
                }
                {
                  id = "auth";
                  # Exchanges the job's OIDC token for a crates.io token, and
                  # revokes it again when the job ends.
                  uses = cratesIoAuth;
                }
                {
                  name = "Publish the crate";
                  env.CARGO_REGISTRY_TOKEN = "\${{ steps.auth.outputs.token }}";
                  run = "${releaseShell} cargo publish --locked";
                }
              ];
            };
            finalize = {
              name = "Publish the release";
              needs = [ "publish-github" "publish-pypi" "publish-crates" ];
              runs-on = "ubuntu-26.04";
              timeout-minutes = 5;
              permissions.contents = "write";
              steps = [
                {
                  name = "Take the release out of draft";
                  env = {
                    GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                    GH_REPO = "\${{ github.repository }}";
                    TAG = "\${{ github.ref_name }}";
                  };
                  run = ''gh release edit "$TAG" --draft=false'';
                }
              ];
            };
            retry = retryDispatch {
              needs = [ "verify" "artifacts" "publish-github" "publish-pypi" "publish-crates" "finalize" ];
            };
          };
        };
        # Line coverage and test results of the network-free Rust tests, for
        # Codecov, and on main a from-scratch `cargo build --timings`. Neither
        # gates merging: the tests' gate is `nix flake check` in SSH baseline.
        "coverage.yml" = {
          name = "Coverage";
          on = {
            pull_request = { };
            push.branches = [ "main" ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          concurrency = {
            group = "\${{ github.workflow }}-\${{ github.ref }}";
            cancel-in-progress = true;
          };
          jobs = {
            coverage = {
              name = "Coverage and test results";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 45;
              permissions = {
                contents = "read";
                # Codecov authenticates the uploads with an OIDC token.
                id-token = "write";
                # cache-nix-action needs this for same-ref cache purging.
                actions = "write";
              };
              steps = nixInstall ++ [
                (rustStoreCache coverageCachePrefix)
                {
                  name = "Run the tests with coverage";
                  run = "nix build -L --no-update-lock-file .#coverage --out-link coverage";
                }
              ]
              ++ map (upload: {
                name = "Upload ${upload.what} to Codecov";
                # Upload failing tests too: that is what test results are for.
                "if" = "\${{ !cancelled() }}";
                uses = codecov;
                "with" = upload.settings // {
                  disable_search = true;
                  fail_ci_if_error = true;
                  # A fork's pull request gets no OIDC token; Codecov takes
                  # tokenless uploads from forks of public repositories.
                  use_oidc = "\${{ ${sameRepository} }}";
                };
              }) [
                {
                  what = "coverage";
                  settings = {
                    files = "coverage/lcov.info";
                    flags = "unit";
                  };
                }
                {
                  what = "test results";
                  settings = {
                    files = "coverage/junit.xml";
                    flags = "unit";
                    report_type = "test_results";
                  };
                }
              ]
              ++ [
                {
                  # The coverage build reports failing tests instead of failing,
                  # so their results reach Codecov; fail here instead.
                  name = "Fail if any test failed";
                  run = ''
                    python3 - coverage/junit.xml <<'EOF'
                    import sys
                    import xml.etree.ElementTree as ET
                    suites = ET.parse(sys.argv[1]).getroot()
                    failed = int(suites.get("failures", 0)) + int(suites.get("errors", 0))
                    print(f"{suites.get('tests')} tests, {failed} failed")
                    sys.exit(1 if failed else 0)
                    EOF
                  '';
                }
              ];
            };
            build-timings = {
              name = "Build timings";
              # From scratch, dependencies included: worth it once per change
              # to main, not on every pull request push.
              "if" = "github.event_name != 'pull_request'";
              runs-on = "ubuntu-26.04";
              timeout-minutes = 45;
              permissions = {
                contents = "read";
                actions = "write";
              };
              steps = nixInstall ++ [
                (rustStoreCache coverageCachePrefix)
                {
                  name = "Build with cargo --timings";
                  run = ''
                    nix build -L --no-update-lock-file .#build-timings --out-link timings
                    cat timings/summary.md >> "$GITHUB_STEP_SUMMARY"
                  '';
                }
                {
                  uses = uploadArtifact;
                  "with" = {
                    name = "build-timings";
                    path = "timings/cargo-timing.html";
                    if-no-files-found = "error";
                    retention-days = 30;
                  };
                }
              ];
            };
          };
        };
        # Findings as SARIF in GitHub code scanning, so they show on the changed
        # lines of a pull request and in the Security tab. The blocking gates stay
        # in `nix flake check`; this adds zizmor's online audits, which need the
        # network and so can't run in the build sandbox, and clippy's findings as
        # annotations.
        "code-scanning.yml" = {
          name = "Code scanning";
          on = {
            push.branches = [ "main" ];
            pull_request = { };
            # Online audits can change with no change here: a pinned action can
            # turn out to be vulnerable, or a tag can move.
            schedule = [ { cron = "17 4 * * 1"; } ];
            workflow_dispatch = { };
          };
          permissions.contents = "read";
          concurrency = {
            group = "\${{ github.workflow }}-\${{ github.ref }}";
            cancel-in-progress = true;
          };
          jobs = {
            zizmor = {
              name = "zizmor";
              "if" = sameRepository;
              runs-on = "ubuntu-26.04";
              timeout-minutes = 15;
              permissions = {
                contents = "read";
                security-events = "write";
              };
              steps = nixInstall ++ [
                {
                  # The regular persona, as in the flake check. The pedantic one
                  # mostly asks for YAML comments, which generated workflows can't
                  # carry. GH_TOKEN enables the online audits: impostor commits,
                  # known-vulnerable actions, ref confusion and stale pins.
                  name = "Audit the workflows, including online audits";
                  env.GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                  run = "nix shell --no-update-lock-file --inputs-from . nixpkgs#zizmor --command zizmor --format sarif --no-exit-codes . > zizmor.sarif";
                }
                {
                  uses = uploadSarif;
                  "with" = {
                    sarif_file = "zizmor.sarif";
                    category = "zizmor";
                  };
                }
              ];
            };
            clippy = {
              name = "clippy";
              "if" = sameRepository;
              runs-on = "ubuntu-26.04";
              timeout-minutes = 30;
              permissions = {
                contents = "read";
                security-events = "write";
              };
              steps = nixInstall ++ [
                {
                  # Without -D warnings: the gate is checks.clippy; this records
                  # every finding, so it can be shown on the lines it concerns.
                  name = "Run clippy";
                  run = "nix develop --no-update-lock-file .#lint --command cargo clippy --locked --all-targets --all-features --message-format=json > clippy.json";
                }
                {
                  name = "Convert to SARIF";
                  run = "nix shell --no-update-lock-file --inputs-from . nixpkgs#clippy-sarif nixpkgs#sarif-fmt --command sh -c 'clippy-sarif < clippy.json | tee clippy.sarif | sarif-fmt'";
                }
                {
                  uses = uploadSarif;
                  "with" = {
                    sarif_file = "clippy.sarif";
                    category = "clippy";
                  };
                }
              ];
            };
          };
        };
        # OpenSSF Scorecard: a weekly supply-chain hygiene score, published for the
        # README badge and uploaded as SARIF. Publishing only works if this
        # workflow keeps to Scorecard's rules: no workflow-level env, defaults or
        # write permissions, and only approved actions in the job, so no run steps.
        "scorecard.yml" = {
          name = "Scorecard";
          on = {
            push.branches = [ "main" ];
            schedule = [ { cron = "23 5 * * 1"; } ];
          };
          permissions.contents = "read";
          jobs.analysis = {
            name = "Scorecard analysis";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 15;
            permissions = {
              contents = "read";
              actions = "read";
              security-events = "write";
              # Signs the results, so the Scorecard API can trust where they came
              # from before it publishes them.
              id-token = "write";
            };
            steps = [
              {
                uses = checkout;
                "with".persist-credentials = false;
              }
              {
                uses = scorecardAction;
                "with" = {
                  results_file = "results.sarif";
                  results_format = "sarif";
                  publish_results = true;
                  fail_on_publish_error = true;
                };
              }
              {
                "if" = "always()";
                uses = uploadArtifact;
                "with" = {
                  name = "scorecard-sarif";
                  path = "results.sarif";
                  retention-days = 5;
                };
              }
              {
                "if" = "always()";
                uses = uploadSarif;
                "with".sarif_file = "results.sarif";
              }
            ];
          };
        };
        # Re-runs a finished run's failed jobs when GitHub itself failed to run
        # them: the job never got a runner, or its runner died. A job that ran and
        # failed is left alone, and a run is tried at most three times. Dispatched
        # by the retry job at the end of the workflows above; scripts/ci-retry.sh
        # makes the decision, and can be run by hand with DRY_RUN=1.
        "ci-retry.yml" = {
          name = "CI retry";
          on.workflow_dispatch.inputs.run_id = {
            description = "Workflow run to inspect and, if GitHub failed to run its jobs, re-run";
            required = true;
            type = "string";
          };
          permissions.contents = "read";
          concurrency = {
            group = "ci-retry-\${{ inputs.run_id }}";
            cancel-in-progress = false;
          };
          jobs.retry = {
            name = "Re-run infrastructure failures";
            runs-on = "ubuntu-26.04";
            timeout-minutes = 20;
            permissions = {
              contents = "read";
              actions = "write";
              checks = "read";
            };
            steps = [
              {
                uses = checkout;
                "with".persist-credentials = false;
              }
              {
                name = "Re-run the run's failed jobs if GitHub failed to run them";
                env = {
                  GH_TOKEN = "\${{ secrets.GITHUB_TOKEN }}";
                  GH_REPO = "\${{ github.repository }}";
                  RUN_ID = "\${{ inputs.run_id }}";
                };
                run = "bash scripts/ci-retry.sh";
              }
            ];
          };
        };
      };
      rendered = lib.mapAttrs (name: workflow:
        pkgs.writeText "${name}.json" (builtins.toJSON workflow)
      ) workflows;
      generated = pkgs.runCommand "github-workflows" {
        nativeBuildInputs = [ pkgs.remarshal pkgs.python3 ];
      } ''
        mkdir -p "$out"
        ${lib.concatStringsSep "\n" (lib.mapAttrsToList (name: file: ''
          printf '%s\n' '# Generated from nix/ci.nix. Run: nix run .#generate-workflows' > "$out/${name}"
          remarshal --from json --to yaml-1.1 --yaml-style-newline '|' --width inf ${file} >> "$out/${name}"
        '') rendered)}
        python3 ${./annotate-action-pins.py} ${./ci.nix} "$out"/*.yml
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
      mkCi = name: acceptance: pkgs.writeShellApplication {
        inherit name;
        text = ''
          : "''${DOCKER_HOST:?set DOCKER_HOST to the Docker-compatible Unix socket}"
          export ESTUS_TEST_FIXTURE=${config.packages.ssh-fixture-image}
          ${acceptance}/bin/ssh-stdio
          exec ${acceptance}/bin/ssh-baseline
        '';
      };
      ci = mkCi "ci" config.packages.ssh-acceptance;
      ciMsrv = mkCi "ci-msrv" config.packages.ssh-acceptance-msrv;
    in
    {
      packages.github-workflows = generated;
      checks.workflows = pkgs.runCommand "github-workflows-current" {
        nativeBuildInputs = [ pkgs.diffutils ];
      } ''
        diff -ru ${generated} ${../.github/workflows}
        touch "$out"
      '';
      # Static security analysis of the workflows. It reads the generated files,
      # which checks.workflows keeps identical to the committed ones. Offline,
      # because the build sandbox has no network: the online audits only check
      # pins against GitHub, and the actions here are already pinned by SHA.
      checks.zizmor = pkgs.runCommand "github-workflows-zizmor" {
        nativeBuildInputs = [ pkgs.zizmor ];
      } ''
        export HOME="$TMPDIR" NO_COLOR=1
        zizmor --offline --no-progress --config ${../.github/zizmor.yml} ${generated}/*.yml
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
        ci-msrv = {
          type = "app";
          program = lib.getExe ciMsrv;
        };
      };
    };
}
