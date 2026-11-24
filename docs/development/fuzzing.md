# Fuzzing

Use the Estus fuzz harnesses to check parsers, codecs and resource limits against generated input. The harnesses exercise production code locally without opening SSH sessions or running containers.

## Replay seeds or run a campaign

The `fuzz` development shell supplies the pinned nightly Rust toolchain, Clang and `cargo-fuzz`. From the repository root, replay one committed corpus:

```sh
nix develop .#fuzz -c cargo fuzz run binding_schema fuzz/corpus/binding_schema -- -runs=0
```

For a bounded campaign, put the writable corpus first. This keeps generated inputs out of the committed seed directory:

```sh
target=binding_schema
mkdir -p "fuzz/generated-corpus/$target"
nix develop .#fuzz -c cargo fuzz run "$target" \
  "fuzz/generated-corpus/$target" "fuzz/corpus/$target" \
  -- -max_total_time=300 -max_len=16384 -rss_limit_mb=1024 -timeout=10
```

## Choose a target

| Target | What it checks |
| --- | --- |
| `binding_schema` | Tool schema compilation, argument mapping and validation limits |
| `command_encoding` | Command validation, shell quoting and request size limits |
| `file_encoding` | File request limits, data encoding and reply size accounting |
| `filename_metadata` | Raw SFTP filename and metadata decoding without a transport |
| `wire_budget` | Serialized JSON-RPC response limits and clipping |

Harnesses live in `fuzz/fuzz_targets/` and reviewed seeds in `fuzz/corpus/<target>/`. Generated inputs go to `fuzz/generated-corpus/<target>/`; crash artifacts go to `fuzz/artifacts/<target>/`. Git ignores both output directories. See [CI](ci.md) for what runs on pull requests.
