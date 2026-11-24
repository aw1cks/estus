# Deploy with separate accounts

If your agent can run local commands, run Estus under a different Linux account from the MCP client. This guide uses the [separated-account examples](../examples/README.md#separate-accounts) to expose a forced MCP stdio session over OpenSSH without giving the client the service account's credentials or shell.

## Set up the service

1. **Create three unprivileged accounts.** Run the agent as `estus-client`, Estus as `estus-service`, and the remote operation as `estus-target` (which can be on another machine). Give `estus-service` the passwd home `/var/lib/estus-service` and login shell `/bin/sh`: `sshd` invokes the forced command through that shell with `-c`, so `nologin` will not work. Disable any other login route to `estus-service`. Do not give the client `sudo`, `su`, service-group membership, ptrace access to the service, or host or container-runtime administration. These restrictions keep the client from assuming the service identity outside MCP.

2. **Install the files and lock down the directories.** Use the paths in the table so the wrapper and helper match the examples. Neither the client nor the service may modify the executable, helper or ingress wrapper, daemon configuration, Estus policy, outbound SSH configuration or ingress authorized keys. Keep their parent directories under trusted control too. This prevents either account from rewriting the rules that govern the connection.

   | Path | Owner and mode | Purpose |
   | --- | --- | --- |
   | `/opt/estus` | Root-controlled installation | Install the Linux package or closure here; a root-owned symlink to an immutable package works. The wrapper starts `/opt/estus/bin/estus`. |
   | `/usr/local/libexec/estus-ingress` | `root:root`, `0755` | Install `estus-ingress` on the service host. It clears the environment, sets a fixed home, path and temporary directory, and starts Estus with a fixed configuration. It never interprets `SSH_ORIGINAL_COMMAND`. |
   | `/etc/estus` | `root:estus-service`, `0750` | Keep service configuration readable by the service and writable only by root. |
   | `/etc/estus/server.toml` | `root:estus-service`, `0640` | Install `server.toml`. It admits the logical target `target` and selects the fixed `record_identity` operation, not the generic `exec_*` tools. |
   | `/etc/estus/outbound_ssh_config` | `root:estus-service`, `0640` | Install `outbound_ssh_config`. Set `HostName` and `Port` in `Host estus-target` to the actual target. |
   | `/etc/estus/sshd_config` | `root:root`, `0644` | Put the supplied `sshd_config` fragment in the dedicated daemon's configuration. Configure the listener in step 5. |
   | `/etc/estus/ingress_authorized_keys` | `root:root`, `0644` | The dedicated daemon reads ingress keys here instead of from the service home. |
   | `/var/lib/estus-service` | `estus-service:estus-service`, `0700` | Persistent, private service home for the outbound key and `known_hosts`. |
   | `/run/estus-service` | `estus-service:estus-service`, `0700` | Private scratch directory; recreate it at boot before accepting connections, for example with `tmpfiles.d`. |
   | `/usr/local/libexec/estus-record-identity` on the target | `root:root`, `0755` | Install the `estus-record-identity` helper. It takes no arguments and writes and prints the remote UID. |
   | `/home/estus-target` on the target | `estus-target:estus-target`, `0700` | Private directory for the helper's `identity-evidence` file. |

   For `tmpfiles.d`, use this entry:

   ```text
   d /run/estus-service 0700 estus-service estus-service -
   ```

   The wrapper clears `XDG_RUNTIME_DIR`, so Estus keeps native SSH control sockets in service-owned `0700` directories under `/tmp/sm-*`, not in `TMPDIR`. Keep those directories and their sockets inaccessible to the client as well.

3. **Set up outbound SSH.** Generate a dedicated Ed25519 key as `estus-service` and keep it at `/var/lib/estus-service/outbound_key` with mode `0600`. Install only its public key in the target account's root-managed authorized keys. Pin the target's host key in `/var/lib/estus-service/known_hosts` using an authenticated source, not unverified `ssh-keyscan` output. Only Estus needs this credential; the target still enforces permissions on its SSH account independently of Estus.

4. **Set up a distinct ingress key.** Generate a different Ed25519 key as `estus-client` and keep it at mode `0600` in the client's private directory. Add its public key to `/etc/estus/ingress_authorized_keys` with `restrict` before `ssh-ed25519`. Pin the ingress daemon's host key on the client, again from an authenticated source. Give each client its own revocable ingress key. This key admits only the MCP session: never put it in the target's authorized keys or give the outbound key to a client.

5. **Enable the dedicated ingress daemon.** Use public-key-only authentication and restrict the listener to intended networks and the `estus-service` account. Keep the supplied `Match User estus-service` block, including `ForceCommand`, `DisableForwarding` and the restrictions on PTY, user rc and tunnels; keep `PermitUserEnvironment no` and the key's `restrict` option. `ForceCommand` by itself does not disable forwarding. Do not inherit any global `AcceptEnv` directives: accepted variables can reach the login shell before the wrapper clears them. Keep stdout reserved for MCP, with no login scripts or banners that write to the stream. Run `sshd -t -f /etc/estus/sshd_config` before starting or reloading the daemon. Together these settings expose the MCP pipe rather than a general SSH session.

## Connect the client

Configure this command as your client's [stdio server](clients.md). Replace the host and the two client-side paths with your own values. The key must be usable without an interactive prompt.

```sh
ssh -F /dev/null -T -i /private/client/ingress_key \
  -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=none \
  -o StrictHostKeyChecking=yes -o GlobalKnownHostsFile=/dev/null \
  -o UserKnownHostsFile=/private/client/pinned_ingress_hosts \
  estus-service@service.example.com
```

Initialize MCP, then call `record_identity` with `{"host":"target"}`. The caller can select neither the SSH alias nor the program, arguments or authority. Check that the returned UID matches the `estus-target` account and that the target has `/home/estus-target/identity-evidence` with the same UID. This exercise checks the route; it does not make the target account's ordinary OS privileges narrower. Review any tools you add against the [security boundary](security.md#out-of-scope).

## Disposable acceptance test

Build the `deployment-fixture-image` flake package for `aarch64-linux` or `x86_64-linux`. Its output contains `image.tar.gz`, `image-ref` and `image-id`. In `nix develop`, point `ESTUS_TEST_FIXTURE` at that output and set `DOCKER_HOST` to the explicit `unix:///…` endpoint of a dedicated Docker-compatible daemon you control. See [acceptance testing](development/acceptance.md) for fixture setup. You do not need host sudo.

```sh
cargo test --test deployment_boundary -- --ignored --nocapture
```

The separated-account test runs the client probes and actual SSH transport as UID `1200`, the packaged Estus process as UID `1201`, and the fixed operation as UID `1202`. It checks denial of direct access to service credentials and the control socket, denial of forwarding and PTYs, rejection of generic exec and caller-supplied overrides, and the target-side UID file. It checks process and socket cleanup after EOF. Only fixture root performs setup and independent observation. The suite also tests configuration replacement with a dedicated chrooted SFTP identity. The fixture harness verifies the image and removes both owned containers for each run, including fixture credentials and state.

This is evidence for the fixture's account and SSH authorization rules, not a production isolation claim or a qualification of container or OpenSSH sandboxing. The fixture omits OpenSSH's pre-authentication syscall sandbox because guest seccomp does not work under cross-CPU Docker emulation and the portable rlimit fallback is rejected there. It retains privilege separation, the real UID drops and the authorization checks. Do not carry that fixture exception into production.
