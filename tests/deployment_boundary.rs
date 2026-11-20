//! Real separated Linux UIDs, not a claim that the disposable container is a sandbox.
//! Requires the deployment-fixture-image artifact, explicit DOCKER_HOST and nix develop.
#[allow(dead_code)]
#[path = "support/isolated.rs"]
mod isolated;
#[allow(dead_code, unused_imports)]
mod support;

use anyhow::{Context, Result, ensure};
use serde_json::json;
use tokio::time::{Duration, timeout};

const SSH: &str = "ssh -F /home/estus-client/ssh_config";

async fn denied_os(fixture: &isolated::Fixture, command: &str) -> Result<()> {
    let result = fixture.deployment_client_exec(command).await?;
    ensure!(
        !result.status.success() && result.stdout.is_empty(),
        "client OS operation unexpectedly succeeded: {command}; stdout={}",
        String::from_utf8_lossy(&result.stdout)
    );
    ensure!(
        String::from_utf8_lossy(&result.stderr)
            .to_ascii_lowercase()
            .contains("permission denied"),
        "operation did not fail at the OS permission boundary: {command}; stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Linux deployment-fixture-image and explicit Docker-compatible daemon"]
async fn separated_accounts_force_real_service_mcp_and_reap_owned_resources() -> Result<()> {
    let fixture = isolated::Fixture::start(isolated::ImageKind::Deployment).await?;
    let scenario = async {
        fixture.prepare_deployment().await?;
        let client_uid = fixture.deployment_client_exec("id -u").await?;
        ensure!(client_uid.status.success() && client_uid.stdout == b"1200\n");

        // These are actual read/write/identity-transition attempts, not mode-bit assertions.
        for path in [
            "/var/lib/estus-service/outbound_key",
            "/var/lib/estus-service/known_hosts",
            "/etc/estus/server.toml",
            "/etc/estus/outbound_ssh_config",
            "/fixture/host_key",
        ] {
            denied_os(&fixture, &format!("cat {}", support::quote(path))).await?;
        }
        for path in [
            "/etc/estus/server.toml",
            "/etc/estus/ingress_authorized_keys",
            "/usr/local/libexec/estus-ingress",
            "/var/lib/estus-service/outbound_key",
        ] {
            denied_os(&fixture, &format!("printf bypass >> {}", support::quote(path))).await?;
        }
        let sudo = fixture.deployment_client_exec(
            "/usr/bin/sudo -n -k -u estus-service -- /usr/bin/id -u",
        ).await?;
        ensure!(!sudo.status.success() && sudo.stdout.is_empty(), "client acquired service execution");
        let sudo_policy = fixture.deployment_client_exec("/usr/bin/sudo -n -l").await?;
        ensure!(!sudo_policy.status.success(), "client unexpectedly has sudo policy");

        // The ingress credential must not authenticate the independent target account.
        let target_auth = fixture.deployment_client_exec(&format!(
            "{SSH} -T -l estus-target ingress /usr/bin/id -u",
        )).await?;
        ensure!(target_auth.status.code() == Some(255));
        ensure!(String::from_utf8_lossy(&target_auth.stderr).contains("Permission denied (publickey)"));
        let forwarding = fixture.deployment_client_exec(&format!(
            "{SSH} -W 127.0.0.1:2222 ingress",
        )).await?;
        ensure!(forwarding.status.code() == Some(255));
        ensure!(String::from_utf8_lossy(&forwarding.stderr).contains("administratively prohibited"));
        let pty = fixture.deployment_client_exec(&format!(
            "{SSH} -tt ingress </dev/null",
        )).await?;
        ensure!(String::from_utf8_lossy(&pty.stderr).contains("PTY allocation request failed"));

        // Even a service-owned user rc cannot run on the forced ingress.
        fixture.primary_exec(indoc::indoc! {r#"
            mkdir -p /var/lib/estus-service/.ssh
            printf '%s\n' '#!/bin/sh' 'touch /tmp/user-rc-bypass' > /var/lib/estus-service/.ssh/rc
            chown -R 1201:1201 /var/lib/estus-service/.ssh
            chmod 0700 /var/lib/estus-service/.ssh /var/lib/estus-service/.ssh/rc
            test ! -e /home/estus-target/identity-evidence
        "#}).await?;

        // Independently establish that the service-owned key authenticates the
        // target account before attributing a later failure to MCP policy.
        let target_control = fixture.primary_exec(
            "chroot --userspec=1201:1201 / /usr/bin/ssh -F /etc/estus/outbound_ssh_config estus-target /usr/bin/id -u",
        ).await?;
        ensure!(target_control == b"1202\n", "service SSH authority resolved another target");

        // SSH_ORIGINAL_COMMAND is deliberately hostile. Successful MCP initialize
        // and fixed remote work prove sshd ran the real forced estus, not this command.
        let transport = fixture.deployment_client_command(&[
            "ssh", "-F", "/home/estus-client/ssh_config", "-T", "ingress",
            "/usr/bin/touch /tmp/forced-command-bypass",
        ])?;
        let client = support::Client::start_command(transport).await?;
        let work = async {
            let service = String::from_utf8(fixture.primary_exec(indoc::indoc! {r#"
                for process in /proc/[0-9]*; do
                    # Kernel credentials are authoritative; emulator launchers may
                    # prefix argv and non-dumpable proc directories can be root-owned.
                    set -- $(sed -n 's/^Uid:[[:space:]]*//p' "$process/status") || continue
                    test "$#" -eq 4 && test "$1" = 1201 && test "$2" = 1201 \
                        && test "$3" = 1201 && test "$4" = 1201 || continue
                    uid=$1
                    previous=
                    last=
                    for argument in $(tr '\000' ' ' < "$process/cmdline"); do
                        previous=$last
                        last=$argument
                    done
                    test "$previous" = --config && test "$last" = /etc/estus/server.toml || continue
                    printf '%s %s\n' "${process##*/}" "$uid"
                done
            "#}).await?)?;
            let mut service_fields = service.split_ascii_whitespace();
            let pid: u32 = service_fields.next().context("real estus service process")?.parse()?;
            ensure!(service_fields.next() == Some("1201") && service_fields.next().is_none(),
                "expected exactly one real service-UID estus process: {service}");
            let process_denied = fixture.deployment_client_exec(&format!("kill -0 {pid}")).await?;
            ensure!(!process_denied.status.success(), "client may signal service process");
            ensure!(String::from_utf8_lossy(&process_denied.stderr).contains("Operation not permitted"));

            for (name, arguments) in [
                ("exec_command", json!({"host":"target","command":"touch /tmp/generic-bypass"})),
                ("exec_argv", json!({"host":"target","program":"/usr/bin/touch","argv":["/tmp/generic-bypass"]})),
                ("exec_sudo", json!({"host":"target","user":"root","program":"/usr/bin/id","argv":["-u"]})),
            ] {
                let denied = timeout(Duration::from_secs(10), client.service.call_tool(
                    support::params(name, arguments),
                )).await?;
                ensure!(denied.is_err(), "generic work was accepted: {name}");
            }
            for (field, value) in [
                ("command", json!("touch /tmp/argument-bypass")),
                ("program", json!("/usr/bin/touch")),
                ("argv", json!(["/tmp/argument-bypass"])),
                ("authority", json!({"sudo":"root"})),
                ("ssh_host", json!("127.0.0.1")),
                ("user", json!("root")),
            ] {
                let mut arguments = json!({"host":"target"});
                arguments[field] = value;
                let denied = timeout(Duration::from_secs(10), client.service.call_tool(
                    support::params("record_identity", arguments),
                )).await?;
                ensure!(denied.is_err(), "fixed binding accepted arbitrary {field}");
            }
            fixture.primary_exec("test ! -e /home/estus-target/identity-evidence").await?;
            let result = client.call("record_identity", json!({"host":"target"})).await?;
            ensure!(result["error"].is_null() && result["data"]["exit_code"] == 0
                && result["data"]["stdout"] == "1202\n", "fixed target work failed: {result}");

            // Root observes the target filesystem independently of MCP's response.
            let evidence = fixture.primary_exec(indoc::indoc! {r#"
                test "$(stat -c %u /home/estus-target/identity-evidence)" = 1202
                test "$(cat /home/estus-target/identity-evidence)" = 1202
                test ! -e /tmp/forced-command-bypass
                test ! -e /tmp/user-rc-bypass
                test ! -e /tmp/generic-bypass
                test ! -e /tmp/argument-bypass
                for socket in /tmp/sm-*/c; do
                    test -S "$socket" || continue
                    test "$(stat -c %u "$socket")" = 1201
                    test "$(stat -c %a "${socket%/c}")" = 700
                    printf '%s\n' "$socket"
                done
            "#}).await.context("independent target evidence")?;
            let sockets = String::from_utf8(evidence)?;
            let socket = sockets.lines().next().context("real service-owned control socket")?;
            ensure!(sockets.lines().count() == 1, "unexpected extra service control sockets");
            denied_os(&fixture, &format!("cat {}", support::quote(socket))).await?;
            let control = fixture.deployment_client_exec(&format!(
                "ssh -F /dev/null -S {} -O check estus-target", support::quote(socket),
            )).await?;
            ensure!(!control.status.success());
            ensure!(String::from_utf8_lossy(&control.stderr).contains("Permission denied"));
            Ok::<_, anyhow::Error>((pid, socket.to_owned()))
        }.await;
        // Await MCP EOF shutdown even when an assertion failed; the fixture owner
        // then removes containers on every error path, without host PID signalling.
        let closed = client.stop().await;
        let (pid, socket) = work?;
        closed?;
        fixture.primary_exec(&format!(
            "test ! -e /proc/{pid}; test ! -e {}; test ! -e {}; \
             test ! -e /tmp/forced-command-bypass; test ! -e /tmp/user-rc-bypass; \
             test ! -e /tmp/generic-bypass; test ! -e /tmp/argument-bypass",
            support::quote(&socket), support::quote(socket.trim_end_matches("/c")),
        )).await.context("service EOF cleanup")?;
        Ok::<_, anyhow::Error>(())
    }.await;
    // Existing verified-image owner removes BOTH named containers and checks absence.
    // This also removes fixture keys, service/target processes and all private state.
    let removed = fixture.stop().await;
    scenario?;
    removed?;
    Ok(())
}

/// File-profile qualification is scoped to this explicit OS-restricted identity.
/// Catalog tools are not applicable: these are native file routes, not
/// catalog definitions or imported automation contracts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real Linux deployment-fixture-image and explicit Docker-compatible daemon"]
async fn configuration_replacement_workflow() -> Result<()> {
    use sha2::{Digest, Sha256};

    let fixture = isolated::Fixture::start(isolated::ImageKind::Deployment).await?;
    let scenario = async {
        fixture.prepare_restricted_files(include_str!(
            "../examples/workflows/config-replacement.toml"
        )).await?;
        let old_digest = hex::encode(Sha256::digest(b"version=old\n"));
        let new_content = "version=reviewed\n";
        let new_digest = hex::encode(Sha256::digest(new_content.as_bytes()));

        // Independent direct SSH/SFTP operations use the SAME service credential,
        // bypassing MCP policy. A poisoned writable directory cannot become a
        // login home, authorized_keys, user rc, or service credential directory.
        let boundary = fixture.primary_exec(indoc::indoc! {r#"
            test "$(stat -c %u:%a /srv/estus-files)" = 0:755
            test "$(stat -c %u:%a /srv/estus-files/config)" = 1202:700
            test "$(stat -c %u /fixture/authorized_keys/estus-target)" = 0
            test "$(stat -c %u /fixture/sshd_config)" = 0
            if chroot --userspec=1201:1201 / /usr/bin/ssh \
                -F /etc/estus/replacement_ssh_config -T replacement \
                'touch /tmp/replacement-shell-escape' </dev/null \
                > /tmp/replacement-exec-result 2>&1; then
                echo 'forced SFTP unexpectedly executed a command' >&2
                exit 1
            fi
            cat /tmp/replacement-exec-result
            test ! -e /tmp/replacement-shell-escape
            sftp=$(dirname "$(readlink -f /usr/bin/ssh)")/sftp
            for path in /etc/estus/server.toml /../../etc/shadow /.ssh/authorized_keys; do
                printf 'get %s /var/lib/estus-service/escaped\n' "$path" \
                    > /var/lib/estus-service/boundary.batch
                chown 1201:1201 /var/lib/estus-service/boundary.batch
                if chroot --userspec=1201:1201 / "$sftp" \
                    -F /etc/estus/replacement_ssh_config \
                    -b /var/lib/estus-service/boundary.batch replacement \
                    > /tmp/replacement-sftp-result 2>&1; then
                    echo "SFTP escaped jail: $path" >&2
                    exit 1
                fi
                test ! -e /var/lib/estus-service/escaped
                cat /tmp/replacement-sftp-result
            done
        "#}).await?;
        let boundary = String::from_utf8(boundary)?;
        ensure!(boundary.contains("This service allows sftp connections only."),
            "arbitrary command was not refused by forced internal-sftp: {boundary}");
        ensure!(boundary.lines().filter(|line| {
            let line = line.to_ascii_lowercase();
            line.contains("no such file") || line.contains("not found")
        }).count() >= 3,
            "outside-boundary SFTP probes did not reach the real server: {boundary}");

        // The consumed recipe must reject rather than widen: it names no
        // execution capability, and a missing tool is not silently granted.
        let inspected = fixture.primary_exec(
            "chroot --userspec=1201:1201 / /opt/estus/bin/estus catalog \
             --root /opt/estus/share/estus/catalog list --json",
        ).await?;
        let inspection: serde_json::Value = serde_json::from_slice(&inspected)?;
        ensure!(
            inspection["tools"].as_array().is_some_and(|tools| !tools.is_empty()),
            "offline listing lost the installed catalog: {inspection}"
        );

        // Actionable setup failure: an explicitly missing site file is diagnosed,
        // not silently replaced by defaults or an ambient configuration.
        let diagnostic = fixture.primary_exec(indoc::indoc! {r#"
            if chroot --userspec=1201:1201 / /opt/estus/bin/estus \
                --config /etc/estus/not-provisioned.toml </dev/null \
                > /tmp/replacement-bad-stdout 2> /tmp/replacement-bad-stderr; then
                echo 'missing configuration unexpectedly started' >&2
                exit 1
            fi
            test ! -s /tmp/replacement-bad-stdout
            cat /tmp/replacement-bad-stderr
        "#}).await?;
        let diagnostic = String::from_utf8(diagnostic)?;
        ensure!(diagnostic.contains("config") && diagnostic.contains("cannot read explicitly selected TOML file"),
            "missing private site lacks actionable diagnostic: {diagnostic}");
        denied_os(&fixture, "cat /var/lib/estus-service/outbound_key").await?;
        denied_os(&fixture, "printf bypass >> /etc/estus/server.toml").await?;

        let client = support::Client::start_command(fixture.deployment_client_command(&[
            "ssh", "-F", "/home/estus-client/ssh_config", "-T", "ingress",
        ])?).await?;
        let work = async {
            let listed = timeout(Duration::from_secs(10), client.service.list_tools(None)).await??;
            let names: std::collections::BTreeSet<_> =
                listed.tools.iter().map(|tool| tool.name.as_ref()).collect();
            ensure!(names.contains("change_file_replace") && names.contains("inspect_file")
                && names.contains("observe_targets") && !names.contains("exec_command")
                && !names.contains("exec_argv") && !names.contains("exec_sudo"),
                "file profile exposed unexpected command authority: {names:?}");
            let targets = client.call("observe_targets", json!({})).await?;
            ensure!(targets["error"].is_null()
                && targets["data"]["mode"] == "configured"
                && targets["data"]["targets"].as_array().is_some_and(|rows|
                    rows.len() == 1 && rows[0]["name"] == "configuration"),
                "discovery did not restrict authority to the reviewed target: {targets}");
            for (name, arguments) in [
                ("exec_command", json!({"host":"configuration","command":"touch /tmp/replacement-generic"})),
                ("exec_argv", json!({"host":"configuration","argv":["/usr/bin/touch","/tmp/replacement-generic"]})),
            ] {
                ensure!(timeout(Duration::from_secs(10),
                    client.service.call_tool(support::params(name, arguments))).await?.is_err(),
                    "generic shell escape published: {name}");
            }
            let foreign = client.call("change_file_replace", json!({
                "host":"foreign","path":"/config/service.conf","content":"NEVER","overwrite":true,
            })).await?;
            ensure!(foreign["error"]["code"] == "policy_denied", "foreign target accepted: {foreign}");
            for path in ["/.ssh/rc", "/.ssh/authorized_keys", "/etc/estus/server.toml"] {
                let denied = client.call("change_file_replace", json!({
                    "host":"configuration","path":path,"content":"NEVER","overwrite":true,
                })).await?;
                ensure!(denied["error"].is_object(), "writable authority escaped /config: {denied}");
            }
            let read = client.call("inspect_file", json!({
                "host":"configuration","path":"/config/service.conf",
                "expected_content_sha256":old_digest,
            })).await?;
            ensure!(read["error"].is_null() && read["data"]["content"] == "version=old\n"
                && read["data"]["content_sha256"] == old_digest, "reviewed read failed: {read}");
            let mismatch = client.call("inspect_file", json!({
                "host":"configuration","path":"/config/service.conf",
                "expected_content_sha256":"00".repeat(32),
            })).await?;
            ensure!(mismatch["error"]["code"] == "checksum_mismatch" && mismatch["data"].is_null(),
                "expected-digest mismatch disclosed content: {mismatch}");

            // An ordinary root-side reader observes only complete old/new files.
            // Readiness is explicit; cleanup always signals and joins the reader.
            let observer = fixture.primary_exec(indoc::indoc! {r#"
                test "$(cat /srv/estus-files/config/service.conf)" = version=old
                touch /tmp/replacement-reader-ready
                while test ! -e /tmp/replacement-reader-done; do
                    value=$(cat /srv/estus-files/config/service.conf)
                    case "$value" in version=old|version=reviewed) ;; *) exit 1 ;; esac
                done
                test "$(cat /srv/estus-files/config/service.conf)" = version=reviewed
            "#});
            let operation = async {
                let replaced = async {
                    fixture.primary_exec(
                        "while test ! -e /tmp/replacement-reader-ready; do sleep 0.01; done",
                    ).await?;
                    let replaced = client.call("change_file_replace", json!({
                        "host":"configuration","path":"/config/service.conf",
                        "content":new_content,"overwrite":true,
                    })).await?;
                    ensure!(replaced["error"].is_null()
                        && replaced["data"]["bytes_written"] == new_content.len(),
                        "atomic replacement failed: {replaced}");
                    Ok::<_, anyhow::Error>(())
                }.await;
                let signalled = fixture.primary_exec("touch /tmp/replacement-reader-done").await;
                replaced?;
                signalled?;
                Ok::<_, anyhow::Error>(())
            };
            let (observed, replaced) = tokio::join!(observer, operation);
            observed?;
            replaced?;
            let oracle = fixture.primary_exec(indoc::indoc! {r#"
                path=/srv/estus-files/config/service.conf
                old=/srv/estus-files/config/old-config
                test "$(cat "$path")" = version=reviewed
                test "$(cat "$old")" = version=old
                test "$(stat -c %i "$path")" != "$(stat -c %i "$old")"
                test "$(stat -c %u:%g:%a "$path")" = 1202:1202:600
                test "$(stat -c %a "$old")" = 644
                set -- /srv/estus-files/config/.estus-replace-*
                test ! -e "$1"
                test ! -e /tmp/replacement-shell-escape
                test ! -e /tmp/replacement-generic
                sha256sum "$path"
            "#}).await?;
            ensure!(String::from_utf8(oracle)?.starts_with(&new_digest), "independent SHA256 differs");
            let readback = client.call("inspect_file", json!({
                "host":"configuration","path":"/config/service.conf",
                "expected_content_sha256":new_digest,
            })).await?;
            ensure!(readback["error"].is_null() && readback["data"]["content"] == new_content,
                "agent-visible replacement readback failed: {readback}");
            Ok::<_, anyhow::Error>(())
        }.await;
        let stopped = client.stop().await;
        work?;
        stopped?;

        // Acknowledged real server rejection, NOT interruption or a lost ACK.
        // Conservative uncertainty must survive; post-rename pathname cleanup
        // is forbidden, so independently retain the one private orphan as evidence.
        fixture.primary_exec(indoc::indoc! {r#"
            mkdir /srv/estus-files/config/blocked.conf
            printf 'preserved\n' > /srv/estus-files/config/blocked.conf/evidence
            chown -R 1202:1202 /srv/estus-files/config/blocked.conf
        "#}).await?;
        let client = support::Client::start_command(fixture.deployment_client_command(&[
            "ssh", "-F", "/home/estus-client/ssh_config", "-T", "ingress",
        ])?).await?;
        let rejected = async {
            let reply = client.call("change_file_replace", json!({
                "host":"configuration","path":"/config/blocked.conf",
                "content":"version=rejected\n","overwrite":true,
            })).await?;
            ensure!(reply["data"].is_null() && reply["error"].is_object()
                && reply["error"]["remote_state_unknown"] == true,
                "failed mutation suppressed conservative uncertainty: {reply}");
            let oracle = fixture.primary_exec(indoc::indoc! {r#"
                test "$(cat /srv/estus-files/config/service.conf)" = version=reviewed
                test "$(stat -c %u:%g:%a /srv/estus-files/config/service.conf)" = 1202:1202:600
                test -d /srv/estus-files/config/blocked.conf
                test "$(cat /srv/estus-files/config/blocked.conf/evidence)" = preserved
                set -- /srv/estus-files/config/.estus-replace-*
                test "$#" = 1
                test -f "$1"
                test "$(stat -c %u:%g:%a "$1")" = 1202:1202:600
                test "$(cat "$1")" = version=rejected
                sha256sum /srv/estus-files/config/service.conf
            "#}).await?;
            ensure!(String::from_utf8(oracle)?.starts_with(&new_digest),
                "rejected rename changed destination or replayed publication");
            Ok::<_, anyhow::Error>(())
        }.await;
        let stopped = client.stop().await;
        rejected?;
        stopped?;
        Ok::<_, anyhow::Error>(())
    }.await;
    let removed = fixture.stop().await;
    scenario?;
    removed?;
    Ok(())
}
