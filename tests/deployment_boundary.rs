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
                ("ssh_exec", json!({"host":"target","command":"touch /tmp/generic-bypass"})),
                ("ssh_run", json!({"host":"target","program":"/usr/bin/touch","argv":["/tmp/generic-bypass"]})),
                ("ssh_sudo", json!({"host":"target","user":"root","program":"/usr/bin/id","argv":["-u"]})),
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
