# Security policy

Use this policy to report a suspected vulnerability in Estus without making it public.

## Report privately

Open [GitHub Security Advisories for `aw1cks/estus`](https://github.com/aw1cks/estus/security/advisories) and select **Report a vulnerability**. Do not post vulnerability details in a public issue, pull request or discussion. If GitHub does not show the reporting button, ask the maintainers to enable private vulnerability reporting without including details of the issue.

Include the Estus release or commit, the relevant configuration with secrets removed, the steps to reproduce the issue, and the expected and observed security impact. Do not include private keys, credentials or live target data.

## Supported versions

Estus is pre-1.0. Security fixes target the latest release and `main` only; older releases do not receive backports.

## Scope and response

Report failures of the controls described in [what Estus enforces](docs/security.md#what-estus-enforces), such as an unauthorized tool dispatch or a misleading result after an uncertain write. The [out-of-scope list](docs/security.md#out-of-scope) explains which boundaries depend on your OS, SSH setup and operator code.

Maintainers triage reports on a best-effort basis, may ask for more information in the private advisory, and will coordinate disclosure there when appropriate. There is no guaranteed response or fix deadline.
