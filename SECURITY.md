# Security policy

TailState holds Tailscale OAuth credentials, notification destination
secrets, and a signing key for its evidence ledger, so security reports are
welcome and handled with priority. How TailState protects those secrets,
administrator access, and its read-only API is described in
[docs/security.md](docs/security.md).

## Supported versions

Only the latest release receives security fixes. Upgrade to the newest
`ghcr.io/crypt0rr/tailstate` version before reporting, and include the
version shown in the web interface or by `tailstate version`.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on
<https://github.com/crypt0rr/TailState/security/advisories/new>.

Do not open a public issue, pull request, or discussion for an unfixed
vulnerability. Include:

- the affected version and deployment mode (Compose, HTTPS override, or
  standalone binary);
- steps to reproduce, or a proof of concept;
- the impact you expect (for example credential disclosure, authentication
  bypass, or tampering with signed evidence).

Never include real Tailscale credentials, master keys, destination URLs, or
database files. `tailstate doctor -json` output is safe to share; it never
contains secrets.

## What to expect

- Acknowledgement within 3 working days.
- An initial assessment within 7 working days.
- A fix, or a mitigation and timeline, for confirmed issues, released as a
  new version with a GitHub security advisory crediting the reporter unless
  you prefer otherwise.

## Scope

In scope: the TailState binary and container image, the web interface,
the webhook receiver, evidence signing and verification, the backup and
restore helpers, and the Compose files in this repository.

Out of scope: vulnerabilities in Tailscale itself, in notification providers,
or in third-party images used only as examples. TailState never writes to a
tailnet; a report that requires TailState to modify a tailnet is a design
change rather than a vulnerability.
