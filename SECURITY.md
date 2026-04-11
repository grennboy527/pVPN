# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in pVPN — especially anything affecting
authentication, tunnel integrity, cryptographic code, the kill switch, DNS
leak prevention, or the daemon's IPC surface — please report it privately
rather than opening a public issue.

Email: **paul.goessmann@proton.me**

Please include:

- A description of the issue and its impact
- Steps to reproduce (or a proof of concept)
- The pVPN version (`pvpnctl --version`) and your distro
- Whether the issue is already public

You will get an acknowledgement within a few days. Once the issue is
understood and a fix is available, a coordinated disclosure timeline will be
agreed on before any public advisory.

## Supported Versions

Only the latest released version receives security fixes. pVPN is
pre-1.0 and moves quickly — please upgrade before reporting.
