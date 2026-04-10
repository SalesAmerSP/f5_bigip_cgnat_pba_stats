# Security Policy

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, use GitHub's private vulnerability reporting for
this repository:

<https://github.com/SalesAmerSP/f5_bigip_cgnat_pba_stats/security/advisories/new>

You can also navigate to the repository's **Security** tab and click
**Report a vulnerability**.

### What to include

Please provide as much of the following as you can:

- A description of the issue and the impact (what an attacker could do)
- Steps to reproduce, or a proof-of-concept
- Affected tool (`cgnat_pba_stats.py`, `cgnat_pba_stats_bigip_compatible.py`,
  `cgnat_pba_collect.py`, or `install-pba-stats.sh`)
- BIG-IP TMOS version and Python version where the issue was observed
- Any mitigation or workaround you are aware of

### What to expect

This is a community project maintained by a single person in their
spare time. Responses are best-effort:

- Acknowledgement of receipt within a few business days
- An initial assessment as soon as practical
- A coordinated fix and disclosure once a patch is ready

There is no paid support or SLA. If you need commercial support for F5
BIG-IP CGNAT, contact F5 directly — this project is **not** a supported
F5 product.

## Supported Versions

Only the tip of the `main` branch is supported. Fixes are landed on
`main` (via `dev`) and are not backported to older commits or tags. Users
should run from a current clone of `main`.

## Scope

In scope:

- The scripts and installer in this repository
- Dependencies pinned in [python/requirements.txt](python/requirements.txt)
- The installer's on-device footprint (files written to `/shared/scripts/`,
  `/etc/profile.d/`, `/config/startup`)

Out of scope:

- Vulnerabilities in F5 BIG-IP itself (report those to F5)
- Issues that require an attacker who already has `admin` or `root` on
  the target BIG-IP
- Output from the tools when pointed at a misconfigured BIG-IP

## Supply-chain hygiene

This repository takes the following precautions against supply-chain
compromise:

- **Pinned dependencies with hashes.** [python/requirements.txt](python/requirements.txt)
  pins every direct and transitive Python dependency to a specific version
  and SHA-256 hash. Install with:

  ```bash
  pip install --require-hashes -r python/requirements.txt
  ```

  This blocks PyPI mirror tampering and typosquatting.

- **Automated dependency updates.** Dependabot watches the pinned
  dependencies and opens PRs when updates or security advisories are
  available. See [.github/dependabot.yml](.github/dependabot.yml).

- **Integrity-checked installer.** [python/install-pba-stats.sh](python/install-pba-stats.sh)
  verifies the file copied to a BIG-IP with SHA-256 before declaring the
  install successful.

- **No third-party dependencies on the BIG-IP.** The on-device script
  [python/cgnat_pba_stats_bigip_compatible.py](python/cgnat_pba_stats_bigip_compatible.py)
  uses only the Python 3.8 standard library, so there is no install-time
  dependency resolution on the target device.
