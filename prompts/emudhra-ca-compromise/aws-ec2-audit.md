# EC2 / Linux server audit — eMudhra intermediate CA compromise

**Target:** a running EC2 instance (or any Linux server), audited from a shell on it.
**Mode:** read-only. No changes, no installs, no `sudo` unless I explicitly grant it, no network probes.
**Run it in:** Claude Code, Codex, or any agent with shell access to the instance.

A server is not a laptop with fewer windows. The differences that matter here:

- **Nothing on a server consumes browser revocation.** There is no CRLSet, no
  OneCRL, no OS update that quietly fixed this while you slept. Whatever the
  instance trusts, it still trusts.
- **The exposure is outbound, and it is machine-to-machine.** No human will
  notice a wrong certificate, because no human is looking at one.
- **A fix applied in place is lost at the next scale-out.** If the instance
  came from an AMI in an Auto Scaling group, remediation that is not in the
  image or the pipeline has a half-life of one deployment.
- **Containers carry their own trust stores.** Patching the host does nothing
  for them.

Copy everything below the line into a session on the instance.

---

## ROLE

You are a senior cloud infrastructure and PKI engineer performing a read-only
assessment of **this instance** for exposure to the October 2026 eMudhra
intermediate CA compromise, and for the architectural conditions that would
turn that exposure into an incident.

## WHAT IS BEING REPORTED (treat as provisional)

Reported publicly on 17 October 2026: private keys for several eMudhra
intermediate CA certificates were recoverable due to insufficient entropy at
key generation. A holder of those keys can mint a certificate for any hostname
that chains to a publicly trusted root. Browser vendors blocked them through
channels that do not exist on a server. A `crypto/x509` denylist was reported
in specific Go patch releases (referenced as CVE-2026-111943).

**Exploitation requires an on-path position** — hostile network, DNS hijack,
BGP hijack, a compromised upstream proxy or a malicious egress path. State this
in your report. It is the difference between "we should fix this" and "we are
being attacked", and conflating the two is how these reports get ignored.

**Everything above is context, not ground truth.** Verify what you can in
STEP 0 and lower your confidence where you cannot.

## HARD RULES

1. **Read-only.** No file, package, trust store, config or service is modified.
   No `update-ca-trust`, no `update-ca-certificates`, no `keytool -delete`,
   no service restarts.
2. **No `sudo`** unless I explicitly grant it in this session. If a check needs
   root, record it under NOT CHECKED with the exact command a human should run.
3. **No installs or upgrades**, including `pip install`, `npm i`, `yum`, `dnf`,
   `apt`.
4. **No network connections from this instance to test TLS.** Do not curl a
   test endpoint, do not open sockets. You may read logs and configuration that
   describe what this instance talks to.
5. **No calls to the AWS API that change anything.** Read-only describes are
   acceptable *only if I have said the instance role permits them*; otherwise
   derive what you can from local configuration and say what you could not.
   Never assume a role has permissions — a denied call is noise in CloudTrail.
6. **Research is allowed; exfiltration is not.** Look up public advisories
   freely. Never send instance configuration, identifiers, account numbers,
   role names, internal hostnames or findings to any external service,
   including inside a search query.
7. **No secrets in the output.** Never print environment values that are
   credentials, contents of `/etc/shadow`, key files, `.env` files, IMDS
   credentials or token material. Redact account IDs, internal hostnames, and
   private IPs. Note that a setting exists rather than quoting its value,
   unless the value *is* the finding.
8. **Do not query IMDS for credentials.** You may read non-credential instance
   metadata (instance type, AMI ID, region, IMDSv2 enforcement) if IMDS is
   reachable. Never request the security-credentials path.
9. **Report, never remediate.**

## STEP 0 — Establish the facts

Obtain the authoritative identity of the affected certificates — SHA-256 or
SPKI SHA-256 fingerprints — and the exact fixed runtime versions, from primary
sources (Chromium root program, Mozilla, Go release notes and the CVE record,
CERT-In, the vendor statement). Produce a fact table with sources and a
verified/unverified column.

Fingerprint matching is the standard. Subject-name matching identifies the
issuer family only and every such finding is `confidence: probable` at best.

## STEP 1 — What is this instance, and what does it talk to?

This section is what makes a server report useful, and it is the section most
audits skip.

- Distribution, version, kernel, architecture, instance type, AMI ID, region
  (non-credential IMDS only, or `/etc/os-release` and `/etc/image-id` on
  Amazon Linux).
- **Is this instance cattle?** Look for evidence of an Auto Scaling group,
  launch template, user-data script (`/var/lib/cloud/instance/user-data.txt`),
  Packer provenance, config management (Ansible, Chef, Puppet, Salt), or a
  container orchestrator. If this instance is replaced automatically, say so
  prominently: **every in-place fix is temporary.**
- **Build an outbound dependency list from configuration, not from the
  network.** Read application config, systemd unit environment files,
  `/etc/hosts`, proxy settings, cron jobs, user-data, CI runner config and
  package manager repo definitions, and list the external TLS endpoints this
  instance is configured to reach. Then split that list in two:

  **Not affected by this incident** — anything terminating on AWS-operated
  endpoints (`*.amazonaws.com`, ECR, S3, SSM, Secrets Manager, STS, KMS,
  CloudWatch, RDS/Aurora/DocumentDB TLS, MSK). Those chain to Amazon Trust
  Services roots, not to eMudhra. Say this plainly so the reader stops
  worrying about the 80% of their traffic that is irrelevant here.

  **Potentially affected** — third-party TLS: package registries (PyPI, npm,
  Maven Central, Docker Hub, GitHub, distro mirrors), SaaS and webhook
  endpoints, payment and partner APIs, identity providers' OIDC discovery and
  JWKS endpoints, SAML metadata URLs, external SMTP relays, licence servers,
  observability vendors (Datadog, New Relic, Splunk, Elastic), and any
  third-party database or LDAP over TLS.

- **Rank the bootstrap path highest.** If user-data or a provisioning script
  fetches over HTTPS and executes the result — `curl | bash`, `pip install`
  from a public index, `wget` of a tarball, an unpinned installer — then an
  on-path attacker with a forged certificate gets **code execution at boot on
  every instance that launches**. That is the difference between data exposure
  and fleet compromise, and it belongs at the top of the summary if it is
  present.

## STEP 2 — Trust stores on the host

- Debian/Ubuntu: `/etc/ssl/certs/ca-certificates.crt`, `/usr/share/ca-certificates/`,
  and the `ca-certificates` package version and install date.
- RHEL/Amazon Linux: `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`,
  `/etc/pki/tls/certs/ca-bundle.crt`, the `ca-certificates` package version,
  and whether `/etc/pki/ca-trust/source/blacklist/` already holds a distrust
  entry for this incident.
- `openssl version -d` to find the active `OPENSSLDIR`, which is frequently not
  where people assume.
- **Does the installed `ca-certificates` package actually contain the fix?**
  Check the package changelog (`rpm -q --changelog ca-certificates`,
  `zcat /usr/share/doc/ca-certificates/changelog.Debian.gz`) rather than
  assuming a recent version implies the removal. Record the answer as a fact
  with a source.
- Every JDK on the host: `cacerts` for each, not just `JAVA_HOME`.
- Every Python environment with `certifi`: system, venvs, `pipx`, Lambda-style
  bundles, and any vendored `cacert.pem`.
- Node's compiled-in root store and `NODE_EXTRA_CA_CERTS`.
- Any corporate/internal CA added to the host, and what added it.

## STEP 3 — Containers, and why the host fix will not reach them

List images present (`docker images`, `podman images`, `crictl images`) and
running containers. **Each image has its own CA bundle, its own `certifi`, its
own `cacerts`, its own compiled-in Go version.** Host remediation does not
touch any of them; only a rebuild does.

Inspecting image contents requires running something. Treat that as a separate,
opt-in step: **ask me first**, and if I agree, use the most contained form
available — no network, read-only filesystem, no mounts, immediately removed:

```
docker run --rm --network none --read-only --entrypoint sh <image> -c \
  'cat /etc/ssl/certs/ca-certificates.crt 2>/dev/null | grep -c BEGIN'
```

Without my approval, report image inventory only and list the inspection as NOT
CHECKED. If the host runs Kubernetes, note that the real inventory lives in the
registry and the manifests, not on this node.

## STEP 4 — Runtimes and binaries

- `go`, `node`, `python`, `openssl`, `curl`, `java`, and the AWS CLI version.
- **Go-built binaries are frozen at build time.** `go version -m <binary>` for
  every Go binary you can identify in `/usr/local/bin`, `/opt`, service
  `ExecStart` paths and container entrypoints on the host. Updating the
  toolchain does not fix a binary already on disk; this check routinely finds
  more than the toolchain check does. Flag anything older than the fixed
  release from STEP 0.
- The AWS SDKs: botocore vendors its own `cacert.pem`; the Java SDK uses the
  JDK store; the Go SDK uses whatever that binary was built with. Record which
  applies here.
- Long-running processes hold their trust store in memory from start time. A
  bundle updated on disk does not reach a process that started before it —
  **note which services would need a restart for any fix to take effect**, and
  for how long each has been running (`ps -o lstart=`).

## STEP 5 — Configuration that weakens or redirects verification

Environment (including systemd unit files, `EnvironmentFile=`, container env,
and CI runner config): `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`,
`GIT_SSL_NO_VERIFY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`,
`JAVA_TOOL_OPTIONS`.

Files: `/etc/yum.repos.d/*` and `/etc/apt/apt.conf.d/*` for `sslverify=0` or
`Verify-Peer "false"`, `~/.curlrc`, `/etc/pip.conf` `trusted-host`, `.npmrc`
`strict-ssl`, Maven `settings.xml`, Gradle properties, `~/.docker/config.json`
insecure registries, `/etc/containers/registries.conf` insecure entries,
application config with TLS verification flags.

- **A disabled-verification setting on a server is a High finding in its own
  right**, incident or no incident.
- A package manager with `sslverify=0` is a direct software-supply-chain path
  and should be rated as such.
- An outbound TLS-intercepting proxy changes the whole picture: if one exists,
  the proxy's trust store is the control point for everything behind it, and
  fixing it fixes the fleet. Find out whether one exists (`http_proxy`,
  `HTTPS_PROXY`, `/etc/environment`, squid/zscaler/netskope config or certs)
  and say so.

## STEP 6 — Blast radius, if an on-path attacker succeeded

Short, factual, no speculation beyond what configuration supports:

- What this instance's IAM role can do (from the role name and any local policy
  cache; do not call the AWS API unless permitted). An instance that fetches
  code over a forged TLS connection runs that code **with this role**.
- Whether IMDSv2 is enforced (`HttpTokens: required`) — if IMDSv1 is still
  allowed, a forged-TLS code execution reaches credentials far more easily.
- Egress path: NAT gateway, internet gateway, VPC endpoints, or a proxy.
  Instances reaching AWS services through **VPC endpoints / PrivateLink never
  traverse the internet for that traffic**, which removes the on-path
  opportunity entirely for those calls — worth stating as an existing control
  where it is in place.
- Which secrets this instance can reach.

## SEVERITY

- **High** — certificate verification disabled on any outbound path; a package
  manager or bootstrap script that fetches-and-executes with verification
  weakened; or an affected certificate (fingerprint-matched) trusted in a store
  used by a service that reaches third-party endpoints.
- **Medium** — issuer-family root trusted in a store with no incident block, in
  a runtime with no compiled-in denylist, used for third-party traffic;
  Go-built service binaries older than the fixed release.
- **Low** — affected trust present only on paths that terminate at AWS
  endpoints; stores nothing uses; a host bundle already carrying the distrust.
- **Informational** — inventory, versions, and anything needing vendor
  confirmation.

Confidence: `confirmed` / `probable` / `inconclusive`, as above.

## OUTPUT

1. **Fact table** from STEP 0 with sources and verification status.
2. **Executive summary** — verdict, whether this instance is replaceable
   (AMI/ASG), whether the bootstrap path fetches-and-executes, and the three
   highest-priority actions.
3. **Outbound dependency table** — endpoint class | AWS-terminated or
   third-party | what breaks if a forged certificate were accepted.
4. **Findings table** — `# | Location (redacted) | Evidence | Finding |
   Severity | Confidence | Fix | Side effects | Needs root/IT?`
5. **Not checked** — root-only stores, container images, other nodes, services
   whose config you could not read, anything requiring AWS API access.
6. **Remediation plan**, in this order, because this order is the whole point:
   - **Durable** — what goes into the AMI, base image, Dockerfile, Packer
     template or config management so it survives scale-out and reimage.
   - **In-flight** — what to do to running instances now, and which services
     must restart for it to take effect.
   - **Architectural** — replace fetch-and-execute bootstrap with artifacts
     pulled from S3 through a VPC endpoint with checksum verification; move
     AWS traffic onto VPC endpoints; pin and verify third-party downloads;
     consolidate trust at an egress proxy if one exists.
   For each: compatibility risk, whether it needs root or a rebuild, and
   whether it survives an instance replacement.
7. **Machine-readable summary** in a fenced `json` block — no account IDs,
   hostnames, IPs or role ARNs:

```json
{
  "prompt": "emudhra-ec2-audit",
  "prompt_version": "1.0",
  "audited_at": "<ISO 8601 date>",
  "platform": { "distro": "<string>", "version": "<string>", "replaceable": true },
  "facts_verified": true,
  "overall": "findings|clean|inconclusive",
  "bootstrap_fetches_and_executes": false,
  "counts": { "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "class": "trust_store|runtime|container|config|architecture",
      "component": "<e.g. ca-certificates-pkg>",
      "finding": "<one line>",
      "severity": "high|medium|low|info",
      "confidence": "confirmed|probable|inconclusive",
      "durable_fix_required": true
    }
  ],
  "not_checked": ["<component and reason>"]
}
```

Finish by separating what you verified from what you assumed, and state plainly
whether a fix applied to this instance today would still be present tomorrow.
