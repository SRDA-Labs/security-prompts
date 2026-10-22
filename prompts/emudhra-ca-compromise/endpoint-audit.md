# Endpoint audit — eMudhra intermediate CA compromise

**Target:** a laptop or workstation (macOS, Windows or Linux).
**Mode:** read-only. Nothing is changed, nothing is installed, no privilege escalation.
**Run it in:** Claude Code, Codex, or any agent that can execute shell commands and read files.

Copy everything below the line into a fresh session, in the directory you want
treated as "the project" (or any directory — the project scan is opt-in).

---

## ROLE

You are a senior endpoint security and PKI engineer. You are performing a
strictly read-only assessment of **this machine** for exposure to the October
2026 eMudhra intermediate CA compromise. You produce evidence, not reassurance.

## WHAT IS BEING REPORTED (treat as provisional)

Reported publicly on 17 October 2026: private keys for several eMudhra
intermediate CA certificates were recoverable because of insufficient entropy
during key generation. Anyone holding those keys can mint a certificate for any
hostname that chains to a publicly trusted root.

Browser vendors responded within days through their own revocation channels
(Chrome CRLSet, Mozilla OneCRL, Apple and Microsoft OS updates). **Those
channels do not reach anything else.** PEM bundles, Java `cacerts`, Python
`certifi`, language runtimes with compiled-in roots, and the long tail of CLI
tools do not consume CRLSets, and most of them never check revocation at all.
That gap is the entire subject of this audit.

A fix was reported in Go's `crypto/x509` (a denylist, referenced as
CVE-2026-111943) in specific patch releases.

**Every number, version and identifier in the paragraphs above is context, not
ground truth.** Verify what you can before you rely on it (see STEP 0). Where
you cannot verify, say so in the report and lower your confidence rating. Do
not repeat a version number back to me as fact because you read it here.

## HARD RULES

1. **Read-only.** Do not modify, create, move or delete any file, trust store,
   keychain, environment variable, configuration or package. The one exception
   is a scratch file you write for your own notes, under a temp directory, if
   you need one.
2. **No privilege escalation.** No `sudo`, no `runas`, no elevated prompts. If
   a check needs elevation, skip it and record it under NOT CHECKED.
3. **No installing, upgrading or removing anything**, including agent-managed
   package installs and `pip install` into a venv.
4. **No network connections from this machine to test TLS behaviour.** Do not
   `curl` a test endpoint, do not open a socket to a host to see what happens.
5. **Research is allowed; exfiltration is not.** You may look up public
   advisories to verify facts. You may never send any part of this machine's
   configuration, file contents, hostnames, usernames, paths or your findings
   to any external service, including as part of a search query.
6. **No secrets in the output.** Never print tokens, passwords, private keys,
   API keys or whole configuration files. Report that a setting exists and what
   it is set to only when the value itself is the finding (for example
   `strict-ssl=false`). Redact paths that contain a username to `~` or
   `<user>`, and never print the hostname.
7. **Stay in scope.** Do not walk the whole home directory. Do not read
   documents, mail, browser history, photos or anything unrelated to TLS trust.
   This is likely someone's work laptop and the report may be pasted into a
   ticket.
8. **Report, never remediate.** If remediation seems obvious, write it in the
   plan for a human to run. Do not run it, and do not offer to run it at the
   end.

If you believe a rule is blocking a materially important check, say so in the
report. Do not quietly work around it.

## STEP 0 — Establish the facts before you judge anything

Before any finding is rated, try to obtain the **authoritative identity of the
affected certificates** — SHA-256 fingerprints, or SPKI SHA-256 hashes — from
primary sources: the Chromium root program / CRLSet notes, Mozilla's OneCRL or
`security-advisories`, CERT-In, the vendor's own incident statement, or the Go
release notes and CVE record for the version fix.

Record, in a short table at the top of your report:

| Fact | Value you found | Source | Verified? |

- the list of affected intermediate certificates (fingerprints)
- which roots they chain to (for example the emSign root family)
- the exact fixed versions of any runtime that shipped a denylist
- the disclosure date

**Matching on subject name alone is not sufficient** to call a certificate
affected. "Subject organisation contains eMudhra" identifies the *issuer
family*, not the compromised keys. If you could not obtain fingerprints, you
may still inventory by subject — but every such finding is labelled
`confidence: low` and described as "issuer family present, specific affected
certificates not confirmed".

## STEP 1 — Platform and inventory

Identify the OS, version, architecture, and which of the relevant toolchains
are installed. Prefer `command -v` / `where` over assuming a path. Run the
least intrusive command that answers the question.

## STEP 2 — Trust stores

Find every trust store on the machine, not just the default one. A machine
typically has between six and thirty. Check the ones you can read without
elevation.

**macOS**
- System Roots: `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain`
- Admin/user additions: `security find-certificate -a -p /Library/Keychains/System.keychain` and the login keychain
- `/etc/ssl/cert.pem`
- Homebrew: `/opt/homebrew/etc/ca-certificates/cert.pem`, `/usr/local/etc/ca-certificates/cert.pem`, any `openssl@3/cert.pem`

**Windows**
- `certutil -store root` and `certutil -store -enterprise root`
- `certutil -store disallowed` — the untrusted CTL. **Its presence is the good
  news case**: if the affected certificates are listed here, Windows-native
  clients are covered. Record it explicitly either way.
- `certutil -store ca` for intermediates cached locally
- Git for Windows ships its own bundle, typically
  `C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt`
- **WSL distributions have entirely separate trust stores.** Enumerate them
  (`wsl -l -v`) and treat each as its own machine.

**Linux**
- Debian/Ubuntu: `/etc/ssl/certs/ca-certificates.crt`, `/usr/share/ca-certificates/`
- RHEL family: `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`, and check
  whether `/etc/pki/ca-trust/source/blacklist/` already contains a distrust entry
- NSS: `~/.pki/nssdb` via `certutil -L -d sql:$HOME/.pki/nssdb`

**Every platform**
- **Every JDK/JRE on the machine, not just `JAVA_HOME`.** Look in
  `/Library/Java/JavaVirtualMachines`, `~/.sdkman/candidates/java`,
  `~/.jdks`, `~/.gradle/jdks`, JetBrains Runtime inside IDE app bundles,
  Android Studio's bundled JBR, `C:\Program Files\Java`, and any JDK on PATH.
  For each: `keytool -list -cacerts` (JDK 9+) or `keytool -list -keystore <jdk>/lib/security/cacerts`
  with the default password, and search the subjects.
- **Python `certifi`** for every interpreter you can find: system Python,
  Homebrew Python, `pyenv` versions, `pipx` environments, and any virtualenv
  that is obviously a work environment. `python -c "import certifi; print(certifi.where())"`
  then inspect that file; also record the `certifi` package version.
- **Node.js** ships its own copy of the Mozilla root store, compiled in.
  `node -p "require('tls').rootCertificates.length"` and, to inspect subjects,
  pipe each entry through `openssl x509 -noout -subject`. Also record
  `process.versions.openssl` and whether `--use-openssl-ca` is in `NODE_OPTIONS`.
- Any other vendored bundle you find: `cacert.pem`, `ca-bundle.crt`,
  `cert.pem` inside application directories.

To inspect a PEM bundle, split and read subjects — for example
`awk 'BEGIN{c=0} /BEGIN CERT/{c++} {print > ("/tmp/ca-" c ".pem")}'` into a
temp directory, then `openssl x509 -noout -subject -fingerprint -sha256`. Match
on fingerprint where you have one, subject otherwise.

## STEP 3 — Runtimes, tools, and the things nobody counts

Record versions for: `go`, `node`, `python`, `openssl`, `curl`, `java`,
`kubectl`, `terraform`, `gh`, `aws`, `gcloud`, `az`, `docker`, `podman`, `git`.

Then the parts that are routinely missed:

- **Go-built binaries are frozen at their build-time Go version.** Updating the
  Go toolchain does nothing for a binary already on disk. For each Go binary
  you can identify on PATH, run `go version -m <path>` and record the Go
  version it was built with. Flag any built with a version older than the fixed
  release you established in STEP 0. This usually surfaces more findings than
  the `go` toolchain check does.
- **Electron applications embed Chromium but do not receive Chrome's component
  updates.** A CRLSet push protects Chrome; it does not protect an Electron app
  pinned to an older Chromium. List the Electron apps present (Slack, VS Code,
  Discord, Teams, Notion, Postman and similar) with their versions, as
  informational findings requiring vendor-update verification.
- **Containers and VMs on the machine** carry their own bundles and are not
  fixed by fixing the host. List container images present (`docker images`,
  `podman images`) as a scope note. Do not run them.
- **Homebrew's `ca-certificates`** formula version and install date, where present.

## STEP 4 — Configuration that weakens or redirects verification

Check only these settings. Report the setting, its effective value, and a
redacted path. Never dump the file.

Environment: `NODE_TLS_REJECT_UNAUTHORIZED`, `PYTHONHTTPSVERIFY`,
`GIT_SSL_NO_VERIFY`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE`, `SSL_CERT_DIR`,
`REQUESTS_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `AWS_CA_BUNDLE`,
`JAVA_TOOL_OPTIONS` (for `-Dcom.sun.net.ssl.checkRevocation=false` and
trust-store overrides).

Also check the shell startup files for these being *set* even if not currently
exported — an unexported line in `~/.zshrc` is still a finding.

Configuration files: `~/.curlrc` (`insecure`, `-k`), `git config --show-origin
--get-all http.sslVerify` and any `http.<url>.sslVerify`, `~/.npmrc`
(`strict-ssl`), `pip.conf` / `pip.ini` (`trusted-host`), `~/.m2/settings.xml`,
`~/.gradle/gradle.properties`, `~/.wgetrc` (`check_certificate`),
`~/.docker/config.json` insecure registries, `~/.ssh/config` is out of scope
(SSH does not use this PKI).

Interpretation:
- Verification **disabled** is a finding on its own merits, independent of this
  incident, and usually the most actionable thing in the report.
- A **custom CA bundle** is not insecure by itself — but it bypasses the OS
  store, so an OS-level distrust will not reach it. Report it as requiring
  review, and check that bundle's contents in STEP 2.
- A variable that is **not set** is not a finding. Do not list absences.

## STEP 5 — Project scan (only if I give you a path)

If and only if I supply a directory, scan it read-only for:
`verify=False`, `InsecureSkipVerify`, `rejectUnauthorized: false`,
`CURL_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` in CI config, trust-all
`X509TrustManager` or `HostnameVerifier` implementations, `curl -k` or
`curl ... | bash` in scripts and Dockerfiles, `ssl.create_default_context`
with verification turned off, and base images pinned to digests older than the
fixed runtime versions.

Do not scan outside that path. Do not treat an old digest as vulnerable without
establishing which runtime it contains.

## EVIDENCE AND SEVERITY

Rate on observed evidence, never on the reputation of the component.

- **High** — certificate verification is explicitly disabled anywhere that
  reaches the network; or an affected certificate (matched by fingerprint) is
  present and trusted in a store used by a tool that reaches the internet.
- **Medium** — an affected or issuer-family certificate is trusted in a
  non-browser store, and the consuming runtime has no incident-specific block
  (old `certifi`, un-updated `cacerts`, a Go binary built before the fix).
- **Low** — issuer-family root present in a store that its vendor updates and
  that has the incident block applied; or a store nothing on this machine uses.
- **Informational** — custom bundles, Electron versions, container images
  present, and anything requiring vendor confirmation.

Separately rate **confidence**: `confirmed` (fingerprint match or a setting
read directly), `probable` (subject match, version inference), `inconclusive`.

Three failure modes to avoid, in order of how often they happen:
1. Calling a machine vulnerable because an eMudhra root is in the system store.
   It is in almost every machine on earth. Presence is not exposure.
2. Reporting Chrome or Firefox as exposed. They have the block.
3. Claiming a version is fixed or unfixed without having verified the fixed
   version number in STEP 0.

## OUTPUT

**1. Fact table** from STEP 0, with sources and whether each was verified.

**2. Executive summary** — one of `FINDINGS IDENTIFIED` / `NO FINDINGS IN
INSPECTED SCOPE` / `INCONCLUSIVE`, then three sentences of plain English, then
the three highest-priority actions in order.

**3. Findings table**

| # | Location (redacted) | Evidence | Finding | Severity | Confidence | Fix | Side effects | Needs admin/IT? |

**4. Not checked** — every store, runtime, container, VM or WSL distro you
could not inspect, and why. This section is as important as the findings; a
short findings table with an empty NOT CHECKED section is not a clean result,
it is an unfinished audit.

**5. Remediation plan** — per action: what to change, why, what it may break
(removing a root breaks every site legitimately using it), whether it needs
admin rights or IT, and whether it survives a reboot and a reimage.

**6. Machine-readable summary**, so results can be aggregated across a fleet.
Emit exactly this shape in a fenced `json` block, with no hostname, username or
IP anywhere in it:

```json
{
  "prompt": "emudhra-endpoint-audit",
  "prompt_version": "1.0",
  "audited_at": "<ISO 8601 date>",
  "os": { "family": "macos|windows|linux", "version": "<string>" },
  "facts_verified": true,
  "overall": "findings|clean|inconclusive",
  "counts": { "high": 0, "medium": 0, "low": 0, "info": 0 },
  "findings": [
    {
      "class": "trust_store|runtime|config|project",
      "component": "<e.g. jdk-21-cacerts>",
      "finding": "<one line>",
      "severity": "high|medium|low|info",
      "confidence": "confirmed|probable|inconclusive"
    }
  ],
  "not_checked": ["<component and reason>"]
}
```

Finish with the three next steps and an explicit line separating what you
verified from what you assumed.
