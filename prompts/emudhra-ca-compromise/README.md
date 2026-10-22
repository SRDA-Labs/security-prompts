# eMudhra intermediate CA compromise — audit prompts

Reported publicly on **17 October 2026**: private keys for several eMudhra
intermediate CA certificates were recoverable because of insufficient entropy
at key generation. A holder of those keys can mint a certificate for any
hostname that chains to a publicly trusted root.

Browsers were fixed within days through CRLSets, OneCRL and OS updates. **Those
channels reach browsers and almost nothing else.** PEM bundles, Java `cacerts`,
Python `certifi`, Node's compiled-in root store, Go binaries, Electron apps,
container images and CLI tools do not consume them, and most non-browser
clients never check revocation at all.

The question these prompts answer is not "is my browser patched" — it is
**"which of the thirty trust stores on this machine did anybody actually fix?"**

| Prompt | Target |
|---|---|
| [endpoint-audit.md](endpoint-audit.md) | A laptop or workstation — macOS, Windows, Linux, including WSL |
| [aws-ec2-audit.md](aws-ec2-audit.md) | An EC2 instance or any Linux server, including containers and AMI/ASG durability |

## Using them

Open a fresh agent session on the machine being audited, paste the prompt
below the `---` line, and let it run. Both are read-only: no changes, no
installs, no privilege escalation, no network probes from the audited host, and
no data leaves the machine.

Both finish with a machine-readable JSON block so results can be aggregated
across a fleet without anyone re-reading prose.

## Two things to know before you trust the output

**Verify the facts.** Both prompts open with a verification step for a reason.
The incident details — how many intermediates, which fingerprints, which fixed
runtime versions — are reported context, not ground truth, and an agent that
repeats a version number from a prompt back to you as fact has told you
nothing. If the fact table at the top of the report is unverified, treat the
severities below it as provisional.

**Presence is not exposure.** An eMudhra root sits in nearly every trust store
on earth. The finding is a trust store that is *consumed by something that
reaches the network* and that *has no incident-specific block* — not the mere
presence of a certificate. The prompts say this repeatedly because it is the
single most common way these audits produce a frightening report about nothing.

## What they are not

A prompt is a structured way to look. It is not an assessment, it does not
cover what the agent could not reach, and the NOT CHECKED section of the output
is as important as the findings table. Read it.
