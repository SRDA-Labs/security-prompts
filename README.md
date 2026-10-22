<div align="center">

# Security prompts

**Read-only audit prompts you paste into an agent session.**

Vetting an endpoint against a specific CVE, or a whole estate against a
published standard — without installing anything, changing anything, or
sending anything anywhere.

[![License: MIT](https://img.shields.io/badge/License-MIT-e85c5f.svg?style=flat-square)](LICENSE) [![Built by SRDA Labs](https://img.shields.io/badge/built%20by-SRDA%20Labs-e85c5f.svg?style=flat-square)](https://github.com/SRDA-Labs)

</div>

---

Everyone now has an agent on their laptop that can read files and run commands.
That is a fast, underused way to answer a question most organisations cannot
answer on the day an advisory lands: **is this machine actually affected?**

Not "have we patched the browser" — the browser fixes itself. The question is
the Java `cacerts` in an IDE's bundled runtime, the `certifi` in a four-year-old
virtualenv, the Go binary in `/usr/local/bin` frozen at the version it was
built with, the container image nobody has rebuilt since March.

These prompts are written for that. They are long on purpose: the failure modes
of an agent doing security work are over-claiming, repeating a prompt's own
unverified context back as fact, and quietly skipping what it could not reach.
Each prompt is built to close those three.

## Prompts

| Prompt | Target | What it looks for |
|---|---|---|
| [eMudhra CA — endpoint](prompts/emudhra-ca-compromise/endpoint-audit.md) | macOS / Windows / Linux laptop, incl. WSL | Every trust store on the machine, runtimes with compiled-in roots, TLS verification turned off |
| [eMudhra CA — EC2 / server](prompts/emudhra-ca-compromise/aws-ec2-audit.md) | EC2 instance or Linux server | The same, plus containers, outbound dependency mapping, and whether a fix survives the next scale-out |

Background on that incident: [prompts/emudhra-ca-compromise/README.md](prompts/emudhra-ca-compromise/README.md).

## Ground rules, in every prompt

- **Read-only.** No modification, no installs, no `sudo`, no service restarts.
- **No network probes** from the audited host. Public advisory research is
  allowed; sending anything about the machine anywhere is not.
- **No secrets in the output.** Settings are reported, values are redacted,
  usernames and hostnames never appear.
- **Verify before judging.** Every prompt opens with a fact-checking step and
  reports which facts it could and could not confirm.
- **Report, never remediate.** Fixes are written down for a human.
- **NOT CHECKED is a required section.** An audit that lists no findings and no
  gaps is not a clean result; it is an unfinished one.

Each prompt ends with a JSON block so a fleet's worth of reports can be
aggregated without anyone reading prose.

## Using one

Open a fresh agent session on the machine, paste everything below the `---`
line, answer the optional project-path question if you want the code scan, and
read the NOT CHECKED section before you read the findings.

Give the agent the narrowest permissions that let it read files and run shell
commands. The prompt forbids destructive actions; your tooling should too.
Trusting the prompt alone to constrain the agent is the wrong number of layers.

## Contributing

A prompt is welcome if it is read-only, states its own uncertainty, and
produces output a human can act on and a script can aggregate. Open a pull
request with the prompt, a short README for the incident or standard it covers,
and a note on what it cannot see.

## Disclaimer

These prompts are a structured way to look. They are not an assessment, they
are not a substitute for one, and their output is only as good as the access
the agent had and the facts it managed to verify. Released under the MIT
licence, with no warranty — see [LICENSE](LICENSE).

---

<div align="center">

Built by **[SRDA Labs](https://srdalabs.com)** — Security Research and Defence Advisory.

</div>
