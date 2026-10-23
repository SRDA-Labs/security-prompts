# Railway environment-variable exposure — October 2026

## What happened

On 21 October 2026 Railway disclosed that an unauthorised third party may have
gained access to encrypted customer environment variables and, in some cases,
obtained the decrypted contents. Railway paused all deployments, rotated its
own bucket credentials, invalidated Railway API tokens, and told customers to
rotate every environment variable, API key and private registry credential
stored on the platform.

Railway described the affected population as "a subset of users" and did not
publish a number. Public reporting places the first known downstream theft at
roughly 19:36 UTC on 21 October — before the disclosure was public — and
connects the intrusion to a broader campaign against platform companies aimed
at reaching AI inference providers.

**Sealed variables.** Railway's sealed variables cannot be read back through
the UI, API or CLI, which limits casual exposure. Railway's disclosure did not
state whether they were within the scope of the breach. The absence of a
statement is not a statement of absence, and both prompts treat them as exposed
while saying so explicitly.

Every fact above was assembled from reporting within days of the event. Both
prompts open with a step that re-checks it against primary sources before any
of it is used, and report which facts they could not confirm.

## Why this needed its own prompts

The advice everybody gave was *rotate everything*. That is correct and almost
useless, because it skips the two questions that decide what actually happens:

**What was exposed, exactly?** A team with forty services across three
environments has several hundred variables. Most are configuration. Some are
credentials that read customer data, deploy code, or spend money. A few can
read *other* credentials — and those have to be rotated first, or every
rotation downstream of them lands somewhere the attacker is still reading.

**Were they used?** Exposure and compromise are different events requiring
different responses, and the evidence that separates them is being deleted on a
rolling basis. Every provider has its own retention window. The question has an
expiry date, and for some providers it has already passed.

## The constraint that shaped the workspace prompt

The usual rule in this repository is *do not print secrets in the output*. For
this incident that is not strong enough.

The obvious way to audit a secrets exposure is to dump every variable so the
agent can classify them. That sends every credential you own to whichever model
provider is running the session — a second exposure, to a second third party,
performed deliberately, during the response to the first one.

So the workspace prompt forbids reading values at all. The agent works from
variable names, and where a value must be processed, the prompt pipes it
through a local filter that strips values before anything returns to the
agent's context. The JSON output carries a `values_never_read` boolean, and the
prompt requires it to be reported honestly as `false` if a value ever leaked
into the session — because at that point the transcript contains the
credentials and has to be handled accordingly.

## The prompts

| Prompt | Target | Answers |
|---|---|---|
| [workspace-audit.md](workspace-audit.md) | A workstation with the `railway` CLI authenticated | What was exposed, what each credential can do, what to rotate and in what order |
| [downstream-abuse-audit.md](downstream-abuse-audit.md) | The provider accounts — AWS, Stripe, GitHub, model providers, databases | Whether anything was actually used, and how long you have left to find out |

Run the workspace audit first; its credential inventory is the input to the
downstream one.

## Running them

Open a fresh agent session and paste everything below the `---` line.

For the workspace audit, the CLI must already be authenticated — the prompt
will not authenticate for you, and will stop if it finds it cannot read.

For the downstream audit, authenticate to each provider with **your own
administrative session**. Never with an exposed credential: it writes your
activity into the evidence you are about to examine, at the moment you are
trying to establish who else used it.

## What they cannot tell you

Neither prompt tests whether a credential is still valid. That would mean an
authentication attempt from your address, landing in the provider's logs,
during an active incident — corrupting the evidence the downstream audit
depends on.

The workspace audit classifies credentials from variable names alone, which is
inference, not confirmation. `STRIPE_SECRET_KEY` is unambiguous; `API_KEY` is a
guess. The prompts rate those differently and never present them in the same
voice.

Neither covers copies held outside Railway unless you point them there:
teammates' `.env` files, CI secrets, a credential pasted into a ticket two
years ago. The workspace audit asks about these and records the answers as
operator-supplied facts rather than observations.

## Related

For local, offline classification of a variable dump — including blast radius
and rotation ordering against a knowledge base of per-provider rotation
mechanics — see [SRDA-Labs/revoka](https://github.com/SRDA-Labs/revoka), which
was written in response to this same incident. It runs on your machine, makes
no network calls, and never writes a credential value to its output, so it can
read values the agent in these prompts deliberately will not.

## Sources

Assembled 23 October 2026. Re-verify before relying on any of it.

- The Hacker News — [Railway Says Intruder May Have Accessed Customer Secrets](https://thehackernews.com/2026/10/railway-says-intruder-may-have-accessed.html)
- GitGuardian — [New Railway Incident: Treat Every Env Variable as Exposed](https://blog.gitguardian.com/railway-october-2026-incident-environment-variables/)
- Railway status page — <https://status.railway.com/>
