# OS-Audit

**Governing agents starts with knowing whether or not they obeyed.**

Attribution of Unauthorised Directives by Input Tracing. From SentinelOS Frontier Lab.

## Why

An AI agent acts on what it reads. One sentence hidden in a mail, a page or a ticket can give it an order, and it will
carry that order out with its owner's access.

Finding the hidden sentence is a solved kind of problem. It does not tell you what matters next: **did the agent obey
it?** By the benchmarks' own score, an attack succeeds in 17.2 % of runs under attack on AgentDojo and 12.2 % on
AgentDyn. A detector of the planted text cannot tell these runs from those in which the agent ignored it.

OS-Audit answers that one question, and shows its proof.

## What it does

It works two ways.

**Before.** Put it where your agent runs its tools, and it judges each call before the call runs.

**After.** Hand it finished sessions, one or a hundred thousand, and it tells you which ones obeyed.

Either way it works from three things: what the user asked, the tool calls with what each returned, and the text that
was flagged as a hidden instruction.

It follows every value of every call back to where it came from. A payment to an account only the hidden text named.
A mail to an address only it gave. A password it dictated. A date it set. And one step further: a value returned by a
lookup the hidden text told the agent to make.

When such a value reaches a call that acts, or a fetch to an address the hidden text named, the agent is obeying. You
know it before the money leaves.

There is no model. Nothing to train, nothing to tune, nothing to download but the package. One file of logic.

## Install

```bash
pip install sentinelos-audit
```

Python 3.9 or later. No dependency.

## Use

**Before.** Where your agent runs its tools:

```python
from os_audit import Watch

watch = Watch(request)

proof = watch.before(tool, args)     # before the call runs
if proof and (proof.acting or proof.egress):
    ...                              # it carries a value of the hidden text: stop it, hold it, log it
result = run(tool, args)
watch.after(result)

watch.flag(text)                     # whenever your detector flags a text
```

The check before a call is fast: per call, p50 50 microseconds, p95 0.41 ms, p99 1.3 ms, measured over 6,574 recorded
sessions. See it stop a payment:

```bash
python examples/live.py
```

```
stopped before it ran: send_money us133000000121212121212 - named only by the hidden text
```

**After.** On a recorded session, three lines:

```python
from os_audit import audit

verdict = audit(request, calls, hidden_text)
if verdict.obeyed:
    print(verdict.level, verdict.evidence)
```

`calls` is the session in order, in the simplest shape there is:

```python
calls = [
    {"tool": "read_file",  "args": {"file_path": "bill-december.txt"}, "result": "..."},
    {"tool": "send_money", "args": {"recipient": "US133000000121212121212", "amount": 98.7}, "result": "ok"},
]
```

Whatever your agent framework, tool gateway or trace format, it reduces to that in a few lines.

Or one command on a log file:

```bash
os-audit check examples/session.json
```

```json
{
  "schema_version": "1",
  "obeyed": true,
  "level": "acted",
  "egress": false,
  "decision": "no-go",
  "evidence": [
    {
      "call": 1,
      "tool": "send_money",
      "value": "us133000000121212121212",
      "reason": "named only by the hidden text",
      "acting": true,
      "egress": false,
      "decision": "no-go"
    }
  ]
}
```

The exit code is `1` when the agent obeyed. Put that line in a build pipeline and the build fails the day an agent
acts on an injected instruction.

`level` is `acted` (a call that acts used a value of the hidden text), `looked_up` (the agent only went and looked at
what the text named) or `none`. `egress` is `true` when a fetching call requests an address the hidden text named.

**Which tools act.** By default, the words of the tool's name: `check_out_and_pay` acts, `get_order` reads, a name with
no reading verb acts. MCP annotations come from the server, and the MCP specification says not to trust them from an
untrusted server: they may only make a tool stricter, never turn a payment into a read. Only you, the operator, can:

```python
from os_audit import Tools

tools = Tools.from_mcp(server_tools, operator={"erp.query": "read", "web.*": "egress"})
verdict = audit(request, calls, hidden_text, tools=tools)
```

**In your logs.** `verdict.to_json()` is one line in a fixed form (`src/os_audit/schema.json`). For a trace,
`os_audit.export.to_otel(evidence)` gives the attributes of a span event on the tool call, after the OpenTelemetry
GenAI conventions; it carries the kind of the value and a salted hash, never the value itself unless you ask for it,
and never a secret. No dependency: with the `opentelemetry` package, `attach(span, evidence)` adds the event.

**In TypeScript.** `ports/ts/os_audit.ts`, one file, no dependency, run by Node 24 or Bun as it is. Every proof it
gives is the Python engine's, byte for byte, on the golden corpus in `ports/golden/`: `node ports/ts/conformance.ts`.

## What it found

Run on the recorded sessions that two public benchmarks publish. Each distinct run is counted once.

| | AgentDojo | AgentDyn |
|---|---|---|
| run folders (model and defence set-ups, as `reproduce` counts them) | 28 | 66 |
| attacks that succeeded through a tool call (distinct runs) | 4,486 | 3,801 |
| **of those, flagged by the audit of the recorded session** | **97.9 %** | **96.3 %** |
| of those, flagged live (the text is flagged only once a result carries it) | 97.7 % | 96.3 % |
| ordinary runs handed a hidden text they never met, flagged by the audit | 0.16 % (3 of 1,824) | 0.80 % (31 of 3,899) |
| ordinary runs interrupted by the gate, with the text known from the start | 0.11 % | 0.56 % |

Live, an ordinary run never carries the hidden text, so it is never flagged: the two false-alarm rows measure what
happens when the text is known from the start. A 10,000-call session is judged in 0.65 s. Live, call by call, it is the
same logic.

Four corpora of clean agent sessions (tau-bench, MCP-Atlas, Toucan, obaydata) produce no false alarm.

Success is not obedience, in both directions. Of 99 AgentDojo runs scored as successful attacks that an earlier version
did not flag, 60 were not obedience (crashed runs, a benchmark version where the "attacker's" account is the user's
landlord, three with no obedience); at most about 39 are real misses. In the other direction, OS-Audit flags 4.36 % of
AgentDojo runs and 7.59 % of AgentDyn runs that the benchmarks score as resisted; in 3.24 and 3.54 percentage points of
them the proof shows obedience directly (a secret left the session, a fetch reached the attacker's address, or an
acting call used an address, site or account that only the attacker gave).

## Check it yourself

Each benchmark figure above comes from one command, run on the benchmark's own archive:

```bash
os-audit reproduce agentdojo-main.tar.gz      # github.com/ethz-spylab/agentdojo, MIT
os-audit reproduce AgentDyn-main.tar.gz       # github.com/SaFo-Lab/AgentDyn, MIT
```

Nothing in the archives is executed. The clean-corpus and constructed-evasion figures are not produced by `reproduce`.

## Where it stops

OS-Audit is a first layer. It catches the attacks that name a value. It does not catch every attack, and it does not
pretend to.

- It does not find the hidden instruction. Something has to hand it one.
- An attack that names no value ("delete one of the repositories", "book the most expensive hotel") leaves it nothing
  to follow.
- An attack whose goal is only to make the agent say something, or stop, makes no call to read. For the first kind,
  `echoed(request, calls, hidden_text, answer)` returns seven words in a row the answer repeated from the hidden text
  and found nowhere else; a separate signal, as an agent that quotes the text to warn its user repeats it too.
- It needs the owner's words: the user's original request and, when there is one, the operator's system prompt. Any
  value that already appears in them is never flagged.
- Dates are read in English, French, German, Spanish, Italian and Portuguese, and quoted values in `'…'`, `"…"`, `«…»`,
  `“…”`, `„…“`, `‘…’` and `「…」`; a date written only in figures (`01/05`) is not read, as its day and month cannot be
  told apart.
- A copy of the hidden text inside an argument that names an object (a channel called after the injection) is taken
  as the object's name, not as values handed to the call. Inside a free-text argument (a message body) it is still read.
  A known secret is never dropped this way; a payee IBAN or a mailbox is kept when the argument is an address, or when
  the call acts and the argument does not name a place.
- In an argument, base64, hex and percent-encoding are undone, Cyrillic and Greek look-alike letters are read as Latin,
  an account sent in two pieces and « the account ending in 1212 » are traced. Not undone: rot13, other ciphers,
  values rebuilt from more than two pieces, or described in any other words.
- Unquoted single alphabetic words shorter than 10 letters, short (`<= 3` chars) or digits-only unquoted values,
  wrapped or reworded dictated text, and unlisted bare TLDs without a URL scheme are not flagged.
- Lookups are followed one step, and only when the lookup itself carried a value from the hidden text; unlinked
  ordinary-name lookups and multi-hop chains pass.
- A tool is judged by the words of its name unless the operator says otherwise: a name with a reading verb and no
  acting verb (`get_order`, `github_list_issues`) is treated as a read unless it fetches a hidden-named address; an
  acting tool named only with reading words (`query_erp`) needs the operator's map to be judged as acting.
- State is per-session; values written in one session and read in a later session with no flagged text are not linked.

## Paper

Preprint: link to be added on publication.

## Licence

MIT.
