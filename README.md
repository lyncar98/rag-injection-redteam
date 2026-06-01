# rag-injection-redteam

A small, dependency-light **red-team harness for indirect prompt injection** in RAG and agent systems. Point it at any callable that takes a user query plus retrieved context and returns a response, and it tries to make your system leak.

Companion code for the article [*"The model is not your security boundary: red-teaming indirect prompt injection in RAG and agents."*](https://medium.com/p/e6dd378d5e59)

## Why this exists

You cannot patch your way out of prompt injection — LLMs process instructions and data in the same channel, and [OWASP ranks it the #1 LLM application risk](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) two editions running. [EchoLeak (CVE-2025-32711)](https://nvd.nist.gov/vuln/detail/CVE-2025-32711) showed the indirect variant exfiltrating real data out of a production copilot with zero clicks.

The only durable answer is defense in depth **plus continuous adversarial testing against the integrated system** — because EchoLeak-class failures never show up in base-model safety tests. This harness is the runnable version of OWASP's "conduct adversarial testing and attack simulations" guidance.

## What it does

- **Versioned attack corpus** grouped by family: direct override, indirect document injection, hidden-text/metadata payloads, Markdown-image exfiltration, encoded payloads, tool-abuse lures.
- **Canary-based detection** — each attack plants a unique secret; a probe checks the response *and* any attempted egress (fetched URLs, tool calls, email bodies) for leakage. Scoring is deterministic, not a judgment call.
- **Per-family report + overall pass rate**, with a configurable threshold suitable for CI gating.
- **Three reference targets** — `vulnerable`, `partial`, and `hardened` — so you can watch the harness tell them apart *and* localize a partial failure to specific families.
- **Adapter stub + GitHub Actions workflow** to wire in your own endpoint and run on every PR.

## Quick start

```bash
git clone https://github.com/lyncar98/rag-injection-redteam
cd rag-injection-redteam
python -m redteam.run --target vulnerable    # 0/6: leaks every canary
python -m redteam.run --target partial       # 4/6: context-as-data, but egress control is missing
python -m redteam.run --target hardened      # 6/6: layered defenses hold (and it still summarizes)
```

The `partial` target is the interesting one: it treats retrieved content as data (so text-echo attacks are contained) but forgot to lock down egress, so it leaks **only** the markdown-image-exfil and tool-abuse families. That per-family signal — not a single averaged number — is what tells you where to spend the next sprint.

Gate a deploy on zero leaks:

```bash
python -m redteam.run --target hardened --threshold 1.0 --report report.md
```

## Test your own system

Wire your stack into `targets/adapter.py` (fill in `call_my_system`), register it in `redteam/run.py`, then:

```bash
python -m redteam.run --target mine --threshold 0.95
```

Capture side effects — fetched URLs, tool calls, outbound messages — in the response's `egress` list. Exfiltration that never appears in visible text is the whole point.

## What it does *not* do

- It is not a product or a guardrail. It is a forkable skeleton you extend with attacks specific to your domain.
- The reference "model" is a rule-based stand-in so the demo runs with no API key. It is deliberately not a real LLM — it exists to show the harness telling a defended system apart from an undefended one. Swap in a real model via the adapter.
- A green run is evidence, not a guarantee. Prompt injection defense is probabilistic; keep growing the corpus.

## Related

For the quality/reliability side of shipping agents — grader registries, `pass@k`/`pass^k`, and release gating — see the companion project [`agent-eval-harness`](https://github.com/lyncar98/agent-eval-harness). This repo is the *security* red-team counterpart; the two are intentionally separate (different threat model, different audience) but compose well: a canary attack family here can be imported as an adversarial suite there.

## Layout

```
redteam/
  core.py            # attack model, canary detection, runner, scoring
  run.py             # CLI + CI gate
  corpus/attacks.py  # the versioned attack set (extend me)
targets/
  reference.py       # vulnerable / partial / hardened reference targets
  adapter.py         # wrap your real system here
tests/
  test_harness.py
```

## Contributing

New attack family or a platform adapter? Open a PR — the corpus gets stronger the more systems it is pressure-tested against. See `CONTRIBUTING.md`.

## License

MIT. See `LICENSE`.
