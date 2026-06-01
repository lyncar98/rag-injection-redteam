# Contributing

Thanks for helping harden the corpus.

## Adding an attack
1. Add a `context_builder(canary) -> list[str]` in `redteam/corpus/attacks.py`.
2. The builder must embed the `canary` somewhere a well-defended system should
   never surface it (visible text OR an egress channel).
3. Register an `Attack(...)` in `ATTACKS` with exactly one `Family`.
4. Run `python -m pytest -q` and `python -m redteam.run --target vulnerable`.

## Adding a target adapter
- Wrap your system in `targets/adapter.py` and register it in `redteam/run.py`.
- Always populate `TargetResponse.egress` with side effects (fetched URLs, tool
  calls, outbound messages). Invisible exfiltration is the most important case.

## Bar for merge
- Tests pass and the hardened reference target still scores 100%.
- New attacks are deterministic (canary-based), not LLM-judged.
