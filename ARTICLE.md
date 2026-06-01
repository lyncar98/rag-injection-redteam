# The model is not your security boundary: red-teaming indirect prompt injection in RAG and agents

*Why the most dangerous LLM vulnerability lives in the data your system retrieves — and how to build a harness that catches it before production does.*

> Published version: https://medium.com/p/e6dd378d5e59

---

In June 2025, researchers at Aim Labs disclosed EchoLeak (CVE-2025-32711), a zero-click flaw in Microsoft 365 Copilot. The attack needed no clicks, no malicious attachment to open, no credential phish. An attacker sent an ordinary-looking email. It sat in the inbox. When Copilot later retrieved that email as context to answer an unrelated question, hidden instructions inside it took over — and exfiltrated internal data to an attacker-controlled destination. Microsoft patched it server-side and reported no exploitation in the wild, but the significance outlived the CVE: it was the first documented case of indirect prompt injection weaponized for real data exfiltration in a production LLM system.

If you build with retrieval-augmented generation or agents, EchoLeak is not a Microsoft problem. It is a preview of your problem. The structural condition that made it possible — a model that reads untrusted external content and acts with the user's privileges — describes most enterprise GenAI architectures shipping today.

This article is about why that condition is so hard to fix, why "we added a guardrail" is not an answer, and how to build something you can actually run against your own stack: a reusable red-team harness for indirect prompt injection. The companion repository is linked at the end.

## Why prompt injection is not SQL injection

The tempting analogy is SQL injection, and the analogy is exactly the trap. SQL injection has a clean fix: parameterized queries separate code from data at the protocol level. The database never confuses a user's name for a command because the two travel in structurally distinct channels.

LLMs have no such channel. Instructions and data arrive as the same undifferentiated token stream. The model was trained to follow instructions written in natural language, and it cannot reliably tell which instructions came from your system prompt, which came from the user, and which were smuggled in via a retrieved document. The UK's NCSC has made this point bluntly: treating prompt injection like SQL injection is conceptually dangerous, because there is no parameterization to reach for. OWASP has ranked prompt injection as the number one risk for LLM applications across two consecutive editions for the same reason — it exploits the design of the model itself, not a bug in your code.

That distinction has a hard consequence. You cannot patch your way out. Every mitigation is probabilistic. The correct engineering posture, which NCSC states directly, is to **assume some injection will succeed** and design so that when it does, the blast radius is small.

## Direct vs. indirect: where the real risk lives

Direct prompt injection is the version everyone pictures: a user types "ignore your previous instructions" into a chatbot. It is real, but it is mostly a content-safety and policy problem, and the attacker is the user — someone already inside your trust perimeter, attacking themselves.

Indirect prompt injection is the dangerous one. Here the malicious instructions live in content the model consumes, not in what the user types: a web page, a PDF, a support ticket, a calendar invite, a row in a vector store, an email. The user asks an innocent question. Your system retrieves the poisoned content as context. The hidden payload executes — using the user's identity, the agent's tools, and the application's network access.

This is why RAG, often sold as a safety feature, is more accurately a new attack surface. OWASP's 2025 list calls this out explicitly under both LLM01 (Prompt Injection) and LLM08 (Vector and Embedding Weaknesses). The retrieval step you added to reduce hallucinations is the same step that imports attacker-controlled instructions into your trusted context.

The failure mode has a name worth internalizing: **scope violation**. The system is granted access to far more data, more tools, and more network reach than you would ever grant an untrusted process — and then the design implicitly trusts the model to enforce the boundary between "summarize this" and "exfiltrate everything you can see." EchoLeak is what happens when that trust is misplaced.

## The anatomy of an indirect injection attack

It helps to decompose the attack into the conditions it requires, because each condition is a place to intervene.

1. **An ingestion path for untrusted content.** The agent reads something it did not author and the user did not write: retrieved documents, tool outputs, web pages, inbound messages.
2. **A payload the model will follow.** The instruction need not be human-visible. White text, metadata, alt-text, speaker notes, and encoded strings all work, as long as the content is parsed by the model.
3. **A capability worth abusing.** Tool access, a privileged service identity, the ability to emit links or images, or simply the presence of sensitive data in the same context window.
4. **An exfiltration or action channel.** A way for the result to leave: an outbound link the renderer will fetch, an image URL, a tool call, an email send.

EchoLeak is instructive precisely because it chained multiple weak links: it evaded the cross-prompt-injection classifier, slipped past link redaction using reference-style Markdown, abused auto-fetched images, and routed data through an allowed proxy. No single guardrail failed catastrophically. The system failed because every layer was individually bypassable and nothing reduced the blast radius once one did.

## Defense in depth, honestly

There is no silver bullet, so the goal is layers that each shrink the attack surface and assume the others will sometimes fail.

**Separate trusted from untrusted context.** Clearly delimit and tag retrieved content as data, never as instructions. This does not solve the problem — the model can still be persuaded — but it raises the cost and supports downstream filtering.

**Least privilege for agents and tools.** This is the highest-return control, because it directly attacks condition 3. Narrow-scope tokens, separate execution identities, allowlisted tools and destinations, and human approval gates for high-risk actions mean a successful injection has little to grab and nowhere to send it.

**Constrain the exfiltration channel.** Restrict outbound network egress. Disable or sanitize auto-fetched images and links in rendered output. EchoLeak's data left through image and link fetches; closing those would have broken the chain.

**Screen prompts and responses.** Classifiers for injection patterns and sensitive-data leakage are worth running — but treat them as speed bumps, not walls. EchoLeak bypassed exactly this kind of classifier.

**Ground and evaluate RAG outputs.** Assess context relevance and groundedness so that off-topic, injected instructions are easier to flag.

**Red-team continuously.** This is the one most teams skip, and it is the one that ties the others together. EchoLeak-class failures appear only in the integrated system — the model, plus its retrieval, plus its tools, plus its renderer. Base-model safety testing will never surface them. You have to attack the assembled application, repeatedly, as it changes.

The unifying rule: **never let the model itself be your only security boundary.** Put identity, policy, egress control, and data filtering around it, and assume the model can be talked into anything.

## What a red-team harness actually needs to do

Most "we tested for prompt injection" claims mean someone pasted three jailbreak strings into a chat window once. That is not a control; it is an anecdote. A real harness has a few properties:

- **It targets the integrated system,** not the bare model — your retrieval path, your system prompt, your tool wiring.
- **It is corpus-driven and versioned,** so the attack set grows over time and runs identically on every change.
- **It scores by canary, not by vibes.** Each attack plants a unique secret (a "canary") in a place the model should never reveal, and a probe checks whether the canary appears in the output or in an attempted egress. Detection is then deterministic, not a judgment call.
- **It is release-gating,** producing a pass/fail metric and a report you can attach to a deploy, with a defined threshold below which you do not ship.
- **It separates attack families,** so you can see whether you regressed on, say, Markdown-image exfiltration specifically.

That last point matters for triage. "Injection defense: 84%" is useless. "Direct override 100%, indirect-document 71%, image-exfil 40%, encoded-payload 55%" tells you exactly where to spend the next sprint.

## The companion harness

To make this concrete, I built **`rag-injection-redteam`** — a small, dependency-light red-team harness for indirect prompt injection in RAG and agent systems. It is deliberately model-agnostic: you point it at any callable that takes a user query plus retrieved context and returns a response, and it does the rest.

What it does:

- Ships a **versioned corpus of attack documents** organized by family: direct override, indirect document injection, hidden-text/metadata payloads, Markdown-image exfiltration, encoded payloads, and tool-abuse lures.
- Uses **canary-based detection**: each scenario plants a unique secret and checks the response (and any simulated egress) for leakage, so scoring is deterministic.
- Produces a **per-family report and an overall pass rate**, with a configurable failure threshold suitable for CI gating.
- Includes **three reference targets** — vulnerable (no controls, leaks everything), partially hardened, and hardened — so you can see the harness do real triage rather than emit one averaged number. The partially hardened target treats retrieved content as data but forgets egress control, and the harness pins the failure to exactly two families (Markdown-image exfiltration and tool abuse) while the rest stay green. Importantly, the hardened target **still summarizes the document** — it does its job; defense here is not "ignore the input," it is delimiting + egress allowlisting + an output-DLP backstop layered around a system that still works.
- Has **adapter stubs** for plugging in your own model endpoint, plus a GitHub Actions workflow so the suite runs on every pull request.

It is intentionally not a product. It is a starting skeleton you fork, extend with attacks specific to your domain, and wire into your own stack — exactly the kind of artifact OWASP's "conduct adversarial testing and attack simulations" guidance asks for, made runnable.

**Repo:** [`github.com/lyncar98/rag-injection-redteam`](https://github.com/lyncar98/rag-injection-redteam)

If you extend it with a new attack family or an adapter for your platform, open a PR — the corpus gets stronger the more systems it is pressure-tested against.

## The takeaway

EchoLeak was patched, but the class of vulnerability it represents is structural and is not going away while LLMs share a single channel for instructions and data. The teams that handle this well are not the ones with the cleverest guardrail. They are the ones who assumed injection would succeed, engineered the blast radius down to nearly nothing, and ran the attacks against their own integrated system on every change.

You cannot patch prompt injection. You can refuse to let the model be your only boundary — and you can prove you did, on every deploy, with a harness that tries to break it.

---

*If you build RAG or agent systems and want to compare notes on injection defenses or the harness, the repo issues are open.*
