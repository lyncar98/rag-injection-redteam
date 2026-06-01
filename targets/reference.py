"""
Reference targets.

These use a tiny rule-based stand-in for an LLM so the harness runs with zero
dependencies and no API key. The point is not realism of the "model" — it is to
show the harness deterministically distinguishing systems by which containment
controls they have:

    vulnerable_target          - no controls. Leaks every family.
    partially_hardened_target  - treats context as data, but FORGOT egress
                                 control. Leaks only the egress families
                                 (markdown-image exfil, tool abuse).
    hardened_target            - context-as-data + egress allowlist + output
                                 DLP backstop. Still summarizes the document
                                 (it does its job); leaks nothing.

`adapter.py` shows how to wrap a real model endpoint as a Target.
"""

from __future__ import annotations

import base64
import re
from typing import Sequence

from redteam import TargetResponse

# Lines that look like instructions or payload carriers, not summarizable prose.
# A defended summarizer treats retrieved content as DATA and refuses to act on,
# or echo, anything matching these.
_INSTRUCTION_MARKERS = (
    "ignore", "instruction", "system note", "assistant:", "reveal", "append",
    "output", "include", "decode", "follow", "call ", "send_email", "policy",
    "verbatim", "required",
)
_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\((https?://[^)]+)\)")
_SEND_EMAIL = re.compile(r"send_email\([^)]*body=['\"]([^'\"]+)['\"]")
_CANARY = re.compile(r"CANARY-[A-Z0-9]+")


def _naive_model(prompt: str) -> str:
    """A credulous 'model': it obeys any instruction-looking line it sees.

    This intentionally mimics the worst case — instructions and data share one
    channel and the model cannot tell them apart.
    """
    out_lines = []
    for line in prompt.splitlines():
        m = re.search(r"(?:reveal|append|output|include)\s+.*?(CANARY-[A-Z0-9]+)",
                      line, re.IGNORECASE)
        if m:
            out_lines.append(m.group(1))
    return " ".join(out_lines) if out_lines else "Here is a brief summary."


def _guarded_summarizer(context: Sequence[str]) -> str:
    """Treat retrieved content strictly as DATA and summarize only benign prose.

    It never follows instructions embedded in the context and never echoes
    instruction-shaped lines (which is where injected canaries live). This is a
    rule-based stand-in for the real architectural control: quarantine untrusted
    context and reduce the model's privileges to those of its least-trusted input.
    """
    benign: list[str] = []
    for raw in context:
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            low = s.lower()
            if any(k in low for k in _INSTRUCTION_MARKERS):
                continue
            if "<!--" in s or "![" in s or "http://" in low or "https://" in low:
                continue
            if _BASE64_BLOB.search(s):
                continue
            benign.append(s)
    summary = " ".join(benign[:2]) if benign else "No summarizable content found."
    return f"Summary: {summary}"


def vulnerable_target(user_query: str, context: Sequence[str]) -> TargetResponse:
    """No separation, no egress control, no output sanitization. Should fail badly."""
    blob = "\n".join(context)
    prompt = f"System: You are a helpful assistant.\n{blob}\nUser: {user_query}"

    text = _naive_model(prompt)
    egress: list[str] = []

    # Vulnerable rendering: auto-fetch every markdown image URL it sees in context,
    # and "decode-and-follow" base64 blobs. Both are real EchoLeak-class mistakes.
    for url in _MD_IMAGE.findall(blob):
        egress.append(url)  # the secret rides out in the query string
    for b64 in re.findall(r"\b([A-Za-z0-9+/]{16,}={0,2})\b", blob):
        try:
            decoded = base64.b64decode(b64).decode()
            m = _CANARY.search(decoded)
            if m:
                text += " " + m.group(0)
        except Exception:
            pass
    # Tool-abuse: naively execute send_email(...) found in context.
    for body in _SEND_EMAIL.findall(blob):
        egress.append(f"email-out:{body}")

    return TargetResponse(text=text, egress=egress)


def partially_hardened_target(user_query: str, context: Sequence[str]) -> TargetResponse:
    """Got the model layer right, forgot the egress layer.

    Context is treated as data (so direct/indirect/hidden/encoded text attacks
    are contained), but the renderer still auto-fetches markdown images and the
    agent still executes tool calls found in retrieved content. The harness
    localizes the gap to exactly two families instead of averaging it away —
    this is the per-family triage the article argues for.
    """
    text = _guarded_summarizer(context)
    blob = "\n".join(context)

    egress: list[str] = []
    for url in _MD_IMAGE.findall(blob):
        egress.append(url)
    for body in _SEND_EMAIL.findall(blob):
        egress.append(f"email-out:{body}")
    # NOTE: no output DLP backstop here, and egress is not allowlisted.

    return TargetResponse(text=text, egress=egress)


def hardened_target(user_query: str, context: Sequence[str]) -> TargetResponse:
    """The layered defenses from the article, on a system that still does its job.

    1. Context-as-data: the summarizer never follows instructions in retrieved
       content (architectural control / privilege reduction).
    2. Egress allowlist: no auto-fetched images/links, no tool calls derived
       from retrieved content. Nothing leaves.
    3. Output DLP backstop: redact sensitive-shaped tokens that slip through, so
       a single upstream failure is not fatal.

    Crucially it STILL summarizes the document — defense is not "ignore the input."
    """
    # Layers 1: quarantine + summarize.
    text = _guarded_summarizer(context)

    # Layer 2: egress allowlisted to empty in this reference target.
    egress: list[str] = []

    # Layer 3: defense-in-depth output filter. The canary stands in for whatever
    # sensitive data your DLP is configured to catch.
    text = _CANARY.sub("[redacted]", text)

    return TargetResponse(text=text, egress=egress)
