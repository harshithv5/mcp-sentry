"""L1 — Semantic prompt-injection detection via an external LLM judge.

Regex detectors (S1, S2, S5) catch known injection vocabulary but miss novel
phrasing. L1 asks a small classifier model (Prompt Guard) whether a tool's
text fields look like injection content, then asks a larger reasoning model
to explain *why* on anything that scores above threshold.

Findings are `confirmed=False` — an LLM judge is a probabilistic signal, not
proof — but the score and reasoning carry the actual evidence.

Two-stage pipeline, per the integration plan:
1. Cheap classifier (Llama Prompt Guard 2 86M) — one call per text field.
2. Reasoning model (Llama 3.3 70B Versatile) — only on fields that exceed
   threshold, to produce the human-readable explanation.

Configuration is via the constructor; the orchestrator instantiates this
detector lazily when `enable_llm_judge=True` and a Groq API key is present.
"""
import asyncio
import logging

from ..base import SemanticDetector
from ...llm import groq_call
from ...models import Finding, Severity, ToolInfo


logger = logging.getLogger(__name__)


_DEFAULT_CLASSIFIER = "meta-llama/llama-prompt-guard-2-86m"
_DEFAULT_REASONING = "llama-3.3-70b-versatile"

_MIN_TEXT_LEN = 20  # skip trivially short fields — too little signal
_EVIDENCE_TRUNCATE = 200


def _truncate(text: str, limit: int = _EVIDENCE_TRUNCATE) -> str:
    text = text.replace("\n", " ").replace("`", "'")
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def _map_severity(score: float) -> Severity:
    if score >= 0.9:
        return Severity.CRITICAL
    if score >= 0.7:
        return Severity.HIGH
    if score >= 0.5:
        return Severity.MEDIUM
    return Severity.LOW


def _parse_classifier_label(raw: str) -> float:
    """Translate a Prompt-Guard-style label into a [0.0, 1.0] probability.

    Prompt Guard's chat-completion responses are short labels (JAILBREAK /
    INDIRECT_INJECTION / BENIGN) sometimes with a confidence number. We pick
    the strongest signal we can extract; if the response is unparseable we
    return 0.0 so the field is not flagged.
    """
    if not raw:
        return 0.0
    label = raw.strip().upper()

    # Some endpoints return a bare float; try that first.
    try:
        return min(max(float(label.split()[0]), 0.0), 1.0)
    except (ValueError, IndexError):
        pass

    if "JAILBREAK" in label or "MALICIOUS" in label:
        return 0.92
    if "INJECTION" in label or "PROMPT_INJECTION" in label:
        return 0.82
    if "SUSPICIOUS" in label:
        return 0.65
    if "BENIGN" in label or "SAFE" in label or label == "NONE":
        return 0.05
    return 0.0


class LLMJudgeDetector(SemanticDetector):
    rule_id = "L1"
    severity = Severity.HIGH
    description = "Semantic detection of prompt injection using an LLM judge."

    _SUGGESTED_FIX = (
        "Review this field for hidden instructions or injection attempts. "
        "An external classifier flagged it as resembling prompt-injection "
        "content — even if the regex banks didn't trip, the phrasing is "
        "suspicious."
    )

    def __init__(
        self,
        groq_api_key: str,
        *,
        classifier_model: str = _DEFAULT_CLASSIFIER,
        reasoning_model: str = _DEFAULT_REASONING,
        threshold: float = 0.7,
    ) -> None:
        self._api_key = groq_api_key
        self.classifier_model = classifier_model
        self.reasoning_model = reasoning_model
        self.threshold = threshold

    async def check(self, tool: ToolInfo) -> list[Finding]:
        if not self._api_key:
            return []

        findings: list[Finding] = []
        for field_name, text in tool.labelled_text_fields:
            if not text or len(text) < _MIN_TEXT_LEN:
                continue
            try:
                score = await self._classify(text)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug("L1 classifier failed for %s.%s: %s", tool.name, field_name, exc)
                continue

            if score < self.threshold:
                continue

            reasoning = await self._explain(text, score)
            severity = _map_severity(score)
            findings.append(
                self._make_finding(
                    tool=tool,
                    field=field_name,
                    evidence=f"score={score:.2f} | {_truncate(text)}",
                    message=(
                        f"Semantic classifier flagged content "
                        f"(score: {score:.2f}). {reasoning}"
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=False,
                    severity=severity,
                )
            )
        return findings

    async def _classify(self, text: str) -> float:
        """Return malicious probability 0.0–1.0 from the prompt-guard model."""
        raw = await groq_call(
            model=self.classifier_model,
            messages=[{"role": "user", "content": text}],
            api_key=self._api_key,
            max_tokens=8,
        )
        return _parse_classifier_label(raw or "")

    async def _explain(self, text: str, score: float) -> str:
        """Short human-readable reasoning from the larger model."""
        prompt = (
            f"This MCP tool field was flagged as potentially malicious "
            f"(classifier confidence: {score:.2f}).\n\n"
            f"Field content:\n{text}\n\n"
            f"In 2 sentences, explain what makes it suspicious. "
            f"If on reflection it looks clean, say so."
        )
        reply = await groq_call(
            model=self.reasoning_model,
            messages=[{"role": "user", "content": prompt}],
            api_key=self._api_key,
            max_tokens=200,
        )
        if not reply:
            return "Reasoning unavailable (LLM call failed)."
        return reply.strip()
