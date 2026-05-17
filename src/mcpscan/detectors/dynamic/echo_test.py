"""D1 — Echo Test detector.

Sends a unique, random marker through one of the tool's string parameters and
checks whether that marker appears verbatim in the tool's response. If it
does, the tool reflects user input into the LLM-visible response surface — an
attacker can therefore smuggle arbitrary instructions through tool arguments
and have them executed by the host agent (indirect prompt injection through
reflection).

The marker is a UUID-suffixed sentinel: false-positive risk is essentially
zero — no legitimate tool would coincidentally return a fresh UUID.

References:
- Greshake et al., "Not what you've signed up for: Compromising Real-World
  LLM-Integrated Applications with Indirect Prompt Injection", 2023.
- OWASP LLM Top 10, LLM01: Prompt Injection (reflection sub-pattern).
"""
import asyncio
import logging
import uuid

from mcp import ClientSession

from ..base import DynamicDetector
from ...models import Finding, Severity, ToolInfo
from ...safety import (
    extract_response_text,
    generate_safe_inputs,
    inject_probe,
    rate_limited_call,
)


logger = logging.getLogger(__name__)


class EchoTestDetector(DynamicDetector):
    rule_id = "D1"
    severity = Severity.HIGH
    description = "Detects tools that reflect user input back into their response."

    _SUGGESTED_FIX = (
        "Tool responses should be generated from server-side data, not by "
        "reflecting user input. Sanitize or exclude user input from responses."
    )

    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        try:
            marker = f"MCPSCAN_ECHO_PROBE_{uuid.uuid4().hex}"

            base_inputs = generate_safe_inputs(tool)
            probed = inject_probe(tool, base_inputs, marker, target_param_type="string")
            if probed is None:
                return []  # no string parameter to probe through

            result = await rate_limited_call(session, tool.name, probed)
            if result is None:
                return []  # timeout — skip cleanly

            response_text = extract_response_text(result)
            if marker not in response_text:
                return []

            return [
                self._make_finding(
                    tool=tool,
                    field="response",
                    evidence=f"Sent marker '{marker[:24]}...' — found in response",
                    message=(
                        "Tool echoes user input in its response. An attacker can "
                        "inject arbitrary instructions through tool arguments "
                        "that flow into the LLM's context."
                    ),
                    suggested_fix=self._SUGGESTED_FIX,
                    confirmed=True,
                )
            ]
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.debug("D1 skipped %s (transport): %s", tool.name, exc)
            return []
        except Exception as exc:
            logger.debug("D1 skipped %s (tool error): %s", tool.name, exc)
            return []
