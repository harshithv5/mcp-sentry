"""D3 — Path Traversal detector.

Probes file/path-shaped parameters with classic traversal payloads (../etc/passwd,
../.ssh/id_rsa, file:///etc/passwd, etc.) and inspects the response for content
fingerprints of the targeted files. A confirmed hit (CRITICAL) means the server
actually returned sensitive file content; a suspected hit (HIGH) means the
server accepted the payload without raising any error, which is itself a strong
indicator of broken input validation.

Tools with no path-like parameter are skipped silently.

References:
- OWASP, "Path Traversal", 2024.
- CWE-22: Improper Limitation of a Pathname to a Restricted Directory.
"""
import asyncio
import logging

from mcp import ClientSession

from ..base import DynamicDetector
from ...models import Finding, Severity, ToolInfo
from ...safety import (
    extract_response_text,
    generate_safe_inputs,
    inject_probe,
    looks_like_error,
    rate_limited_call,
)


logger = logging.getLogger(__name__)


PATH_PARAM_NAMES: tuple[str, ...] = (
    "path", "file", "filename", "filepath", "file_path",
    "dir", "directory", "folder", "location", "resource",
)

PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../.env",
    "../../../.ssh/id_rsa",
    "../../.aws/credentials",
    "file:///etc/passwd",
)

# Content fingerprints — strings that almost certainly appear in the targeted
# file and almost certainly don't appear in a generic error message.
FILE_MARKERS: dict[str, tuple[str, ...]] = {
    "passwd": ("root:x:0:0", "root:x:", "/bin/bash", "daemon:x:"),
    "ssh": (
        "-----BEGIN RSA",
        "-----BEGIN OPENSSH",
        "-----BEGIN PRIVATE KEY",
    ),
    "aws": ("aws_access_key_id", "aws_secret_access_key"),
    "env": ("API_KEY=", "SECRET_KEY=", "DATABASE_URL=", "OPENAI_API_KEY="),
}


def _match_file_marker(response: str) -> tuple[str, str] | None:
    """Return (category, marker) of the first FILE_MARKERS hit, else None."""
    lowered = response.lower()
    for category, markers in FILE_MARKERS.items():
        for marker in markers:
            if marker.lower() in lowered:
                return category, marker
    return None


class PathTraversalDetector(DynamicDetector):
    rule_id = "D3"
    severity = Severity.CRITICAL
    description = "Probes path parameters for directory traversal vulnerabilities."

    _SUGGESTED_FIX = (
        "Validate and canonicalize path inputs server-side. Reject any path "
        "that escapes the intended root directory after resolution, and "
        "reject 'file://' and other non-filesystem URI schemes."
    )

    async def check(self, tool: ToolInfo, session: ClientSession) -> list[Finding]:
        try:
            base = generate_safe_inputs(tool)
            for payload in PAYLOADS:
                probed = inject_probe(
                    tool, base, payload,
                    target_param_type="string",
                    name_filter=PATH_PARAM_NAMES,
                )
                if probed is None:
                    return []  # tool has no path-like param; nothing to probe

                result = await rate_limited_call(session, tool.name, probed)
                if result is None:
                    continue

                response = extract_response_text(result)
                if not response:
                    continue

                hit = _match_file_marker(response)
                if hit is not None:
                    category, marker = hit
                    return [
                        self._make_finding(
                            tool=tool,
                            field="response",
                            evidence=(
                                f"Payload '{payload}' returned {category} "
                                f"content containing '{marker}'"
                            ),
                            message=(
                                f"Tool returned sensitive file content for "
                                f"traversal payload '{payload}'. The server "
                                f"reads attacker-controlled paths without "
                                f"validation."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                            confirmed=True,
                            severity=Severity.CRITICAL,
                        )
                    ]

                if not looks_like_error(response):
                    return [
                        self._make_finding(
                            tool=tool,
                            field="response",
                            evidence=(
                                f"Payload '{payload}' accepted without error "
                                f"(response length {len(response)})"
                            ),
                            message=(
                                f"Tool accepted traversal payload '{payload}' "
                                f"without raising an error. Cannot confirm file "
                                f"disclosure but input validation is missing."
                            ),
                            suggested_fix=self._SUGGESTED_FIX,
                            confirmed=False,
                            severity=Severity.HIGH,
                        )
                    ]

            return []
        except (asyncio.TimeoutError, ConnectionError) as exc:
            logger.debug("D3 skipped %s (transport): %s", tool.name, exc)
            return []
        except Exception as exc:
            logger.debug("D3 skipped %s (tool error): %s", tool.name, exc)
            return []
