"""S6 — Input Schema Weakness Detector.

Unlike the text-based detectors, S6 walks the tool's JSON-Schema input
definition and flags structural weaknesses that enable downstream attacks:

- A. Unbounded strings on risky params (path, file, cmd, query, url, sql, exec)
     with no maxLength and no pattern → MEDIUM.
- B. Sensitive parameter names (password, secret, token, api_key, credential)
     → INFO. Clients should inject auth; MCP tools should not accept secrets.
- C. additionalProperties: true (or unset) → MEDIUM. Permits arbitrary
     extra fields beyond the declared schema.
- D. Schema declares properties but no `required` array → LOW.

References:
- JSON Schema 2020-12 §10.3.2.3 (additionalProperties default behavior).
- MCP server-author guidance, "Strict schemas for tool inputs", 2025.
"""
import re

from ..base import Detector
from ...models import Finding, Severity, ToolInfo


_RISKY_PARAM_NAME = re.compile(r"path|file|cmd|command|query|url|sql|exec", re.IGNORECASE)
_SECRET_PARAM_NAME = re.compile(r"password|secret|token|api_key|credential", re.IGNORECASE)


class SchemaValidatorDetector(Detector):
    rule_id = "S6"
    severity = Severity.MEDIUM  # default; some sub-checks override
    description = "Detects weak or permissive JSON-Schema definitions on tool inputs."

    _FIX_UNBOUNDED = (
        "Add maxLength and/or pattern constraints to risky string parameters "
        "to limit injection payload size."
    )
    _FIX_SECRET = (
        "MCP tools should not accept secrets as parameters; the client should "
        "inject auth headers/credentials instead."
    )
    _FIX_ADDITIONAL = (
        "Set additionalProperties: false on the input schema to reject "
        "unexpected fields."
    )
    _FIX_REQUIRED = (
        "Declare a `required` array on the input schema so callers cannot "
        "omit mandatory fields."
    )

    def check(self, tool: ToolInfo) -> list[Finding]:
        findings: list[Finding] = []
        schema = tool.input_schema or {}
        props = schema.get("properties", {}) if isinstance(schema, dict) else {}

        # A + B: per-property checks
        for pname, pdef in props.items():
            if not isinstance(pdef, dict):
                continue
            ptype = pdef.get("type")
            field = f"param:{pname}"

            # Check A — unbounded risky string
            if (
                ptype == "string"
                and _RISKY_PARAM_NAME.search(pname)
                and "maxLength" not in pdef
                and "pattern" not in pdef
            ):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.MEDIUM,
                        tool_name=tool.name,
                        field=field,
                        evidence=f"Parameter '{pname}' is unbounded string with no validation",
                        message=(
                            f"Risky parameter '{pname}' is an unbounded string "
                            f"with no maxLength or pattern constraint."
                        ),
                        suggested_fix=self._FIX_UNBOUNDED,
                    )
                )

            # Check B — sensitive parameter name (always informational)
            if _SECRET_PARAM_NAME.search(pname):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=Severity.INFO,
                        tool_name=tool.name,
                        field=field,
                        evidence=f"Parameter '{pname}' looks like a secret",
                        message=(
                            f"Parameter '{pname}' appears to accept a secret. "
                            "Secrets should be injected by the client, not "
                            "passed as tool inputs."
                        ),
                        suggested_fix=self._FIX_SECRET,
                    )
                )

        # Check C — additionalProperties not explicitly false
        if isinstance(schema, dict) and schema.get("additionalProperties") is not False:
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.MEDIUM,
                    tool_name=tool.name,
                    field="input_schema",
                    evidence="additionalProperties is not False",
                    message=(
                        "Input schema permits arbitrary extra properties "
                        "(additionalProperties defaults to true)."
                    ),
                    suggested_fix=self._FIX_ADDITIONAL,
                )
            )

        # Check D — properties present but no required array
        if props and not schema.get("required"):
            findings.append(
                Finding(
                    rule_id=self.rule_id,
                    severity=Severity.LOW,
                    tool_name=tool.name,
                    field="input_schema",
                    evidence="no `required` array",
                    message="Input schema declares properties but no `required` array.",
                    suggested_fix=self._FIX_REQUIRED,
                )
            )

        return self._dedupe(findings)
