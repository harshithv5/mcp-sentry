from enum import Enum
from pydantic import BaseModel

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ToolInfo(BaseModel):
    name: str
    description: str = ""
    input_schema: dict = {}

    @property
    def parameter_descriptions(self) -> list[str]:
        props = self.input_schema.get("properties", {})
        return [
            v.get("description", "")
            for v in props.values()
            if isinstance(v, dict) and v.get("description")
        ]

    @property
    def all_text_fields(self) -> list[str]:
        return [self.name, self.description] + self.parameter_descriptions

    @property
    def labelled_text_fields(self) -> list[tuple[str, str]]:
        """(field_name, text) pairs for every human-readable string on this tool."""
        pairs: list[tuple[str, str]] = [
            ("name", self.name),
            ("description", self.description),
        ]
        for pname, pdef in self.input_schema.get("properties", {}).items():
            if isinstance(pdef, dict) and pdef.get("description"):
                pairs.append((f"param:{pname}", pdef["description"]))
        return pairs

class Finding(BaseModel):
    rule_id: str
    severity: Severity
    tool_name: str
    field: str           # which tool field triggered the finding (name/description/param:x/server/response)
    evidence: str        # the actual text that triggered the finding
    message: str         # human readable explanation
    suggested_fix: str   # what to do about it
    confirmed: bool = False  # True for dynamic findings (proven by live probe), False for static (suspected)

class ScanReport(BaseModel):
    target_url: str
    tool_count: int
    findings: list[Finding]
    score: int           # 0-100
    grade: str           # A+ through F
    scan_duration_ms: int
    notes: list[str] = []  # operational notes (e.g. "dynamic phase skipped: auth required")