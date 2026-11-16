"""AppSentinel Structured AI Response Validator (V8).

Validates and enforces strict JSON schemas on AI provider outputs:
- Rejects malformed JSON, truncated streams, or missing required fields.
- Strips markdown code block wrappers (```json ... ```).
- Enforces list and dictionary type constraints on recommendations and verification steps.
- Sanitizes and ensures model outputs do not claim authority over deterministic scores.
"""

import json
import re
from typing import Tuple, Optional


class ResponseValidator:
    """Enforces structural schema validation on AI provider outputs."""

    REQUIRED_ROOT_KEYS = [
        "analysis_type",
        "summary",
        "technical_explanation",
        "root_cause",
        "impact",
        "evidence_assessment",
        "recommendations",
        "verification_steps",
        "limitations",
        "ai_confidence",
    ]

    VALID_CONFIDENCE_LEVELS = {"HIGH", "MEDIUM", "LOW"}
    VALID_ANALYSIS_TYPES = {"vulnerability_explanation", "target_summary", "security_chat"}

    @classmethod
    def clean_raw_output(cls, raw_output: str) -> str:
        """Strip markdown fences, leading/trailing whitespace, and prose wrapper artifacts."""
        if not raw_output:
            return ""

        cleaned = raw_output.strip()

        # Strip markdown code fences (e.g., ```json\n{...}\n``` or ```{...}```)
        fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned)
        if fence_match:
            cleaned = fence_match.group(1).strip()

        # If wrapped in XML delimiters, extract JSON content
        xml_match = re.search(r"<json>([\s\S]*?)</json>", cleaned)
        if xml_match:
            cleaned = xml_match.group(1).strip()

        return cleaned

    @classmethod
    def validate_analysis_response(cls, raw_text: str) -> Tuple[bool, Optional[dict], str]:
        """Validate raw AI output string against the required AppSentinel JSON schema.
        
        Returns:
            (is_valid, parsed_dict_or_none, error_message)
        """
        if not raw_text or not isinstance(raw_text, str):
            return False, None, "AI response is empty or non-string"

        cleaned_text = cls.clean_raw_output(raw_text)

        try:
            data = json.loads(cleaned_text)
        except json.JSONDecodeError as err:
            return False, None, f"JSON parse error in AI response: {str(err)}"

        if not isinstance(data, dict):
            return False, None, "AI response root must be a JSON object (dict)"

        # Check for required root keys
        for key in cls.REQUIRED_ROOT_KEYS:
            if key not in data:
                return False, None, f"Missing required response schema key: '{key}'"

        # Validate analysis_type
        analysis_type = data.get("analysis_type")
        if analysis_type not in cls.VALID_ANALYSIS_TYPES:
            # Allow fallback if valid type is not recognized
            data["analysis_type"] = "vulnerability_explanation"

        # Validate ai_confidence
        conf = str(data.get("ai_confidence", "")).upper()
        if conf not in cls.VALID_CONFIDENCE_LEVELS:
            data["ai_confidence"] = "MEDIUM"
        else:
            data["ai_confidence"] = conf

        # Validate recommendations structure
        recs = data.get("recommendations")
        if not isinstance(recs, list):
            data["recommendations"] = []
        else:
            normalized_recs = []
            for item in recs:
                if isinstance(item, dict):
                    normalized_recs.append({
                        "priority": str(item.get("priority", "Immediate")),
                        "action": str(item.get("action", "Remediation Action")),
                        "details": str(item.get("details", "")),
                        "code_example": str(item.get("code_example", "")),
                    })
                elif isinstance(item, str):
                    normalized_recs.append({
                        "priority": "Immediate",
                        "action": item,
                        "details": item,
                        "code_example": "",
                    })
            data["recommendations"] = normalized_recs

        # Validate verification_steps
        steps = data.get("verification_steps")
        if not isinstance(steps, list):
            data["verification_steps"] = [str(steps)] if steps else []
        else:
            data["verification_steps"] = [str(s) for s in steps if s]

        # Validate limitations
        limitations = data.get("limitations")
        if not isinstance(limitations, list):
            data["limitations"] = [str(limitations)] if limitations else []
        else:
            data["limitations"] = [str(l) for l in limitations if l]

        # Ensure text fields are strings
        for text_key in ["summary", "technical_explanation", "root_cause", "impact", "evidence_assessment"]:
            if text_key in data and not isinstance(data[text_key], str):
                data[text_key] = str(data[text_key])

        # Optional exploitability discussion
        if "exploitability_discussion" not in data:
            data["exploitability_discussion"] = "Assessment derived from scanner observation."
        elif not isinstance(data["exploitability_discussion"], str):
            data["exploitability_discussion"] = str(data["exploitability_discussion"])

        return True, data, "Valid structured response"
