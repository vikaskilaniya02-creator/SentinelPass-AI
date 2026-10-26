"""Treat AI output as UNTRUSTED. Only a strict, small, text-only shape is accepted.

AI can explain, classify and recommend. It can NOT execute code, touch the
database, unlock accounts or change settings: the output is never evaluated and
is only ever displayed after passing this validator.
"""
from __future__ import annotations

import json
import re
from typing import Any

from exceptions import AIOutputError

MAX_EXPLANATION = 500
MAX_RECS, MAX_REC_LEN = 6, 200

_BLOCKED = re.compile(
    r"(https?://|www\.|```|`|<\s*/?\s*script|\$\(|&&|\|\||\brm\s+-rf\b|\bsudo\b|\bchmod\b|\bcurl\b|\bwget\b|"
    r"\bpowershell\b|\bos\.system\b|\bsubprocess\b|\beval\s*\(|\bexec\s*\(|\bdrop\s+table\b|\bdelete\s+from\b|"
    r"ignore (all |any )?(previous|prior) instructions|system prompt)", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _clean(text: str, limit: int) -> str:
    return _CONTROL.sub("", text).strip()[:limit]


def validate_output(raw: Any, allowed_risks: tuple[str, ...]) -> dict:
    if isinstance(raw, str):
        text = raw.strip()
        text = re.sub(r"^```(?:json)?|```$", "", text, flags=re.MULTILINE).strip()
        try:
            raw = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AIOutputError("AI output is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise AIOutputError("AI output must be a JSON object")

    risk = str(raw.get("risk", "")).upper()
    if risk not in allowed_risks:
        raise AIOutputError("AI risk label not allowed")
    explanation = raw.get("explanation")
    if not isinstance(explanation, str) or not explanation.strip():
        raise AIOutputError("AI explanation missing")
    explanation = _clean(explanation, MAX_EXPLANATION)
    if _BLOCKED.search(explanation):
        raise AIOutputError("AI explanation contained blocked content")

    recs_in = raw.get("recommendations", [])
    if not isinstance(recs_in, list):
        raise AIOutputError("AI recommendations must be a list")
    recs = []
    for item in recs_in:
        if isinstance(item, str):
            item = _clean(item, MAX_REC_LEN)
            if item and not _BLOCKED.search(item):
                recs.append(item)
    # Unknown extra keys are silently dropped: only these three fields ever pass through.
    return {"risk": risk, "explanation": explanation, "recommendations": recs[:MAX_RECS]}
