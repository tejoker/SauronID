import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional

from dotenv import load_dotenv
from google import genai
from google.genai import types

load_dotenv()

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")

_client: Optional[genai.Client] = None


def get_client() -> genai.Client:
    global _client
    if _client is None:
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise RuntimeError("GEMINI_API_KEY is not set in environment")
        _client = genai.Client(api_key=api_key)
    return _client


def _image_part(image_bytes: bytes, mime_type: str = "image/jpeg") -> types.Part:
    return types.Part.from_bytes(data=image_bytes, mime_type=mime_type)


def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return json.loads(text)


# ── Extracted fields ──────────────────────────────────────────────────────────

@dataclass
class ExtractedFields:
    document_type: str
    full_name: str
    first_name: str
    last_name: str
    date_of_birth: str
    nationality: str
    document_number: str
    expiry_date: str
    gender: Optional[str]
    extra: dict = field(default_factory=dict)


EXTRACTION_PROMPT = """
You are an expert identity document parser.
The image is an identity document (national ID, passport, or driver's license).

Extract the fields and return ONLY a valid JSON object — no markdown, no explanation:
{
  "document_type": "national_id | passport | drivers_license | unknown",
  "full_name": "LAST FIRST exactly as printed",
  "first_name": "given name(s) only",
  "last_name": "family name only",
  "date_of_birth": "YYYY-MM-DD",
  "nationality": "ISO 3-letter code e.g. FRA, DEU, GBR",
  "document_number": "...",
  "expiry_date": "YYYY-MM-DD",
  "gender": "M | F | X | null"
}

If a field is not visible, use null. Return nothing but the JSON.
"""


def extract_id_fields(id_image_bytes: bytes) -> ExtractedFields:
    client = get_client()
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=[EXTRACTION_PROMPT, _image_part(id_image_bytes)],
    )
    raw = _extract_json(response.text)

    full_name  = raw.get("full_name") or ""
    first_name = raw.get("first_name") or ""
    last_name  = raw.get("last_name") or ""

    if full_name and not (first_name and last_name):
        parts = full_name.strip().split()
        last_name  = parts[0] if parts else ""
        first_name = " ".join(parts[1:]) if len(parts) > 1 else ""

    return ExtractedFields(
        document_type=raw.get("document_type") or "unknown",
        full_name=full_name,
        first_name=first_name,
        last_name=last_name,
        date_of_birth=raw.get("date_of_birth") or "",
        nationality=raw.get("nationality") or "",
        document_number=raw.get("document_number") or "",
        expiry_date=raw.get("expiry_date") or "",
        gender=raw.get("gender"),
        extra={},
    )


# ── Face match ────────────────────────────────────────────────────────────────

@dataclass
class FaceMatchResult:
    match: bool
    confidence: float
    label: str          # high | medium | low | no_face_detected
    reasoning: str


FACE_MATCH_PROMPT = """
You are a biometric face-matching expert.
You are given TWO images:
  1. An identity document (national ID / passport / driver's license) — it contains a portrait photo.
  2. A live selfie of a person.

Determine whether BOTH images show the SAME person.

Return ONLY a valid JSON object — no markdown, no explanation:
{
  "match": true or false,
  "confidence": 0.0 to 1.0,
  "label": "high | medium | low | no_face_detected",
  "reasoning": "One concise sentence."
}

- "high"             : match=true and confidence >= 0.75
- "medium"           : confidence 0.40–0.74
- "low"              : confidence < 0.40 or match=false
- "no_face_detected" : face not found in one or both images

Be strict: different people must return match=false.
"""


def face_match(id_image_bytes: bytes, selfie_bytes: bytes) -> FaceMatchResult:
    client = get_client()
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=[
            FACE_MATCH_PROMPT,
            _image_part(id_image_bytes),
            _image_part(selfie_bytes),
        ],
    )
    raw = _extract_json(response.text)
    confidence = float(raw.get("confidence", 0.0))
    label = raw.get("label", "low") or "low"
    return FaceMatchResult(
        match=bool(raw.get("match", False)),
        confidence=confidence,
        label=label,
        reasoning=raw.get("reasoning", ""),
    )


# ── Full KYC pipeline ─────────────────────────────────────────────────────────

@dataclass
class KYCResult:
    decision: str           # pass | review | fail
    decision_reason: str
    face_match_score: float
    face_match_label: str
    raw_face_match: dict
    extracted_fields: ExtractedFields


def run_kyc(id_image_bytes: bytes, selfie_bytes: bytes) -> KYCResult:
    """Extract ID fields and compare faces — full KYC pipeline."""
    fields = extract_id_fields(id_image_bytes)
    fm = face_match(id_image_bytes, selfie_bytes)

    if fm.label == "no_face_detected":
        decision = "fail"
        reason = "Face could not be detected in one or both images."
    elif fm.match and fm.confidence >= 0.75:
        decision = "pass"
        reason = "Identity document verified and face matched successfully."
    elif fm.match and fm.confidence >= 0.40:
        decision = "review"
        reason = "Face match confidence is moderate — manual review recommended."
    else:
        decision = "fail"
        reason = "Face does not match the identity document."

    return KYCResult(
        decision=decision,
        decision_reason=reason,
        face_match_score=fm.confidence,
        face_match_label=fm.label,
        raw_face_match={"reasoning": fm.reasoning},
        extracted_fields=fields,
    )
