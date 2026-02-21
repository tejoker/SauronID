import asyncio
import base64
import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import extract_id_fields, run_kyc

app = FastAPI(title="KYC Scan", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST"],
    allow_headers=["*"],
)


def _decode_image(data: str) -> bytes:
    if "," in data:
        data = data.split(",", 1)[1]
    return base64.b64decode(data)


class ScanRequest(BaseModel):
    id_image: str  # base64 (data URL or raw)


class KYCRequest(BaseModel):
    id_image: str
    selfie: str


@app.post("/api/kyc")
async def kyc(request: KYCRequest):
    try:
        id_bytes     = _decode_image(request.id_image)
        selfie_bytes = _decode_image(request.selfie)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image data. Expected base64.")

    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_kyc, id_bytes, selfie_bytes)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KYC pipeline error: {e}")

    f = result.extracted_fields
    return {
        "decision":             result.decision,
        "decision_reason":      result.decision_reason,
        "face_match_score":     result.face_match_score,
        "face_match_label":     result.face_match_label,
        "face_match_reasoning": result.raw_face_match.get("reasoning", ""),
        "extracted_fields": {
            "document_type":   f.document_type,
            "full_name":       f.full_name,
            "first_name":      f.first_name,
            "last_name":       f.last_name,
            "date_of_birth":   f.date_of_birth,
            "nationality":     f.nationality,
            "document_number": f.document_number,
            "expiry_date":     f.expiry_date,
            "gender":          f.gender,
        },
    }


@app.post("/api/scan")
async def scan(request: ScanRequest):
    try:
        image_bytes = _decode_image(request.id_image)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid image data. Expected base64.")

    try:
        loop = asyncio.get_event_loop()
        fields = await loop.run_in_executor(None, extract_id_fields, image_bytes)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {e}")

    return {
        "document_type":   fields.document_type,
        "full_name":       fields.full_name,
        "first_name":      fields.first_name,
        "last_name":       fields.last_name,
        "date_of_birth":   fields.date_of_birth,
        "nationality":     fields.nationality,
        "document_number": fields.document_number,
        "expiry_date":     fields.expiry_date,
        "gender":          fields.gender,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
