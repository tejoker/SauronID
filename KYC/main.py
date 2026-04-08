import os
import time
import json
import hmac
import hashlib

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from adapters import BankKYCAdapter, DBKYCAdapter, KYCRecord, KYCAdapter
from bank_profiles import provider_profile_map_from_env, validate_provider_request

app = FastAPI(title="KYC Adapter Service", version="3.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


def _build_adapter() -> KYCAdapter:
    adapter_type = os.getenv("KYC_ADAPTER", "db").strip().lower()
    db_path = os.getenv("KYC_DB_PATH", os.getenv("DATABASE_PATH", "./sauron.db"))
    if adapter_type == "bank":
        return BankKYCAdapter(db_path)
    return DBKYCAdapter(db_path)


ADAPTER = _build_adapter()
PROVIDER_PROFILE_MAP = provider_profile_map_from_env()


class KYCUpsertRequest(BaseModel):
    user_key_image: str
    bank_customer_id: str | None = None
    first_name: str
    last_name: str
    email: str
    date_of_birth: str
    nationality: str
    kyc_status: str = "verified"
    source: str = "bank"
    provider_id: str | None = None
    attestation_signature: str | None = None
    attestation_issued_at: int | None = None
    attestation_nonce: str | None = None


def _bank_provider_secrets() -> dict[str, str]:
    raw = os.getenv("BANK_PROVIDER_SECRETS_JSON", "{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(k): str(v) for k, v in parsed.items() if str(v)}


def _attestation_payload(req: KYCUpsertRequest) -> str:
    return "|".join(
        [
            req.provider_id or "",
            req.bank_customer_id or "",
            req.user_key_image,
            req.first_name,
            req.last_name,
            req.email,
            req.date_of_birth,
            req.nationality,
            str(req.attestation_issued_at or 0),
            req.attestation_nonce or "",
        ]
    )


def _verify_bank_attestation(req: KYCUpsertRequest) -> tuple[bool, str]:
    if not req.provider_id:
        return False, "provider_id is required in bank mode"
    if not req.attestation_signature:
        return False, "attestation_signature is required in bank mode"
    if not req.attestation_nonce:
        return False, "attestation_nonce is required in bank mode"
    if not req.attestation_issued_at:
        return False, "attestation_issued_at is required in bank mode"

    now = int(time.time())
    if abs(now - int(req.attestation_issued_at)) > 300:
        return False, "attestation_issued_at outside allowed 5-minute skew"

    secrets = _bank_provider_secrets()
    secret = secrets.get(req.provider_id)
    if not secret:
        return False, "unknown provider_id"

    ok, reason, profile_name = validate_provider_request(
        req.provider_id,
        req.bank_customer_id or "",
        req.email,
        req.nationality.upper(),
        req.attestation_nonce,
        PROVIDER_PROFILE_MAP,
    )
    if not ok:
        return False, f"profile validation failed ({profile_name}): {reason}"

    payload = _attestation_payload(req).encode("utf-8")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, req.attestation_signature):
        return False, "invalid bank attestation signature"

    return True, "ok"


def _record_to_json(record: KYCRecord) -> dict:
    return {
        "user_key_image": record.user_key_image,
        "bank_customer_id": record.bank_customer_id,
        "first_name": record.first_name,
        "last_name": record.last_name,
        "email": record.email,
        "date_of_birth": record.date_of_birth,
        "nationality": record.nationality,
        "kyc_status": record.kyc_status,
        "source": record.source,
        "updated_at": record.updated_at,
    }


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "kyc-adapter",
        "adapter": os.getenv("KYC_ADAPTER", "db").strip().lower(),
        "provider_profiles": PROVIDER_PROFILE_MAP,
    }


@app.get("/api/kyc/by-user/{user_key_image}")
async def get_kyc_by_user(user_key_image: str):
    record = ADAPTER.get_by_user_key_image(user_key_image)
    if record is None:
        raise HTTPException(status_code=404, detail="KYC record not found")
    return _record_to_json(record)


@app.get("/api/kyc/by-bank/{bank_customer_id}")
async def get_kyc_by_bank(bank_customer_id: str):
    record = ADAPTER.get_by_bank_customer_id(bank_customer_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Bank-linked KYC record not found")
    return _record_to_json(record)


@app.post("/api/kyc/upsert")
async def upsert_kyc(request: KYCUpsertRequest):
    if request.kyc_status.lower() != "verified":
        raise HTTPException(status_code=400, detail="Only verified KYC records are accepted")

    if isinstance(ADAPTER, BankKYCAdapter):
        ok, reason = _verify_bank_attestation(request)
        if not ok:
            raise HTTPException(status_code=401, detail=reason)
        inserted = ADAPTER.register_bank_attestation_nonce(
            request.provider_id or "",
            request.attestation_nonce or "",
            int(request.attestation_issued_at or 0),
        )
        if not inserted:
            raise HTTPException(status_code=409, detail="Replay detected for bank attestation nonce")

    record = KYCRecord(
        user_key_image=request.user_key_image,
        bank_customer_id=request.bank_customer_id,
        first_name=request.first_name,
        last_name=request.last_name,
        email=request.email,
        date_of_birth=request.date_of_birth,
        nationality=request.nationality,
        kyc_status="verified",
        source=request.source,
        updated_at=int(time.time()),
    )
    saved = ADAPTER.upsert(record)
    return {"saved": True, "record": _record_to_json(saved)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
