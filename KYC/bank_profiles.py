from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class BankAttestationView:
    provider_id: str
    bank_customer_id: str
    email: str
    nationality: str
    attestation_nonce: str


class BankProfile:
    name = "generic"

    def validate(self, req: BankAttestationView) -> Tuple[bool, str]:
        if not req.bank_customer_id:
            return False, "bank_customer_id is required"
        if not req.email or "@" not in req.email:
            return False, "email must be valid"
        if not re.fullmatch(r"[A-Z]{3}", req.nationality.upper()):
            return False, "nationality must be ISO-3 uppercase"
        return True, "ok"


class SepaRetailProfile(BankProfile):
    name = "sepa_retail"

    def validate(self, req: BankAttestationView) -> Tuple[bool, str]:
        ok, reason = super().validate(req)
        if not ok:
            return ok, reason
        if not req.bank_customer_id.startswith("SEPA-"):
            return False, "bank_customer_id must start with SEPA- for sepa_retail profile"
        return True, "ok"


class SwiftCorporateProfile(BankProfile):
    name = "swift_corporate"

    def validate(self, req: BankAttestationView) -> Tuple[bool, str]:
        ok, reason = super().validate(req)
        if not ok:
            return ok, reason
        if not req.bank_customer_id.startswith("SWIFT-"):
            return False, "bank_customer_id must start with SWIFT- for swift_corporate profile"
        return True, "ok"


class OpenBankingPsd2Profile(BankProfile):
    name = "open_banking_psd2"

    def validate(self, req: BankAttestationView) -> Tuple[bool, str]:
        ok, reason = super().validate(req)
        if not ok:
            return ok, reason
        if not req.attestation_nonce.startswith("psd2_"):
            return False, "attestation_nonce must start with psd2_ for open_banking_psd2 profile"
        return True, "ok"


PROFILE_REGISTRY: Dict[str, BankProfile] = {
    "generic": BankProfile(),
    "sepa_retail": SepaRetailProfile(),
    "swift_corporate": SwiftCorporateProfile(),
    "open_banking_psd2": OpenBankingPsd2Profile(),
}


def provider_profile_map_from_env() -> Dict[str, str]:
    try:
        raw = json.loads(os.environ.get("BANK_PROVIDER_PROFILES_JSON", "{}"))
    except json.JSONDecodeError:
        return {}
    if not isinstance(raw, dict):
        return {}
    return {str(provider): str(profile) for provider, profile in raw.items()}


def resolve_profile(provider_id: str, provider_map: Dict[str, str]) -> BankProfile:
    profile_name = provider_map.get(provider_id, "generic")
    return PROFILE_REGISTRY.get(profile_name, PROFILE_REGISTRY["generic"])


def validate_provider_request(
    provider_id: str,
    bank_customer_id: str,
    email: str,
    nationality: str,
    attestation_nonce: str,
    provider_map: Dict[str, str],
) -> Tuple[bool, str, str]:
    profile = resolve_profile(provider_id, provider_map)
    view = BankAttestationView(
        provider_id=provider_id,
        bank_customer_id=bank_customer_id,
        email=email,
        nationality=nationality,
        attestation_nonce=attestation_nonce,
    )
    ok, reason = profile.validate(view)
    return ok, reason, profile.name
