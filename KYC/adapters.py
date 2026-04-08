from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class KYCRecord:
    user_key_image: str
    bank_customer_id: Optional[str]
    first_name: str
    last_name: str
    email: str
    date_of_birth: str
    nationality: str
    kyc_status: str
    source: str
    updated_at: int


class KYCAdapter(ABC):
    @abstractmethod
    def get_by_user_key_image(self, user_key_image: str) -> Optional[KYCRecord]:
        raise NotImplementedError

    @abstractmethod
    def get_by_bank_customer_id(self, bank_customer_id: str) -> Optional[KYCRecord]:
        raise NotImplementedError

    @abstractmethod
    def upsert(self, record: KYCRecord) -> KYCRecord:
        raise NotImplementedError

    @abstractmethod
    def register_bank_attestation_nonce(self, provider_id: str, nonce: str, issued_at: int) -> bool:
        raise NotImplementedError


class DBKYCAdapter(KYCAdapter):
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bank_kyc_links (
                    bank_customer_id TEXT PRIMARY KEY,
                    user_key_image TEXT NOT NULL,
                    updated_at INTEGER NOT NULL,
                    metadata_json TEXT NOT NULL DEFAULT '{}'
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS bank_attestation_nonces (
                    provider_id TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    issued_at INTEGER NOT NULL,
                    PRIMARY KEY (provider_id, nonce)
                )
                """
            )

    def _row_to_record(self, row: sqlite3.Row, source: str) -> KYCRecord:
        return KYCRecord(
            user_key_image=row["key_image_hex"],
            bank_customer_id=row["bank_customer_id"] if "bank_customer_id" in row.keys() else None,
            first_name=row["first_name"],
            last_name=row["last_name"],
            email=row["email"],
            date_of_birth=row["date_of_birth"],
            nationality=row["nationality"],
            kyc_status="verified",
            source=source,
            updated_at=int(row["updated_at"]),
        )

    def get_by_user_key_image(self, user_key_image: str) -> Optional[KYCRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.key_image_hex, u.first_name, u.last_name, u.email, u.date_of_birth, u.nationality,
                       COALESCE(MAX(b.bank_customer_id), '') AS bank_customer_id,
                       CAST(strftime('%s','now') AS INTEGER) AS updated_at
                FROM users u
                LEFT JOIN bank_kyc_links b ON b.user_key_image = u.key_image_hex
                WHERE u.key_image_hex = ?1
                GROUP BY u.key_image_hex
                """,
                (user_key_image,),
            ).fetchone()
            if row is None:
                return None
            rec = self._row_to_record(row, source="db")
            if rec.bank_customer_id == "":
                rec.bank_customer_id = None
            return rec

    def get_by_bank_customer_id(self, bank_customer_id: str) -> Optional[KYCRecord]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT u.key_image_hex, u.first_name, u.last_name, u.email, u.date_of_birth, u.nationality,
                       b.bank_customer_id,
                       b.updated_at
                FROM bank_kyc_links b
                JOIN users u ON u.key_image_hex = b.user_key_image
                WHERE b.bank_customer_id = ?1
                """,
                (bank_customer_id,),
            ).fetchone()
            if row is None:
                return None
            return self._row_to_record(row, source="bank_link")

    def upsert(self, record: KYCRecord) -> KYCRecord:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO users
                (key_image_hex, public_key_hex, first_name, last_name, email, date_of_birth, nationality)
                VALUES (?1, COALESCE((SELECT public_key_hex FROM users WHERE key_image_hex = ?1), ''), ?2, ?3, ?4, ?5, ?6)
                """,
                (
                    record.user_key_image,
                    record.first_name,
                    record.last_name,
                    record.email,
                    record.date_of_birth,
                    record.nationality,
                ),
            )

            if record.bank_customer_id:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO bank_kyc_links
                    (bank_customer_id, user_key_image, updated_at, metadata_json)
                    VALUES (?1, ?2, ?3, ?4)
                    """,
                    (
                        record.bank_customer_id,
                        record.user_key_image,
                        record.updated_at,
                        json.dumps({"source": record.source}),
                    ),
                )

        return record

    def register_bank_attestation_nonce(self, provider_id: str, nonce: str, issued_at: int) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM bank_attestation_nonces WHERE provider_id = ?1 AND nonce = ?2",
                (provider_id, nonce),
            ).fetchone()
            if row is not None and int(row[0]) > 0:
                return False
            conn.execute(
                "INSERT INTO bank_attestation_nonces (provider_id, nonce, issued_at) VALUES (?1, ?2, ?3)",
                (provider_id, nonce, issued_at),
            )
            return True


class BankKYCAdapter(KYCAdapter):
    """
    Bank-mode adapter.

    For now this uses the same DB-backed storage plus bank-customer links.
    It keeps the interface contract stable for swapping in a real bank connector.
    """

    def __init__(self, db_path: str):
        self.delegate = DBKYCAdapter(db_path)

    def get_by_user_key_image(self, user_key_image: str) -> Optional[KYCRecord]:
        rec = self.delegate.get_by_user_key_image(user_key_image)
        if rec is not None:
            rec.source = "bank"
        return rec

    def get_by_bank_customer_id(self, bank_customer_id: str) -> Optional[KYCRecord]:
        rec = self.delegate.get_by_bank_customer_id(bank_customer_id)
        if rec is not None:
            rec.source = "bank"
        return rec

    def upsert(self, record: KYCRecord) -> KYCRecord:
        record.source = "bank"
        return self.delegate.upsert(record)

    def register_bank_attestation_nonce(self, provider_id: str, nonce: str, issued_at: int) -> bool:
        return self.delegate.register_bank_attestation_nonce(provider_id, nonce, issued_at)
