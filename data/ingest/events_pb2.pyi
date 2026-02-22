from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ActionType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ACTION_UNKNOWN: _ClassVar[ActionType]
    ACTION_TRANSACTION: _ClassVar[ActionType]
    ACTION_LOGIN_ATTEMPT: _ClassVar[ActionType]
    ACTION_API_CALL: _ClassVar[ActionType]

class RiskLevel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    RISK_PASS: _ClassVar[RiskLevel]
    RISK_WATCH: _ClassVar[RiskLevel]
    RISK_BLOCK: _ClassVar[RiskLevel]
ACTION_UNKNOWN: ActionType
ACTION_TRANSACTION: ActionType
ACTION_LOGIN_ATTEMPT: ActionType
ACTION_API_CALL: ActionType
RISK_PASS: RiskLevel
RISK_WATCH: RiskLevel
RISK_BLOCK: RiskLevel

class Event(_message.Message):
    __slots__ = ("company_id", "user_id", "action_type", "amount_usd", "timestamp_ms", "credit_balance", "auth_failed")
    COMPANY_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ACTION_TYPE_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_USD_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    CREDIT_BALANCE_FIELD_NUMBER: _ClassVar[int]
    AUTH_FAILED_FIELD_NUMBER: _ClassVar[int]
    company_id: int
    user_id: int
    action_type: ActionType
    amount_usd: float
    timestamp_ms: int
    credit_balance: float
    auth_failed: bool
    def __init__(self, company_id: _Optional[int] = ..., user_id: _Optional[int] = ..., action_type: _Optional[_Union[ActionType, str]] = ..., amount_usd: _Optional[float] = ..., timestamp_ms: _Optional[int] = ..., credit_balance: _Optional[float] = ..., auth_failed: bool = ...) -> None: ...

class Decision(_message.Message):
    __slots__ = ("company_id", "user_id", "timestamp_ms", "risk_level", "is_fraud", "fraud_score", "z_score", "reason", "credit_balance")
    COMPANY_ID_FIELD_NUMBER: _ClassVar[int]
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_MS_FIELD_NUMBER: _ClassVar[int]
    RISK_LEVEL_FIELD_NUMBER: _ClassVar[int]
    IS_FRAUD_FIELD_NUMBER: _ClassVar[int]
    FRAUD_SCORE_FIELD_NUMBER: _ClassVar[int]
    Z_SCORE_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    CREDIT_BALANCE_FIELD_NUMBER: _ClassVar[int]
    company_id: int
    user_id: int
    timestamp_ms: int
    risk_level: RiskLevel
    is_fraud: bool
    fraud_score: float
    z_score: float
    reason: str
    credit_balance: float
    def __init__(self, company_id: _Optional[int] = ..., user_id: _Optional[int] = ..., timestamp_ms: _Optional[int] = ..., risk_level: _Optional[_Union[RiskLevel, str]] = ..., is_fraud: bool = ..., fraud_score: _Optional[float] = ..., z_score: _Optional[float] = ..., reason: _Optional[str] = ..., credit_balance: _Optional[float] = ...) -> None: ...

class EventBatch(_message.Message):
    __slots__ = ("events",)
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[Event]
    def __init__(self, events: _Optional[_Iterable[_Union[Event, _Mapping]]] = ...) -> None: ...
