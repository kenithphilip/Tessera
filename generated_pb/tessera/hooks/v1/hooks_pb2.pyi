from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class PostPolicyEvaluateRequest(_message.Message):
    __slots__ = ("tool", "principal", "decision_kind", "reason", "required_trust", "observed_trust")
    TOOL_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    DECISION_KIND_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_TRUST_FIELD_NUMBER: _ClassVar[int]
    OBSERVED_TRUST_FIELD_NUMBER: _ClassVar[int]
    tool: str
    principal: str
    decision_kind: str
    reason: str
    required_trust: int
    observed_trust: int
    def __init__(self, tool: _Optional[str] = ..., principal: _Optional[str] = ..., decision_kind: _Optional[str] = ..., reason: _Optional[str] = ..., required_trust: _Optional[int] = ..., observed_trust: _Optional[int] = ...) -> None: ...

class PostPolicyEvaluateResponse(_message.Message):
    __slots__ = ("decision_kind", "reason")
    DECISION_KIND_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    decision_kind: str
    reason: str
    def __init__(self, decision_kind: _Optional[str] = ..., reason: _Optional[str] = ...) -> None: ...

class PostToolCallGateRequest(_message.Message):
    __slots__ = ("tool", "arguments_json", "principal")
    TOOL_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_JSON_FIELD_NUMBER: _ClassVar[int]
    PRINCIPAL_FIELD_NUMBER: _ClassVar[int]
    tool: str
    arguments_json: str
    principal: str
    def __init__(self, tool: _Optional[str] = ..., arguments_json: _Optional[str] = ..., principal: _Optional[str] = ...) -> None: ...

class PostToolCallGateResponse(_message.Message):
    __slots__ = ("allow", "reason")
    ALLOW_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    allow: bool
    reason: str
    def __init__(self, allow: bool = ..., reason: _Optional[str] = ...) -> None: ...

class PostDelegationVerifyRequest(_message.Message):
    __slots__ = ("subject", "delegate", "audience", "authorized_actions")
    SUBJECT_FIELD_NUMBER: _ClassVar[int]
    DELEGATE_FIELD_NUMBER: _ClassVar[int]
    AUDIENCE_FIELD_NUMBER: _ClassVar[int]
    AUTHORIZED_ACTIONS_FIELD_NUMBER: _ClassVar[int]
    subject: str
    delegate: str
    audience: str
    authorized_actions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, subject: _Optional[str] = ..., delegate: _Optional[str] = ..., audience: _Optional[str] = ..., authorized_actions: _Optional[_Iterable[str]] = ...) -> None: ...

class PostDelegationVerifyResponse(_message.Message):
    __slots__ = ("valid", "reason")
    VALID_FIELD_NUMBER: _ClassVar[int]
    REASON_FIELD_NUMBER: _ClassVar[int]
    valid: bool
    reason: str
    def __init__(self, valid: bool = ..., reason: _Optional[str] = ...) -> None: ...
