from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PolicyBundle(_message.Message):
    __slots__ = ("version", "revision", "requirements", "default_trust_level", "human_approval_tools")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    REQUIREMENTS_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_TRUST_LEVEL_FIELD_NUMBER: _ClassVar[int]
    HUMAN_APPROVAL_TOOLS_FIELD_NUMBER: _ClassVar[int]
    version: str
    revision: str
    requirements: _containers.RepeatedCompositeFieldContainer[ToolRequirement]
    default_trust_level: int
    human_approval_tools: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, version: _Optional[str] = ..., revision: _Optional[str] = ..., requirements: _Optional[_Iterable[_Union[ToolRequirement, _Mapping]]] = ..., default_trust_level: _Optional[int] = ..., human_approval_tools: _Optional[_Iterable[str]] = ...) -> None: ...

class ToolRequirement(_message.Message):
    __slots__ = ("name", "resource_type", "required_trust")
    NAME_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_TRUST_FIELD_NUMBER: _ClassVar[int]
    name: str
    resource_type: str
    required_trust: int
    def __init__(self, name: _Optional[str] = ..., resource_type: _Optional[str] = ..., required_trust: _Optional[int] = ...) -> None: ...

class ToolRegistryEntry(_message.Message):
    __slots__ = ("name", "is_external")
    NAME_FIELD_NUMBER: _ClassVar[int]
    IS_EXTERNAL_FIELD_NUMBER: _ClassVar[int]
    name: str
    is_external: bool
    def __init__(self, name: _Optional[str] = ..., is_external: bool = ...) -> None: ...

class ToolRegistry(_message.Message):
    __slots__ = ("version", "revision", "tools")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TOOLS_FIELD_NUMBER: _ClassVar[int]
    version: str
    revision: str
    tools: _containers.RepeatedCompositeFieldContainer[ToolRegistryEntry]
    def __init__(self, version: _Optional[str] = ..., revision: _Optional[str] = ..., tools: _Optional[_Iterable[_Union[ToolRegistryEntry, _Mapping]]] = ...) -> None: ...

class TrustConfig(_message.Message):
    __slots__ = ("version", "revision", "trust_levels")
    class TrustLevelsEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    VERSION_FIELD_NUMBER: _ClassVar[int]
    REVISION_FIELD_NUMBER: _ClassVar[int]
    TRUST_LEVELS_FIELD_NUMBER: _ClassVar[int]
    version: str
    revision: str
    trust_levels: _containers.ScalarMap[str, int]
    def __init__(self, version: _Optional[str] = ..., revision: _Optional[str] = ..., trust_levels: _Optional[_Mapping[str, int]] = ...) -> None: ...
