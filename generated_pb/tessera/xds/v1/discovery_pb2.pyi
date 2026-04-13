from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class DiscoveryRequest(_message.Message):
    __slots__ = ("node_id", "resource_type", "version_info", "resource_names")
    NODE_ID_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    VERSION_INFO_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_NAMES_FIELD_NUMBER: _ClassVar[int]
    node_id: str
    resource_type: str
    version_info: str
    resource_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, node_id: _Optional[str] = ..., resource_type: _Optional[str] = ..., version_info: _Optional[str] = ..., resource_names: _Optional[_Iterable[str]] = ...) -> None: ...

class DiscoveryResponse(_message.Message):
    __slots__ = ("version_info", "type_url", "resources", "nonce")
    VERSION_INFO_FIELD_NUMBER: _ClassVar[int]
    TYPE_URL_FIELD_NUMBER: _ClassVar[int]
    RESOURCES_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    version_info: str
    type_url: str
    resources: _containers.RepeatedCompositeFieldContainer[ResourceWrapper]
    nonce: str
    def __init__(self, version_info: _Optional[str] = ..., type_url: _Optional[str] = ..., resources: _Optional[_Iterable[_Union[ResourceWrapper, _Mapping]]] = ..., nonce: _Optional[str] = ...) -> None: ...

class ResourceWrapper(_message.Message):
    __slots__ = ("name", "version", "resource")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    RESOURCE_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    resource: bytes
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ..., resource: _Optional[bytes] = ...) -> None: ...
