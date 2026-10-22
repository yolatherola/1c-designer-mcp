"""Validate readonly FormType persistence support; never certify a clone."""
import hashlib
import re

FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
PROPERTY = 'e3331ed0-3854-478d-b6b5-4f14acdd6edb'
TYPE = 'b5fdf93a-40ea-4fc2-8911-2cb676377eff'
BODY_FILE = 'form-type-persistence-v68.bin'
BODY_LIMIT = 1048576
GUID = re.compile(r'\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}')
SOURCE_FLAGS = ('sourceKnown', 'sourceIValueUnchanged', 'sourceScopeExited',
                'goldControlPreserved')
SERIALIZATION_FLAGS = ('memoryFactoryVerified', 'streamFactoryVerified',
                       'streamClosed', 'fileWritten')
FACTORY_COUNTERS = ('memoryFactoryCalls', 'streamFactoryCalls', 'sourceSerializeCalls')
ZERO_COUNTERS = ('cloneFactoryCalls', 'deserializeCalls', 'metadataSetterCalls',
                 'goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def verify(info, version, bodyReader):
    """Validate sanitized observation and, if supported, hash one exact body.

    bodyReader is the trusted caller's bounded own-runtime reader. It receives
    BODY_FILE only, once and after all metadata validation; unavailable QI never
    invokes it. No data is printed or executed, and no factory/clone is authorized.
    """
    _need(type(info) is dict and type(info.get('persistenceSupported')) is bool,
          'V68_OBSERVATION_REJECTED')
    supported = info['persistenceSupported']
    expected_status = 'VALUE_PERSIST_OBSERVED' if supported else 'VALUE_PERSIST_UNAVAILABLE'
    _need(info.get('status') == expected_status, 'V68_STATUS_REJECTED')
    _need(type(version) is int and version > 0
          and type(info.get('version')) is int and info['version'] == version,
          'V68_VERSION_REJECTED')
    _need(info.get('sourceFormId') == FORM and info.get('propertyId') == PROPERTY
          and info.get('typeId') == TYPE, 'V68_SCOPE_REJECTED')
    _need(all(info.get(key) is True for key in SOURCE_FLAGS)
          and info.get('exception') is False
          and type(info.get('sourceTypeMutable')) is bool, 'V68_SOURCE_REJECTED')
    _need(all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V68_MUTATION_REJECTED')
    _need(all(type(info.get(key)) is int and info[key] == int(supported)
              for key in FACTORY_COUNTERS)
          and all(info.get(key) is supported for key in SERIALIZATION_FLAGS),
          'V68_SERIALIZATION_REJECTED')
    class_id = info.get('persistenceClassId')
    size = info.get('serializedBytes')
    _need(type(class_id) is str and type(size) is int, 'V68_BODY_METADATA_REJECTED')
    if supported:
        _need(GUID.fullmatch(class_id) is not None
              and int(class_id[1:-1].replace('-', ''), 16) != 0, 'V68_CLASS_REJECTED')
        _need(0 < size <= BODY_LIMIT and info.get('serializedFile') == BODY_FILE,
              'V68_BODY_METADATA_REJECTED')
    else:
        _need(class_id == '' and size == 0 and info.get('serializedFile') == '',
              'V68_UNAVAILABLE_REJECTED')
    result = dict(persistenceSupported=supported, serializationVerified=supported,
                  independentCloneVerified=False, formCreationVerified=False,
                  typeMutable=info['sourceTypeMutable'])
    if supported:
        _need(callable(bodyReader), 'V68_BODY_READ_REJECTED')
        try:
            body = bodyReader(BODY_FILE)
        except Exception:
            raise ValueError('V68_BODY_READ_REJECTED') from None
        _need(type(body) is bytes and len(body) == size, 'V68_BODY_SIZE_REJECTED')
        result.update(persistenceClassId=class_id, serializedBytes=size,
                      sha256=hashlib.sha256(body).hexdigest())
    return result
