"""Validate one own class-preserving form descriptor observation; run nothing."""
import re

SOURCE_FORM = 'b8a520d4-c823-477e-ba92-708656e9c9c6'
SOURCE_PARENT = 'c80fe1d6-4f67-454a-92bd-98b01e1e8332'
FORM_CLASS = 'd5b0e5ed-256d-401c-9c36-f630cafd8a62'
PARENT_CLASS = 'bf845118-327b-4682-b5c6-285d2a0eb296'
OWN_PROCESSING = '0fbfe5a2-5229-4165-a18e-446ac335850c'
OWN_FORM = '754b60bf-50c3-4f4f-ae8f-d92948c16525'
GOLD_ROOT = '218b5d00-7e10-486f-874c-73c2368ed5da'
DESCRIPTOR_LIMIT = 1048576
GUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}')
COMMON_FLAGS = ('sourceKnown', 'sourceManagedVerified', 'managerIndependent', 'ownFactoryVerified',
                'ownParentVerified', 'contextEmpty', 'sourceDescriptorUnchanged',
                'sourceControlPreserved', 'ownScopeExited')
CLONE_FLAGS = ('descriptorInputConsumed', 'formTypeKnown', 'formTypeEqual',
               'formTypeIndependent', 'ownTypeMutable', 'descriptorCloneVerified')
ZERO_COUNTERS = ('goldSourceWrites', 'goldSaves', 'repositoryWrites',
                 'databaseUpdates', 'businessCalls')
UNAVAILABLE_REASONS = ('LOAD_ABI_UNKNOWN', 'PERSISTENCE_QI_ABSENT')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def verify(info, version):
    """Check a sanitized native receipt, without granting any further writes.

    The trusted caller supplies fresh native identity/control witnesses and the
    expected repository version. A distinct canonical IValue proves only the
    wrapper identity; neither branch certifies independent backing/deep clone.
    Unsupported observations record only factory/attach preflight. A loaded
    descriptor does not prove a persisted body or a completed managed form.
    MemoryFile roots may have the zero GUID; canonical manager independence is
    a separate mandatory native witness and is not inferred from the root ID.
    """
    _need(type(info) is dict, 'V69_OBSERVATION_REJECTED')
    status = info.get('status')
    _need(status in ('PROCESSING_FORM_DESCRIPTOR_VERIFIED',
                     'PROCESSING_FORM_CLONE_UNAVAILABLE'), 'V69_STATUS_REJECTED')
    cloned = status == 'PROCESSING_FORM_DESCRIPTOR_VERIFIED'
    _need(type(version) is int and version > 0
          and type(info.get('version')) is int and info['version'] == version,
          'V69_VERSION_REJECTED')
    expected_ids = dict(sourceFormId=SOURCE_FORM, sourceParentId=SOURCE_PARENT,
                        sourceFormClassId=FORM_CLASS, sourceParentClassId=PARENT_CLASS,
                        ownProcessingId=OWN_PROCESSING, ownFormId=OWN_FORM,
                        ownFormClassId=FORM_CLASS, ownParentClassId=PARENT_CLASS,
                        ownFormParentId=OWN_PROCESSING)
    _need(all(info.get(key) == value for key, value in expected_ids.items()),
          'V69_SCOPE_REJECTED')
    root = info.get('ownRootId')
    _need(type(root) is str and GUID.fullmatch(root) is not None
          and root not in (GOLD_ROOT, SOURCE_FORM, SOURCE_PARENT,
                           OWN_PROCESSING, OWN_FORM), 'V69_ROOT_REJECTED')
    _need(all(info.get(key) is True for key in COMMON_FLAGS)
          and info.get('exception') is False
          and info.get('sourceTypeMutable') is True, 'V69_CONTROL_REJECTED')
    _need(all(info.get(key) is cloned for key in CLONE_FLAGS)
          and info.get('formTypeBackingIndependent') is False
          and info.get('independentCloneVerified') is False
          and info.get('formCreationVerified') is False
          and info.get('persistedFormVerified') is False, 'V69_CLAIM_REJECTED')
    _need(type(info.get('factoryCalls')) is int and info['factoryCalls'] == 2
          and type(info.get('ownAttachCalls')) is int and info['ownAttachCalls'] == 2
          and type(info.get('descriptorLoadCalls')) is int
          and info['descriptorLoadCalls'] == int(cloned), 'V69_CALLS_REJECTED')
    _need(all(type(info.get(key)) is int and info[key] == 0 for key in ZERO_COUNTERS),
          'V69_MUTATION_REJECTED')
    size = info.get('descriptorBytes')
    _need(type(size) is int and 0 < size <= DESCRIPTOR_LIMIT,
          'V69_DESCRIPTOR_REJECTED')
    reason = info.get('unavailableReason')
    _need(type(reason) is str and (reason == '' if cloned else reason in UNAVAILABLE_REASONS),
          'V69_UNAVAILABLE_REJECTED')
    return dict(observationAccepted=True, descriptorCloneVerified=cloned,
                formTypeBackingIndependent=False, independentCloneVerified=False,
                formCreationVerified=False,
                persistedFormVerified=False, sourceTypeMutable=True,
                ownTypeMutable=cloned, descriptorBytes=size)
