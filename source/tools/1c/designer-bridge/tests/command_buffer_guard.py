"""Validate fresh native buffer observations; never grant source-write permission."""
import hashlib


MARKER = '// AH1C owned dirty guard V28\r\n'
LIMIT = 1048576


def require(condition, code):
    if not condition:
        raise ValueError(code)


def verify_status(value, previous=None):
    """Check the startup baseline of our own process, not previously saved text."""
    require(type(value) is dict, 'BUFFER_STATUS_MISSING')
    for key in ('initialTextKnown', 'scopeUnchanged', 'matchesInitialText'):
        require(value.get(key) is True, 'BUFFER_STATUS_CHANGED_OR_UNKNOWN')
    for key in ('persistedBaselineVerified', 'allOpenEditorsInspected', 'sourceOverwriteAuthorized'):
        require(value.get(key) is False, 'BUFFER_STATUS_FALSE_PERMISSION')
    number = value.get('observationNumber')
    size = value.get('initialTextCharacters')
    require(type(number) is int and 0 < number < 2**32
        and type(size) is int and 0 <= size <= LIMIT, 'BUFFER_STATUS_COUNTER')
    require(value.get('baselineKind') == 'startup-of-owned-process', 'BUFFER_STATUS_BASELINE')
    if previous is not None:
        require(number > previous['observationNumber']
            and size == previous['initialTextCharacters'], 'BUFFER_STATUS_STALE_OR_REBOUND')
    return dict(value)


def verify_owned(proof, before, changed, restored):
    """Check actual own text bytes independently of the native success booleans."""
    require(type(proof) is dict and 'error' not in proof, 'BUFFER_NATIVE_REJECTED')
    require(proof.get('nativeMutationTarget') == 'fresh-native-text-document', 'BUFFER_TARGET')
    for key in ('sharedNativeComparatorUsed', 'initialClean', 'initialComparisonAccepted',
                'unknownBaselineRejected', 'insertionExact', 'changedTextComparisonRejected',
                'exactTextRestored', 'restoredComparisonAccepted', 'selectedGoldBufferUnchanged'):
        require(proof.get(key) is True, 'BUFFER_NATIVE_COMPARISON_REJECTED')
    require(type(proof.get('actualNativeModifiedAfterInsertion')) is bool, 'BUFFER_DIRTY_UNKNOWN')
    for key in ('dirtyFlagPatched', 'businessCodeExecuted', 'persistedBaselineVerified',
                'allOpenEditorsInspected', 'sourceOverwriteAuthorized'):
        require(proof.get(key) is False, 'BUFFER_FALSE_PERMISSION')
    for key, count in (('replacementSetterCalls', 0), ('ownedTextSetterCalls', 2),
                       ('goldConfigurationWrites', 0), ('repositoryMutations', 0), ('databaseUpdates', 0)):
        require(type(proof.get(key)) is int and proof[key] == count, 'BUFFER_SETTER_OR_WRITE_COUNT')
    require(all(type(value) is bytes for value in (before, changed, restored)), 'BUFFER_TEXT_BYTES')
    require(before == restored == b'' and changed == MARKER.encode('utf-8'), 'BUFFER_TEXT_NOT_EXACT')
    return dict(proof, independentTextVerified=True, insertedCharacters=len(MARKER),
        initialTextSha256=hashlib.sha256(before).hexdigest(),
        changedTextSha256=hashlib.sha256(changed).hexdigest(),
        restoredTextSha256=hashlib.sha256(restored).hexdigest())
