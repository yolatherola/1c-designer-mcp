"""Verify two readonly Value-carrier observations; never authorize a setter.

SDK Value copy/assignment retains a counted reference to the same IValue. This
proof covers carrier lifetime only, including when the underlying type is mutable.
"""

FORM = '0ed914fb-2a1a-4b58-9fad-eaa103b47c9e'
PROPERTY = 'e3331ed0-3854-478d-b6b5-4f14acdd6edb'
TYPE = 'b5fdf93a-40ea-4fc2-8911-2cb676377eff'
ZERO_COUNTERS = ('metadataSetterCalls', 'goldSourceWrites', 'goldSaves',
                 'repositoryWrites', 'databaseUpdates', 'businessCalls')
START_FLAGS = ('sourceKnown', 'copyKnown', 'carriersDistinct',
               'copyConstructorExact', 'sourceClearedToOriginalEmpty',
               'scopedSourceCarrierDestroyed', 'goldControlPreserved')
FINISH_FLAGS = ('copySurvivedSeparateCallback', 'freshSourceSameValue',
                'copyClearedToOriginalEmpty', 'goldControlPreserved')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def verify(start, finish, version):
    """Return a narrow lifetime proof for the exact two native phases.

    Inputs are sanitized JSON dictionaries and the freshly observed integer
    repository version. There are no file, process, connection or native calls.
    The result grants neither metadata mutation nor underlying-value sharing.
    """
    _need(type(start) is dict and type(finish) is dict, 'V67_PHASE_REJECTED')
    _need(start.get('status') == 'VALUE_COPY_VERIFIED'
          and finish.get('status') == 'VALUE_LIFETIME_VERIFIED', 'V67_PHASE_REJECTED')
    _need(type(version) is int and version > 0
          and all(type(phase.get('version')) is int and phase['version'] == version
                  for phase in (start, finish)), 'V67_VERSION_REJECTED')
    _need(start.get('sourceFormId') == FORM and start.get('propertyId') == PROPERTY
          and start.get('typeId') == TYPE, 'V67_SCOPE_REJECTED')
    _need(all(start.get(key) is True for key in START_FLAGS)
          and start.get('exception') is False, 'V67_COPY_REJECTED')
    _need(all(finish.get(key) is True for key in FINISH_FLAGS)
          and finish.get('exception') is False, 'V67_LIFETIME_REJECTED')
    _need(type(start.get('sourceTypeMutable')) is bool
          and type(finish.get('sourceTypeMutable')) is bool
          and start['sourceTypeMutable'] is finish['sourceTypeMutable'], 'V67_MUTABLE_REJECTED')
    for phase, clear_calls in ((start, 1), (finish, 2)):
        _need(phase.get('underlyingValueIndependent') is False, 'V67_INDEPENDENCE_REJECTED')
        _need(type(phase.get('nativeCopyCalls')) is int and phase['nativeCopyCalls'] == 2
              and type(phase.get('nativeClearCalls')) is int
              and phase['nativeClearCalls'] == clear_calls, 'V67_DISPATCH_REJECTED')
        _need(all(type(phase.get(key)) is int and phase[key] == 0
                  for key in ZERO_COUNTERS), 'V67_MUTATION_REJECTED')
    return dict(carrierLifetimeVerified=True, underlyingValueIndependent=False,
                sourceTypeMutable=start['sourceTypeMutable'], formCreationVerified=False,
                metadataSetterCalls=0)
