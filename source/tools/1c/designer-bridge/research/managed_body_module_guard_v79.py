"""Pure V79 numeric module observation on one known owned body factory.

Reuses frozen V78 source/factory checks. Twelve physical receipts are required;
the common guard's ten basename requests are translated to this version and the
two module receipts are inserted before scope exit. No configuration/body/text
file is read, and no native, persistence, cleanup or writer capability is granted.
"""
import re

import managed_body_factory_guard_v78 as base

MARKER_LIMIT = base.MARKER_LIMIT
RESULT_LIMIT = base.RESULT_LIMIT
ZERO_COUNTERS = base.ZERO_COUNTERS
LENGTH_LIMIT = 16384
MODULE_OFFSET = 48
GETTER_RVA = 0xa55a0
PHASES = base.PHASES[:6] + ('beforeModuleProbe', 'afterModuleProbe') + base.PHASES[6:]
EXTRA_KEYS = ('module', 'moduleVerified', 'ownContextPresent', 'own8DisjointVerified')
MAIN_KEYS = base.MAIN_KEYS + EXTRA_KEYS
MODULE_KEYS = ('getterCalls', 'getterAbiVerified', 'getterTarget', 'getterReturnMatched',
               'stringStorageReadable', 'rawLengthReads', 'convertedTextReads',
               'rawLength', 'convertedLength', 'rawLengthBounded', 'convertedLengthBounded',
               'rawEmpty', 'convertedEmpty', 'textLogged', 'textSaved', 'textWrites',
               'expectedStorageOffset', 'lengthLimit')
MODULE_BOOLS = ('getterAbiVerified', 'getterReturnMatched', 'stringStorageReadable',
                'rawLengthBounded', 'convertedLengthBounded', 'rawEmpty', 'convertedEmpty',
                'textLogged', 'textSaved')


def _need(condition, code):
    if not condition:
        raise ValueError(code)


def _shape(value, keys, code):
    _need(type(value) is dict and set(value) == set(keys), code)


def _common_code(error):
    code = str(error)
    return 'V79_' + code[4:] if re.fullmatch(r'V78_[A-Z_]+', code) else 'V79_COMMON_REJECTED'


def parse_result(raw):
    """Parse bounded unique-key JSON with the frozen common parser; reveal fixed codes only."""
    try:
        return base.parse_result(raw)
    except ValueError as error:
        raise ValueError(_common_code(error)) from None


def marker_filename(phase):
    """Return one of twelve fixed own basenames; perform no I/O or path resolution."""
    _need(type(phase) is str and phase in PHASES, 'V79_PHASE_REJECTED')
    return 'managed-body-module-v79-' + phase + '.json'


def _marker(reader, phase):
    _need(callable(reader), 'V79_MARKER_READER_REJECTED')
    filename = marker_filename(phase)
    try:
        raw = reader(filename)
    except Exception:
        raise ValueError('V79_MARKER_READ_REJECTED') from None
    _need(type(raw) is bytes and 0 < len(raw) <= MARKER_LIMIT, 'V79_MARKER_REJECTED')
    receipt = parse_result(raw)
    _shape(receipt, ('phase',) + ZERO_COUNTERS, 'V79_MARKER_REJECTED')
    _need(receipt['phase'] == phase and all(type(receipt[key]) is int and receipt[key] == 0
          for key in ZERO_COUNTERS), 'V79_MARKER_REJECTED')
    return receipt


def _no_raw(value):
    _need(value['rawLengthReads'] == 0 and value['rawLength'] is None
          and value['rawLengthBounded'] is False and value['rawEmpty'] is False,
          'V79_UNREAD_RAW_REJECTED')


def _no_conversion(value):
    _need(value['convertedTextReads'] == 0 and value['convertedLength'] is None
          and value['convertedLengthBounded'] is False and value['convertedEmpty'] is False,
          'V79_UNREAD_CONVERSION_REJECTED')


def _module(value, factory_verified):
    _shape(value, MODULE_KEYS, 'V79_MODULE_SHAPE_REJECTED')
    _need(all(type(value[key]) is bool for key in MODULE_BOOLS)
          and all(type(value[key]) is int and value[key] in (0, 1)
                  for key in ('getterCalls', 'rawLengthReads', 'convertedTextReads')),
          'V79_MODULE_TYPES_REJECTED')
    _need(type(value['expectedStorageOffset']) is int and value['expectedStorageOffset'] == MODULE_OFFSET
          and type(value['lengthLimit']) is int and value['lengthLimit'] == LENGTH_LIMIT
          and type(value['textWrites']) is int and value['textWrites'] == 0
          and value['textLogged'] is False and value['textSaved'] is False,
          'V79_MODULE_SCOPE_REJECTED')
    if value['getterCalls'] == 0:
        _need(value['getterAbiVerified'] is False and value['getterTarget'] is None
              and value['getterReturnMatched'] is False and value['stringStorageReadable'] is False,
              'V79_UNCALLED_GETTER_REJECTED')
        _no_raw(value)
        _no_conversion(value)
        return False
    _need(factory_verified is True and value['getterAbiVerified'] is True
          and value['getterTarget'] == dict(module='mngcore.dll', rva=GETTER_RVA),
          'V79_GETTER_PREREQUISITE_REJECTED')
    # Exact target fields/types still reject bool-as-RVA and extra provenance data.
    _shape(value['getterTarget'], ('module', 'rva'), 'V79_GETTER_TARGET_REJECTED')
    _need(type(value['getterTarget']['rva']) is int, 'V79_GETTER_TARGET_REJECTED')
    if not value['getterReturnMatched']:
        _need(value['stringStorageReadable'] is False, 'V79_RETURN_REJECTED')
    if not (value['getterReturnMatched'] and value['stringStorageReadable']):
        _no_raw(value)
        _no_conversion(value)
        return False
    _need(value['rawLengthReads'] == 1 and base._uint(value['rawLength'], zero=True)
          and value['rawLengthBounded'] is (value['rawLength'] <= LENGTH_LIMIT)
          and value['rawEmpty'] is (value['rawLength'] == 0), 'V79_RAW_LENGTH_REJECTED')
    if not value['rawLengthBounded']:
        # Observe an out-of-bound uint without converting or exposing its text.
        _no_conversion(value)
        return False
    _need(value['convertedTextReads'] == 1 and base._uint(value['convertedLength'], zero=True)
          and value['convertedLengthBounded'] is (value['convertedLength'] <= LENGTH_LIMIT)
          and value['convertedEmpty'] is (value['convertedLength'] == 0),
          'V79_CONVERTED_LENGTH_REJECTED')
    # Raw and converted string APIs may count different units; equality is not assumed.
    return value['convertedLengthBounded']


def verify(info, version, read_marker):
    """Verify observation/factory/module separately and all twelve physical receipts.

    Call parse_result on the raw main response first. The caller supplies a
    contained, reparse-safe reader; this guard requests only fixed V79 names.
    Factory/QI/getter ABI also requires the separate fixed PE/SDK prerequisite.
    Empty text is an observation, not a prerequisite or a writer authorization.
    """
    _shape(info, MAIN_KEYS, 'V79_RESULT_SHAPE_REJECTED')
    _need(info['status'] == 'MANAGED_BODY_MODULE_OBSERVED_V79'
          and type(info['moduleVerified']) is bool and type(info['bodyFactoryVerified']) is bool
          and info['ownContextPresent'] is False and info['own8DisjointVerified'] is False,
          'V79_OUTCOME_REJECTED')
    module_verified = _module(info['module'], info['bodyFactoryVerified'])
    _need(info['moduleVerified'] is module_verified, 'V79_MODULE_CLAIM_REJECTED')
    _shape(info['lifecycle'], PHASES, 'V79_LIFECYCLE_REJECTED')
    _need(all(info['lifecycle'][phase] is True for phase in PHASES), 'V79_LIFECYCLE_REJECTED')
    common = {key: info[key] for key in base.MAIN_KEYS}
    common['status'] = 'MANAGED_BODY_FACTORY_OBSERVED_V78'
    common['lifecycle'] = {phase: info['lifecycle'][phase] for phase in base.PHASES}
    translations = {base.marker_filename(phase): phase for phase in base.PHASES}
    reads = []

    def common_reader(name):
        _need(type(name) is str and name in translations, 'V79_COMMON_MARKER_REJECTED')
        phase = translations[name]
        if phase == 'beforeScopeExit':
            for extra in ('beforeModuleProbe', 'afterModuleProbe'):
                _marker(read_marker, extra)
                reads.append(extra)
        # V78 parses this same physical receipt and validates the common phase/zeros.
        _need(callable(read_marker), 'V79_MARKER_READER_REJECTED')
        raw = read_marker(marker_filename(phase))
        reads.append(phase)
        return raw

    try:
        proof = base.verify(common, version, common_reader)
    except ValueError as error:
        raise ValueError(_common_code(error)) from None
    _need(tuple(reads) == PHASES, 'V79_PHYSICAL_PHASES_REJECTED')
    proof.update(moduleVerified=module_verified, physicalMarkerCount=len(PHASES),
                 ownContextPresent=False, own8DisjointVerified=False)
    return proof
