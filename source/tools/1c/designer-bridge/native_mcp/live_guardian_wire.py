"""Bounded LIVE guardian frames, reusing the pinned saved codec's pure helpers.

The separate magic and grammar prevent a saved connection from interpreting a
LIVE request. Tokens prove possession only; the Root owner checks currentness.
"""
import hashlib
from pathlib import Path
from types import FunctionType

from . import guardian_wire as _base
from .resident_live_source import SOURCE_DOMAIN

BASE_SHA = '3ca907c8f4df783cba01f63fb002e86c9cb2a262f504b785f50a9276c938a456'
if hashlib.sha256(Path(_base.__file__).read_bytes()).hexdigest() != BASE_SHA:
    raise ValueError('LIVE_GUARDIAN_WIRE_SOURCE_PIN')

MAGIC = b'AH1CLGD1'
VERSION = _base.VERSION
HEADER_BYTES = _base.HEADER_BYTES
MAX_REQUEST_BYTES = _base.MAX_REQUEST_BYTES
MAX_RESPONSE_BYTES = _base.MAX_RESPONSE_BYTES
MAX_DEPTH = _base.MAX_DEPTH
ERRORS = _base.ERRORS
GuardianWireRefusal = _base.GuardianWireRefusal
LiveGuardianWireRefusal = GuardianWireRefusal
TOOLS = frozenset(('health', 'open_live_session', 'refresh_observed', 'observe_module',
    'read_module_slice', 'search_symbols', 'get_context', 'analyze_syntax', 'close_live_session', 'close_live_connection'))
_UNBOUND = frozenset(('health', 'open_live_session'))
_BASE = frozenset(('capture_id', 'source_domain', 'nocache'))
_TARGET = _BASE | {'object_uuid', 'property_uuid'}
_FIELDS = {
    'health': (frozenset(('nocache',)), frozenset()),
    'open_live_session': (frozenset(('object_uuid', 'source_domain', 'nocache')), frozenset()),
    'refresh_observed': (_BASE, frozenset()),
    'observe_module': (_TARGET, frozenset()),
    'read_module_slice': (_TARGET, frozenset(('offset', 'count', 'expected_sha256'))),
    'search_symbols': (_BASE, frozenset(('query', 'limit', 'offset'))),
    'get_context': (_TARGET | {'method_name'}, frozenset()),
    'analyze_syntax': (_TARGET | {'expected_sha256'}, frozenset()),
    'close_live_session': (_BASE, frozenset()),
    'close_live_connection': (frozenset(('nocache',)), frozenset()),
}

# The original functions use this private namespace, never altered saved globals.
# Rehome the small, pinned codec rather than maintaining a second JSON parser.
_codec = dict(vars(_base), MAGIC=MAGIC)
for _name, _value in tuple(vars(_base).items()):
    if isinstance(_value, FunctionType) and _value.__module__ == _base.__name__:
        _codec[_name] = FunctionType(_value.__code__, _codec, _name, _value.__defaults__, _value.__closure__)
        _codec[_name].__kwdefaults__ = _value.__kwdefaults__
for _name in ('_need', '_integer', '_hex', '_token', '_uuid', '_word', 'parse_header'):
    globals()[_name] = _codec[_name]


def _request(row):
    _need(type(row) is dict and row.keys() == {'kind', 'request_id', 'tool', 'args', 'binding_token'}, 'REQUEST_SCHEMA')
    _need(type(row['kind']) is str and row['kind'] == 'CALL' and _token(row['request_id'])
        and type(row['tool']) is str and row['tool'] in TOOLS, 'REQUEST_IDENTITY')
    tool = row['tool']; args = row['args']; required, optional = _FIELDS[tool]
    _need(type(args) is dict and required <= args.keys() <= required | optional, 'ARGUMENT_SCHEMA')
    _need(args['nocache'] is True, 'NOCACHE')
    _need(row['binding_token'] is None if tool in _UNBOUND else _token(row['binding_token']), 'BINDING_TOKEN')
    if 'source_domain' in args:
        _need(type(args['source_domain']) is str and args['source_domain'] == SOURCE_DOMAIN, 'DOMAIN')
    if 'capture_id' in args: _need(_token(args['capture_id']), 'CAPTURE_ID')
    if 'object_uuid' in args: _need(_uuid(args['object_uuid']), 'TARGET')
    if 'property_uuid' in args:
        _need(_uuid(args['property_uuid']) and args['object_uuid'] != args['property_uuid'], 'TARGET')
    if 'offset' in args:
        _need(_integer(args['offset'], 0, 100000 if tool == 'search_symbols' else 131072), 'OFFSET')
    if 'count' in args: _need(_integer(args['count'], 1, 16384), 'COUNT')
    if 'limit' in args: _need(_integer(args['limit'], 1, 100), 'LIMIT')
    if 'query' in args: _need(_word(args['query']), 'QUERY')
    if 'method_name' in args: _need(_word(args['method_name'], 1), 'METHOD')
    if 'expected_sha256' in args:
        _need(args['expected_sha256'] is None or _hex(args['expected_sha256'], 64), 'HASH')
    if tool == 'analyze_syntax': _need(_hex(args['expected_sha256'], 64), 'HASH')
    if tool == 'read_module_slice' and args.get('offset', 0) > 0:
        _need(args.get('expected_sha256') is not None, 'CONTINUATION_HASH')


_codec['_request'] = _request
for _name in ('build_request', 'parse_request', 'build_response', 'parse_response'):
    globals()[_name] = _codec[_name]
