"""Root-issued READY LIVE session, serialized on one asyncio owner loop.

No installer, saved fallback, result cache or EOF finalizer. Only explicit
close_live_connection can ask the existing session for native closure.
"""
import asyncio
import hashlib
from pathlib import Path
import secrets

from . import live_guardian_wire as wire

SESSION_SHA = 'a63decd08efa3a6e53c1e18b4a3f22aa3f2c1c8509d48464f39c46607c79f4fc'
if hashlib.sha256(Path(__file__).with_name('resident_live_session.py').read_bytes()).hexdigest() != SESSION_SHA:
    raise ValueError('LIVE_HOST_SESSION_PIN')
from .resident_live_session import ResidentLiveSession, ResidentLiveSessionRefusal, source

TOOLS = wire.TOOLS
DATA_TOOLS = TOOLS - {'health', 'open_live_session'}


class LiveHostSlotRefusal(ValueError):
    """Body-free constructor or owner-loop refusal."""


def _need(value, code):
    if not value: raise LiveHostSlotRefusal('LIVE_HOST_' + code)


class LiveHostSlot:
    """Own one exact READY session and one nonreplaceable RAM binding token.

    Root may supply its already issued token; otherwise construction issues it
    once. The token is returned only by successful opens and bound responses.
    """
    def __init__(self, session, *, binding_token=None):
        _need(type(session) is ResidentLiveSession, 'SESSION')
        _need(session.health().get('status') == 'READY', 'READY')
        token = secrets.token_hex(16) if binding_token is None else binding_token
        _need(wire._token(token), 'TOKEN')
        self._session = session
        self._token = token
        self._loop = None
        self._lock = asyncio.Lock()
        self._state = 'READY'

    def __repr__(self): return '<LiveHostSlot ' + self._state + ' session=privateRAM>'

    @property
    def binding_token(self):
        """Root-only in-process capability; never a public tool or health field."""
        return self._token

    def _enter_loop(self):
        loop = asyncio.get_running_loop()
        _need(self._loop is None or self._loop is loop, 'OWNER_LOOP')
        self._loop = loop

    def _health(self):
        row = self._session.health()
        if row.get('status') == 'UNKNOWN_RETAIN': self._state = 'UNKNOWN_RETAIN'
        elif row.get('status') == 'CLOSED': self._state = 'CLOSED'
        if self._state == 'UNKNOWN_RETAIN': row = dict(row, status='UNKNOWN_RETAIN')
        return dict(row, binding_token=None, binding_retired=self._state == 'CLOSED')

    def _refused(self):
        try:
            if self._session.health().get('status') == 'UNKNOWN_RETAIN': self._state = 'UNKNOWN_RETAIN'
        except Exception:
            self._state = 'UNKNOWN_RETAIN'
        return dict(status='LIVE_REQUEST_REFUSED', source_domain=source.SOURCE_DOMAIN,
            connection_status=self._state, source_body_included=False,
            writer_authorized=False, binding_retired=self._state == 'CLOSED')

    def _dispatch(self, tool, args):
        session = self._session
        capture = args.get('capture_id')
        if tool == 'health': return self._health()
        if tool == 'open_live_session': return session.open_live_session(args['object_uuid'])
        if tool == 'refresh_observed': return session.refresh_observed(capture)
        if tool == 'close_live_session': return session.close_live_session(capture)
        if tool == 'close_live_connection': return session.close_live_connection()
        if tool == 'search_symbols':
            return session.search_symbols(capture, args.get('query', ''), args.get('limit', 25), args.get('offset', 0))
        target = source.ResidentLiveTarget(args['object_uuid'], args['property_uuid'])
        target.validate()
        if tool == 'observe_module': return session.observe_module(capture, target)
        if tool == 'read_module_slice':
            return session.read_module_slice(capture, target, args.get('offset', 0), args.get('count', 4096), args.get('expected_sha256'))
        if tool == 'analyze_syntax': return session.analyze_syntax(capture, target, args['expected_sha256'])
        return session.get_context(capture, target, args['method_name'])

    async def call(self, tool, args, *, binding_token=None):
        """Validate and dispatch one call; caller disconnect never closes native.

        Known request refusals leave a healthy session usable. Unexpected local
        failures conservatively retain ownership and never echo source/errors.
        """
        self._enter_loop()
        async with self._lock:
            result = None
            try:
                wire.build_request(dict(kind='CALL', request_id='1' * 32, tool=tool,
                    args=args, binding_token=binding_token))
                if tool in DATA_TOOLS:
                    _need(secrets.compare_digest(binding_token, self._token), 'STALE_TOKEN')
                if tool != 'health':
                    _need(self._state == 'READY' or tool == 'close_live_connection', 'PHASE')
                result = self._dispatch(tool, args)
                _need(type(result) is dict, 'RESULT')
                if tool == 'close_live_connection': self._state = 'CLOSED'
                if tool != 'health':
                    result = dict(result, binding_token=self._token, binding_retired=self._state == 'CLOSED')
                # Bound the complete envelope, not only the session payload.
                wire.build_response(dict(kind='RESULT', request_id='1' * 32,
                    ok=True, result=result, error=None), request_id='1' * 32)
                return result
            except (ResidentLiveSessionRefusal, source.ResidentLiveRefusal,
                    wire.GuardianWireRefusal, LiveHostSlotRefusal):
                result = None
                return self._refused()
            except Exception:
                result = None
                self._state = 'UNKNOWN_RETAIN'
                return self._refused()
