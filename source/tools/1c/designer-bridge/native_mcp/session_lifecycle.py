"""Bounded binding generations over a resident saved-source transport.

This module owns metadata and SavedSession instances only. An external launcher
must authenticate the transport and implement open/shutdown; accepting callbacks
here is not native attestation. No I/O, process creation, or body cache lives here.
"""
from dataclasses import dataclass
import inspect
import threading
import time
from uuid import uuid4

from .saved_source import (SourceBinding, GuardState, Target, SavedRefusal,
                           validate_snapshot, need, finite, integer)
from .server import SavedSession


@dataclass(frozen=True, slots=True)
class SessionIdentity:
    root_uuid: str
    session_id: str
    process_id: int
    birth: str
    source_domain: str

    def binding(self, generation, valid_until):
        value = SourceBinding(self.root_uuid, self.session_id, self.process_id,
                              self.birth, generation, self.source_domain, valid_until)
        value.validate()
        return value


@dataclass(frozen=True, slots=True)
class BindingRequest:
    identity: SessionIdentity
    request_id: str
    generation: int
    issued_at: float
    valid_until: float


@dataclass(frozen=True, slots=True)
class SessionPorts:
    request_id: str
    binding: SourceBinding
    checked_at: float
    provider: object
    guard: object
    current_binding: object


@dataclass(frozen=True, slots=True)
class ShutdownReceipt:
    known_terminal: bool
    references_closed: bool
    workers_closed: bool
    callbacks_closed: bool


class SessionBroker:
    """Explicitly renew bounded bindings without recreating the transport.

    Only open_generation can acquire a new binding. Selecting, searching, or
    reading a stale generation never opens another one implicitly. The opener
    must verify current identity after each request; the resident function may
    survive a generation, but observations/index metadata do not cross it.
    """
    def __init__(self, identity, opener, shutdown, *, clock=time.monotonic,
                 binding_ttl=60.0, snapshot_ttl=5.0):
        need(type(identity) is SessionIdentity, 'LIFECYCLE_IDENTITY')
        identity.binding(1, 1.0)
        need(all(callable(x) and not inspect.iscoroutinefunction(x)
                 for x in (opener, shutdown, clock)), 'LIFECYCLE_CALLBACK')
        need(finite(binding_ttl) and 0 < binding_ttl <= 60
             and finite(snapshot_ttl) and 0 < snapshot_ttl <= binding_ttl, 'LIFECYCLE_TTL')
        self.identity, self.opener, self.shutdown = identity, opener, shutdown
        self.clock, self.binding_ttl, self.snapshot_ttl = clock, binding_ttl, snapshot_ttl
        self._session = None
        self.generation = 0
        self.state = 'UNOPENED'
        self.last_error = None
        self._last_now = None
        self._lock = threading.Lock()
        self._shutdown_attempted = False

    def _enter(self):
        need(self._lock.acquire(blocking=False), 'LIFECYCLE_BUSY')

    def _invalidate(self):
        if self._session is not None:
            self._session.close()

    def _unknown(self, code):
        self._invalidate()
        self.state, self.last_error = 'UNKNOWN_RETAIN', code

    def _now(self):
        now = self.clock()
        if not finite(now) or now < 0 or (self._last_now is not None and now < self._last_now):
            self._unknown('LIFECYCLE_CLOCK')
            raise SavedRefusal('SAVED_LIFECYCLE_CLOCK')
        self._last_now = now
        return now

    def _usable(self):
        need(self.state not in ('CLOSED', 'UNKNOWN_RETAIN'), 'LIFECYCLE_SEALED')

    def _guarded_ports(self, ports):
        # SavedSession.refresh intentionally aggregates individual refusals.
        # Seal inside callbacks, before that aggregation can hide an uncertain
        # native outcome and advance to another target in the same refresh.
        def identity():
            try:
                self._usable()
                value = ports.current_binding()
                need(type(value) is SourceBinding and value == ports.binding,
                     'LIFECYCLE_CURRENT_BINDING')
                return value
            except Exception:
                self._unknown('LIFECYCLE_IDENTITY_UNPROVEN')
                raise SavedRefusal('SAVED_LIFECYCLE_IDENTITY_UNPROVEN') from None

        def guard(binding, target):
            try:
                self._usable()
                before = self._now()
                value = ports.guard(binding, target)
                after = self._now()
                need(type(value) is GuardState and type(value.binding) is SourceBinding
                     and value.binding == binding == ports.binding and type(value.target) is Target
                     and value.target == target and value.identity_verified is True,
                     'LIFECYCLE_GUARD_BINDING')
                need(type(value.dirty_state) is str and value.dirty_state in ('clean', 'dirty', 'unknown')
                     and finite(value.checked_at) and finite(value.valid_until)
                     and before <= value.checked_at <= after <= value.valid_until <= binding.valid_until,
                     'LIFECYCLE_GUARD_FRESHNESS')
                return value
            except Exception:
                self._unknown('LIFECYCLE_GUARD_UNPROVEN')
                raise SavedRefusal('SAVED_LIFECYCLE_GUARD_UNPROVEN') from None

        def provider(request):
            try:
                self._usable()
                need(request.binding == ports.binding, 'LIFECYCLE_PROVIDER_BINDING')
                packet = ports.provider(request)
                text = validate_snapshot(packet, request, self._now())
                del text
                return packet
            except Exception:
                self._unknown('LIFECYCLE_PROVIDER_UNPROVEN')
                raise SavedRefusal('SAVED_LIFECYCLE_PROVIDER_UNPROVEN') from None

        return provider, guard, identity

    def open_generation(self):
        """Open once or explicitly replace an expired binding; never read source.

        An ambiguous/invalid opener result seals this broker. Recovery requires
        a separately verified transport close and a distinct broker instance.
        """
        self._enter()
        try:
            self._usable()
            now = self._now()
            if self._session is not None and now <= self._session.binding.valid_until:
                return self._session.binding
            self._invalidate()
            need(integer(self.generation + 1, 1, 2**53-1), 'LIFECYCLE_GENERATION')
            request = BindingRequest(self.identity, uuid4().hex, self.generation+1,
                                     now, now+self.binding_ttl)
            # Reserve the issued generation even if opening becomes UNKNOWN.
            # Its client can then request one explicit cleanup using that exact
            # generation; a failed first open must not leave an uncloseable 0.
            self.generation = request.generation
            self.state = 'OPENING'
            try:
                ports = self.opener(request)
                after = self._now()
                need(type(ports) is SessionPorts and type(ports.binding) is SourceBinding
                     and ports.request_id == request.request_id, 'LIFECYCLE_PORTS')
                ports.binding.validate()
                need(ports.binding == self.identity.binding(request.generation, ports.binding.valid_until)
                     and finite(ports.checked_at)
                     and now <= ports.checked_at <= after <= ports.binding.valid_until <= request.valid_until,
                     'LIFECYCLE_BINDING_JOIN')
                need(all(callable(x) and not inspect.iscoroutinefunction(x)
                         for x in (ports.provider, ports.guard, ports.current_binding)), 'LIFECYCLE_PORT_CALLBACK')
                provider, guard, identity = self._guarded_ports(ports)
                session = SavedSession(ports.binding, provider, guard,
                                       identity, clock=self.clock, ttl=self.snapshot_ttl)
            except Exception:
                self._unknown('LIFECYCLE_OPEN_UNPROVEN')
                raise SavedRefusal('SAVED_LIFECYCLE_OPEN_UNPROVEN') from None
            self._session, self.generation = session, request.generation
            self.state, self.last_error = 'READY', None
            return session.binding
        finally:
            self._lock.release()

    def _select_locked(self, source_domain, generation):
        self._usable()
        now = self._now()
        need(self._session is not None and self.state == 'READY', 'LIFECYCLE_NOT_OPEN')
        need(type(source_domain) is str and source_domain == self.identity.source_domain
             and integer(generation, 1, 2**53-1) and generation == self.generation,
             'LIFECYCLE_SELECTION')
        if now > self._session.binding.valid_until:
            self._invalidate()
            self.state = 'STALE_BINDING'
            raise SavedRefusal('SAVED_LIFECYCLE_EXPIRED')
        try:
            self._session.select(source_domain, generation)
        except Exception:
            self._unknown('LIFECYCLE_IDENTITY_UNPROVEN')
            raise SavedRefusal('SAVED_LIFECYCLE_IDENTITY_UNPROVEN') from None
        return self._session

    def select(self, source_domain, generation):
        """Validate an existing generation, returning immutable metadata only.

        Returning the SavedSession would let callers run its provider after
        releasing the broker lock, racing shutdown. Native work must instead
        run within run_selected's complete selection/action critical section.
        """
        self._enter()
        try:
            return self._select_locked(source_domain, generation).binding
        finally:
            self._lock.release()

    def run_selected(self, source_domain, generation, action):
        """Serialize guard/provider/index work with renewal and shutdown.

        Only explicit safe refusals leave the transport reusable. An ambiguous
        guard, provider, receipt, or identity failure seals the broker without
        retrying or attempting to release possibly live native references.
        """
        need(callable(action) and not inspect.iscoroutinefunction(action), 'LIFECYCLE_ACTION')
        self._enter()
        try:
            session = self._select_locked(source_domain, generation)
            try:
                result = action(session)
                need(not inspect.isawaitable(result), 'LIFECYCLE_ASYNC_ACTION')
                self._usable()
                return result
            except SavedRefusal as error:
                safe = {'SAVED_TARGET_TYPE', 'SAVED_TARGET', 'SAVED_SELECTION_BOUND',
                        'SAVED_SLICE_BOUND', 'SAVED_OFFSET_AFTER_END', 'SAVED_SOURCE_CHANGED',
                        'SAVED_DIRTY_OR_UNKNOWN', 'SAVED_PAGE'}
                if str(error) not in safe:
                    self._unknown('LIFECYCLE_ACTION_UNPROVEN')
                raise
            except Exception:
                self._unknown('LIFECYCLE_ACTION_UNPROVEN')
                raise SavedRefusal('SAVED_LIFECYCLE_ACTION_UNPROVEN') from None
        finally:
            self._lock.release()

    def health(self):
        """Metadata only: no opener, native probe, renewal, or source dispatch."""
        self._enter()
        try:
            now = self._now()
            if self._session is not None and self.state == 'READY' and now > self._session.binding.valid_until:
                self._invalidate()
                self.state = 'STALE_BINDING'
            return dict(status=self.state, generation=self.generation,
                        source_domain=self.identity.source_domain,
                        native_binding_verified=False,
                        provider_binding='trusted_callback_only',
                        last_error=self.last_error, source_read_performed=False,
                        transport_open_performed=False, body_retained=False)
        finally:
            self._lock.release()

    def _close_locked(self):
        if self.state == 'CLOSED':
            return 'CLOSED'
        need(not self._shutdown_attempted, 'LIFECYCLE_CLOSE_ALREADY_ATTEMPTED')
        self._shutdown_attempted = True
        self._invalidate()
        try:
            receipt = self.shutdown()
            need(type(receipt) is ShutdownReceipt and all(getattr(receipt, k) is True for k in
                 ('known_terminal', 'references_closed', 'workers_closed', 'callbacks_closed')),
                 'LIFECYCLE_CLOSE_UNPROVEN')
        except Exception:
            self._unknown('LIFECYCLE_CLOSE_UNPROVEN')
            raise SavedRefusal('SAVED_LIFECYCLE_CLOSE_UNPROVEN') from None
        self.state, self.last_error = 'CLOSED', None
        return 'CLOSED'

    def close_selected(self, source_domain, generation):
        """Close the exact generation, including expired bindings, atomically."""
        self._enter()
        try:
            need(type(source_domain) is str and source_domain == self.identity.source_domain
                 and integer(generation, 1, 2**53-1) and generation == self.generation,
                 'LIFECYCLE_SELECTION')
            return self._close_locked()
        finally:
            self._lock.release()

    def close(self):
        """Attempt transport shutdown once; retain UNKNOWN on uncertain closure."""
        self._enter()
        try:
            return self._close_locked()
        finally:
            self._lock.release()
