"""Fixed private admission after both closed4587 and full-read e5 sessions.

Only historical exceptions and their own worker identities are added. Original
Root5a source, authority, plan pin, operation type and native entry points remain
unchanged. Every new installation still requires a separate reviewed scope/run.
"""
import importlib
from pathlib import Path
from types import FunctionType, SimpleNamespace

import resident_session_admission as previous

root = previous.root
HERE = Path(__file__).resolve().parent
PREVIOUS_SHA = '3bfc223fb21b6fc1280490f3d07a9acf57e6db9647fce72e813b4e54562e4d4c'
AUDIT_NAME = 'resident_full_read_closure_audit'
AUDIT_SHA = '28a3403ebbc796b10e4719069502097aab1f45cfd773d26a2ed1046ec59bb6a2'
MANIFEST = root.ROOT/'artifacts/designer-bridge/resident-full-read-closed-e5d117867fda41c1a9810e14a5b7ba6b-manifest.json'
MANIFEST_SHA = '3809bbfe69ae67f402d7843500304e0d48697775151d8b5b9fb3502d54ba7662'
OPERATION = 'e5d117867fda41c1a9810e14a5b7ba6b'
PLAN_SHA = '2c0d1c432fef8486d20ccb785ca0bbd8483d5806d4b796de7e67f9dcee08d116'
PRIOR_PLAN = root.ROOT/('build/designer-hot-v233-'+OPERATION)/'plan.json'
SERVER_PID = 41872
SERVER_BIRTH = '01dd5ee2698cf4df'


def need(ok, code):
    if not ok:
        raise ValueError('PERSISTENT_ADMISSION_'+code)


def _pins():
    need(root.c.digest(root.c.read(Path(previous.__file__))) == PREVIOUS_SHA, 'PREVIOUS_PIN')
    need(root.c.digest(root.c.read(HERE/(AUDIT_NAME+'.py'))) == AUDIT_SHA, 'AUDIT_PIN')
    need(root.c.digest(root.c.read(MANIFEST, 32768)) == MANIFEST_SHA, 'MANIFEST_PIN')
    previous._pins()


def validate_scope(row):
    """Require both adapters/audits in a new, unchanged Root5a read scope."""
    previous.validate_scope(row)
    need(row.get('persistentMcpAdmissionSha256') == root.c.digest(root.c.read(Path(__file__)))
         and row.get('fullReadClosureAuditSha256') == AUDIT_SHA
         and row.get('fullReadClosureManifestSha256') == MANIFEST_SHA, 'SCOPE_PINS')


def _prior_helper(function):
    # Reuse the exact frozen plan/kernel algorithm, only for this fixed episode.
    return FunctionType(function.__code__, dict(function.__globals__,
        OPERATION=OPERATION, PLAN_SHA=PLAN_SHA, PRIOR_PLAN=PRIOR_PLAN,
        SERVER_PID=SERVER_PID, SERVER_BIRTH=SERVER_BIRTH),
        function.__name__, function.__defaults__, function.__closure__)


def _prior_plan():
    return _prior_helper(previous._prior_plan)()


def _prior_worker_gone(plan):
    return _prior_helper(previous._prior_worker_gone)(plan)


def _checked_audit(plan):
    _pins()
    result = importlib.import_module(AUDIT_NAME).audit_closed(plan)
    need(result.get('classification') == 'RESIDENT_FULL_READ_SESSION_RESOURCES_CLOSED'
         and result.get('freshServerWorkerExitCheckRequired') is True, 'CLOSURE_CLASSIFICATION')
    _prior_worker_gone(plan)
    root.base._lease(SimpleNamespace(plan=plan))
    root.c._fresh(root.base._carrier_view(plan))
    return result


def _extra_factory(factory):
    reader = factory.__globals__['reader']; inspect = factory.__globals__['inspect']
    def namespace(parent):
        ns = reader._namespace(parent)
        ns.update(__full_read_closed_operation=OPERATION, __full_read_closed_audit=_checked_audit)
        return ns
    def getsource(target):
        text = inspect.getsource(target)
        if target is root.c._no_pending:
            anchor = '        if prior_identity!=identity: continue\n'
            need(text.count(anchor) == 1, 'AUDIT_ANCHOR')
            text = text.replace(anchor, anchor+
                '        if operation==__full_read_closed_operation:\n'
                '            __full_read_closed_audit(prior);continue\n', 1)
        return text
    reader_proxy = SimpleNamespace(**dict(reader.__dict__)); reader_proxy._namespace = namespace
    inspect_proxy = SimpleNamespace(**dict(inspect.__dict__)); inspect_proxy.getsource = getsource
    return root.previous._private_factory(factory, reader=reader_proxy, inspect=inspect_proxy)


def _prepare_parent(path, pin):
    def composed(factory):
        return previous._extra_factory(_extra_factory(factory))
    fn = FunctionType(previous._prepare_parent.__code__,
        dict(previous._prepare_parent.__globals__, _extra_factory=composed, validate_scope=validate_scope),
        previous._prepare_parent.__name__, previous._prepare_parent.__defaults__, previous._prepare_parent.__closure__)
    return fn(path, pin)


def _check(s):
    previous._check(s)
    _pins()
    scope = root.reader._json(s.scope_path, s.scope_sha256)
    validate_scope(scope)
    need(scope == s.scope, 'SCOPE_CHANGED')
    _prior_worker_gone(_prior_plan())


def prepare_root(path, pin):
    """Prepare the original Root operation with both bound admission guards.

    No native install/open/read is implicit. Original stage/require_stage use the
    returned operation's private _fresh; additional pin failures close only its
    still-unused channel through the original abort routine.
    """
    _pins()
    scope_path = root.c._plain(path, root.ROOT/'artifacts/designer-bridge')
    validate_scope(root.reader._json(scope_path, pin))
    _prior_worker_gone(_prior_plan())
    fn = FunctionType(previous.prepare_root.__code__,
        dict(previous.prepare_root.__globals__, _pins=_pins, validate_scope=validate_scope,
             _prepare_parent=_prepare_parent, _check=_check),
        previous.prepare_root.__name__, previous.prepare_root.__defaults__, previous.prepare_root.__closure__)
    s = fn(scope_path, pin)
    try:
        _check(s)
        return s
    except BaseException:
        root.abort_before_start(s)
        raise
