"""Fixed guardian admission after closed4587, full-read e5 and frontend aaf4.

Only historical exceptions and their own worker identities are added. Original
Root5a source, authority, plan pin, operation type and native entry points remain
unchanged. Every new installation still requires a separate reviewed scope/run.
"""
import importlib
from pathlib import Path
from types import FunctionType, SimpleNamespace

import persistent_mcp_admission as previous

root = previous.root
HERE = Path(__file__).resolve().parent
PREVIOUS_SHA = '4179e0c9e7526b4c8a48e7da1ba7f7fd9fef7fec22564e0208c8b65ff565aeea'
AUDIT_NAME = 'persistent_frontend_closure_audit'
AUDIT_SHA = '4be25ce025c5aeaee08b7746dbf535fc9f88da8e2b763bc15f077b5ba148e687'
MANIFEST = root.ROOT/'artifacts/designer-bridge/persistent-frontend-closed-aaf4cbe0a3a64e4ea4ddacadd7cd60d9-manifest.json'
MANIFEST_SHA = '5d1a24045b60405965ff6129163f8e13f972a6735a7043457f58ec0b36d785fd'
OPERATION = 'aaf4cbe0a3a64e4ea4ddacadd7cd60d9'
PLAN_SHA = '5cd9b806787060bd752a870f1ccedfc95ef92062d163ad599e7b933ff264d33d'
PRIOR_PLAN = root.ROOT/('build/designer-hot-v233-'+OPERATION)/'plan.json'
SERVER_PID = 22520
SERVER_BIRTH = '01dd5ee5926b846a'


def need(ok, code):
    if not ok:
        raise ValueError('GUARDIAN_NATIVE_ADMISSION_'+code)


def _pins():
    need(root.c.digest(root.c.read(Path(previous.__file__))) == PREVIOUS_SHA, 'PREVIOUS_PIN')
    need(root.c.digest(root.c.read(HERE/(AUDIT_NAME+'.py'))) == AUDIT_SHA, 'AUDIT_PIN')
    need(root.c.digest(root.c.read(MANIFEST, 32768)) == MANIFEST_SHA, 'MANIFEST_PIN')
    previous._pins()


def validate_scope(row):
    """Require all adapters/audits in a new, unchanged Root5a read scope."""
    previous.validate_scope(row)
    need(row.get('guardianNativeAdmissionSha256') == root.c.digest(root.c.read(Path(__file__)))
         and row.get('persistentFrontendClosureAuditSha256') == AUDIT_SHA
         and row.get('persistentFrontendClosureManifestSha256') == MANIFEST_SHA, 'SCOPE_PINS')


def _prior_helper(function):
    # Reuse the exact frozen plan/kernel algorithm, only for this fixed episode.
    return FunctionType(function.__code__, dict(function.__globals__,
        OPERATION=OPERATION, PLAN_SHA=PLAN_SHA, PRIOR_PLAN=PRIOR_PLAN,
        SERVER_PID=SERVER_PID, SERVER_BIRTH=SERVER_BIRTH),
        function.__name__, function.__defaults__, function.__closure__)


def _prior_plan():
    return _prior_helper(previous.previous._prior_plan)()


def _prior_worker_gone(plan):
    return _prior_helper(previous.previous._prior_worker_gone)(plan)


def _checked_audit(plan):
    _pins()
    result = importlib.import_module(AUDIT_NAME).audit_closed(plan)
    need(result.get('classification') == 'PERSISTENT_FRONTEND_SESSION_RESOURCES_CLOSED'
         and result.get('freshServerWorkerExitCheckRequired') is True, 'CLOSURE_CLASSIFICATION')
    _prior_worker_gone(plan)
    root.base._lease(SimpleNamespace(plan=plan))
    root.c._fresh(root.base._carrier_view(plan))
    return result


def _extra_factory(factory):
    reader = factory.__globals__['reader']; inspect = factory.__globals__['inspect']
    def namespace(parent):
        ns = reader._namespace(parent)
        ns.update(__guardian_frontend_closed_operation=OPERATION, __guardian_frontend_closed_audit=_checked_audit)
        return ns
    def getsource(target):
        text = inspect.getsource(target)
        if target is root.c._no_pending:
            anchor = '        if prior_identity!=identity: continue\n'
            need(text.count(anchor) == 1, 'AUDIT_ANCHOR')
            text = text.replace(anchor, anchor+
                '        if operation==__guardian_frontend_closed_operation:\n'
                '            __guardian_frontend_closed_audit(prior);continue\n', 1)
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
    """Prepare the original Root operation with all bound admission guards.

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
