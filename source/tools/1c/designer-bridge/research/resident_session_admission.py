"""Fixed private admission of a new resident read after exact closed4587.

Historical closure grants no current authority. The caller must supply a new
Root5a scope binding this adapter and the fixed audit/manifest. Native dispatch
remains exclusively in the unchanged Root5a stage/start/close functions.
"""
import ctypes
import importlib
from pathlib import Path
from types import FunctionType, SimpleNamespace

import resident_saved_module_operation as root

HERE = Path(__file__).resolve().parent
ROOT_SHA = '5a6384b247b2070cf0d8eddbe9632b37d301f426d512943ab7a92352aa094bff'
AUDIT_NAME = 'resident_saved_session_closure_audit'
AUDIT_SHA = '0da8c6eb1234c5b5cba7c1f15740dae36fa2ae4069ac6571f4fecb54e5af2d8a'
MANIFEST = root.ROOT/'artifacts/designer-bridge/resident-saved-session-closed-4587a158919e494dbb8e08176e42fc89-manifest.json'
MANIFEST_SHA = '53236d0bef10070f7181407539a9242566a4d6dec7ae3481b1e38e9e94a9afab'
OPERATION = '4587a158919e494dbb8e08176e42fc89'
PLAN_SHA = '9075692f2b36f17694f2bd3ea8468e0eb758de94322ca5ab99e8b67c998b9f93'
PRIOR_PLAN = root.ROOT/('build/designer-hot-v233-'+OPERATION)/'plan.json'
SERVER_PID = 44184
SERVER_BIRTH = '01dd5edec380283a'


def need(ok, code):
    if not ok:
        raise ValueError('RESIDENT_ADMISSION_'+code)


def _pins():
    need(root.c.digest(root.c.read(Path(root.__file__))) == ROOT_SHA, 'ROOT_PIN')
    need(root.c.digest(root.c.read(HERE/(AUDIT_NAME+'.py'))) == AUDIT_SHA, 'AUDIT_PIN')
    need(root.c.digest(root.c.read(MANIFEST, 32768)) == MANIFEST_SHA, 'MANIFEST_PIN')
    root._pins()


def validate_scope(row):
    """Require new Root authority and all three additional immutable joins."""
    root.validate_scope(row)
    need(row.get('residentAdmissionAdapterSha256') == root.c.digest(root.c.read(Path(__file__)))
         and row.get('closedResidentAuditSha256') == AUDIT_SHA
         and row.get('closedResidentManifestSha256') == MANIFEST_SHA, 'SCOPE_PINS')


def _prior_plan():
    plan = root.reader._json(PRIOR_PLAN)
    need(root.c.digest(root.c.canonical(plan)) == PLAN_SHA and plan.get('operationId') == OPERATION, 'PRIOR_PLAN')
    configuration = plan.get('residentConfiguration', {})
    need(type(configuration.get('serverPid')) is int and configuration['serverPid'] == SERVER_PID
         and configuration.get('serverBirth') == SERVER_BIRTH, 'PRIOR_SERVER_BINDING')
    return plan


def _prior_worker_gone(plan):
    """Fresh kernel check; absent PID or exited exact incarnation only.

    An inaccessible, live or recycled PID is refused conservatively. No process
    is terminated, waited on with a timeout, or treated as a new read authority.
    """
    configuration = plan.get('residentConfiguration', {})
    need(type(configuration.get('serverPid')) is int and configuration['serverPid'] == SERVER_PID
         and configuration.get('serverBirth') == SERVER_BIRTH, 'PRIOR_SERVER_BINDING')
    api = root._Api()
    ctypes.set_last_error(0)
    handle = api.k.OpenProcess(0x101000, False, SERVER_PID)
    if not handle:
        need(ctypes.get_last_error() == 87, 'PRIOR_SERVER_STATE_UNKNOWN')
        return
    try:
        need(api.birth(handle) == SERVER_BIRTH, 'PRIOR_SERVER_RECYCLED')
        need(api.w.WaitForSingleObject(handle, 0) == 0, 'PRIOR_SERVER_NOT_EXITED')
    finally:
        api.w.CloseHandle(handle)


def _checked_audit(plan):
    _pins()
    audit = importlib.import_module(AUDIT_NAME)
    result = audit.audit_closed(plan)
    need(result.get('classification') == 'RESIDENT_SAVED_RAM_SESSION_RESOURCES_CLOSED'
         and result.get('freshServerWorkerExitCheckRequired') is True, 'CLOSURE_CLASSIFICATION')
    _prior_worker_gone(plan)
    root.base._lease(SimpleNamespace(plan=plan))
    root.c._fresh(root.base._carrier_view(plan))
    return result


def _extra_factory(factory):
    """Add exactly one historical branch in this factory's private globals."""
    original_reader = factory.__globals__['reader']
    original_inspect = factory.__globals__['inspect']
    def namespace(parent):
        ns = original_reader._namespace(parent)
        ns.update(__closed_resident_operation=OPERATION, __closed_resident_audit=_checked_audit)
        return ns
    def getsource(target):
        text = original_inspect.getsource(target)
        if target is root.c._no_pending:
            anchor = '        if prior_identity!=identity: continue\n'
            need(text.count(anchor) == 1, 'AUDIT_ANCHOR')
            text = text.replace(anchor, anchor+
                '        if operation==__closed_resident_operation:\n'
                '            __closed_resident_audit(prior);continue\n', 1)
        return text
    reader_proxy = SimpleNamespace(**dict(original_reader.__dict__)); reader_proxy._namespace = namespace
    inspect_proxy = SimpleNamespace(**dict(original_inspect.__dict__)); inspect_proxy.getsource = getsource
    return root.previous._private_factory(factory, reader=reader_proxy, inspect=inspect_proxy)


def _prepare_parent(path, pin):
    # Existing Root5a adds CBC and120b around this already private factory.
    original = root.previous.prior.maintenance
    factory = _extra_factory(original.private_prepare())
    maintenance = SimpleNamespace(**dict(original.__dict__)); maintenance.private_prepare = lambda: factory
    prior = SimpleNamespace(**dict(root.previous.prior.__dict__)); prior.maintenance = maintenance
    previous = SimpleNamespace(**dict(root.previous.__dict__)); previous.prior = prior
    fn = FunctionType(root.prepare_parent.__code__,
        dict(root.prepare_parent.__globals__, previous=previous, validate_scope=validate_scope),
        root.prepare_parent.__name__, root.prepare_parent.__defaults__, root.prepare_parent.__closure__)
    return fn(path, pin)


def _check(s):
    root._check(s)
    _pins()
    scope = root.reader._json(s.scope_path, s.scope_sha256)
    validate_scope(scope)
    need(scope == s.scope, 'SCOPE_CHANGED')
    _prior_worker_gone(_prior_plan())


def prepare_root(path, pin):
    """Prepare only; return the original Root5a operation with bound guards.

    New authority is validated before parent creation. The private root's bound
    _fresh checks these pins again after creation and in original stage/require
    stage, before any future start. A failure closes only our unused channel.
    """
    _pins()
    scope_path = root.c._plain(path, root.ROOT/'artifacts/designer-bridge')
    validate_scope(root.reader._json(scope_path, pin))
    _prior_worker_gone(_prior_plan())
    fn = FunctionType(root.prepare_root.__code__,
        dict(root.prepare_root.__globals__, prepare_parent=_prepare_parent,
             validate_scope=validate_scope, _check=_check),
        root.prepare_root.__name__, root.prepare_root.__defaults__, root.prepare_root.__closure__)
    s = fn(scope_path, pin)
    try:
        _check(s)
        return s
    except BaseException:
        root.abort_before_start(s)
        raise
