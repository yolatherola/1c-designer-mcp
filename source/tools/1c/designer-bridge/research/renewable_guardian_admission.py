"""Private original-Root admission after any proven closed guardian episode.

The prior episode is bound in the new reviewed scope, not an ambient latest
file. Kernel prior-owner exit, current target identity/lease and all historical
UNKNOWN guards remain mandatory. No same-owner reuse or native dispatch exists.
"""
import importlib
from pathlib import Path
import re
from types import FunctionType, SimpleNamespace

import guardian_native_admission as previous

root=previous.root
HERE=Path(__file__).resolve().parent
PREVIOUS_SHA='5f8aad5ea45df9d3e56f58054e7a48c4c4fc41eaa4bb3c24cf8e30b3f1f6bc6b'
AUDIT_NAME='daemon_guardian_closure_audit'
AUDIT_SHA='dc74b681f0d1a2dc098ed4199a19935e46a667f827b41762a589b22ab791e3dc'
RUNTIME_SHA='8d27e9db466e7d4dbbe6a23f0a7f28c487426980fa784d292cfcec8158d8b206'
HOST_SHA='d79f2ad6c12c181aebb126e7cf6894284cb6da0b20bb1eb260274a15e523ce3a'


def need(ok,code):
    if not ok:raise ValueError('RENEWABLE_ADMISSION_'+code)
def _hex(value,size):return type(value) is str and re.fullmatch('[0-9a-f]{'+str(size)+'}',value) is not None and value!='0'*size


def _pins():
    need(root.c.digest(root.c.read(Path(previous.__file__)))==PREVIOUS_SHA,'PREVIOUS_PIN')
    need(_hex(AUDIT_SHA,64) and root.c.digest(root.c.read(HERE/(AUDIT_NAME+'.py')))==AUDIT_SHA,'AUDIT_PIN')
    need(root.c.digest(root.c.read(HERE/'guardian_episode_runtime.py'))==RUNTIME_SHA,'RUNTIME_PIN')
    need(root.c.digest(root.c.read(HERE/'native_guardian_host.py'))==HOST_SHA,'HOST_PIN')
    previous._pins()


def validate_scope(row):
    """Old Root authority/pins plus explicit new prior and pure-checker joins."""
    previous.validate_scope(row)
    need(row.get('renewableGuardianAdmissionSha256')==root.c.digest(root.c.read(Path(__file__)))
        and row.get('daemonGuardianClosureAuditSha256')==AUDIT_SHA and row.get('daemonRuntimeSha256')==RUNTIME_SHA
        and row.get('guardianEpisodeWorkerSha256')==root.c.digest(root.c.read(HERE/'guardian_episode_worker.py'))
        and _hex(row.get('priorGuardianOperationId'),32) and _hex(row.get('priorGuardianPlanSha256'),64),'SCOPE_PINS')


def _prior_plan(scope):
    op=scope.get('priorGuardianOperationId');pin=scope.get('priorGuardianPlanSha256')
    need(_hex(op,32) and _hex(pin,64),'PRIOR_SCOPE')
    path=root.ROOT/'build'/('designer-hot-v233-'+op)/'plan.json'
    need(path.resolve().is_relative_to((root.ROOT/'build').resolve()),'PRIOR_PATH')
    plan=root.reader._json(path)
    need(type(plan) is dict and plan.get('operationId')==op and root.c.digest(root.c.canonical(plan))==pin,'PRIOR_PLAN')
    return plan


def _prior_owner_gone(plan,result):
    """Exact frozen worker algorithm, dynamically bound to audited PID/birth.

    An existing current owner is refused even if metadata says resources closed.
    An inaccessible or recycled PID is unknown, never a replacement authority.
    """
    cfg=plan.get('residentConfiguration',{})
    need(type(cfg.get('serverPid')) is int and 0<cfg['serverPid']<2**32 and _hex(cfg.get('serverBirth'),16)
        and result.get('priorOwnerProcessId')==cfg['serverPid'] and result.get('priorOwnerBirth')==cfg['serverBirth'],'PRIOR_OWNER')
    original=previous.previous.previous._prior_worker_gone
    fn=FunctionType(original.__code__,dict(original.__globals__,SERVER_PID=cfg['serverPid'],SERVER_BIRTH=cfg['serverBirth']),
        original.__name__,original.__defaults__,original.__closure__)
    return fn(plan)


def _checked_audit(plan):
    _pins()
    result=importlib.import_module(AUDIT_NAME).audit_closed(plan)
    need(result.get('classification')=='DAEMON_GUARDIAN_RESOURCES_CLOSED' and result.get('resourcesClosed') is True
        and result.get('freshPriorOwnerExitCheckRequired') is True and result.get('priorOwnerExitVerified') is False
        and result.get('sameOwnerReuseAuthorized') is False and result.get('dispatchAuthorized') is False,'CLOSURE_CLASSIFICATION')
    _prior_owner_gone(plan,result)
    root.base._lease(SimpleNamespace(plan=plan))
    root.c._fresh(root.base._carrier_view(plan))
    return result


def _candidate(plan):
    """Recognize only a bounded guardian artifact candidate, never waive it."""
    if type(plan) is not dict or not _hex(plan.get('operationId'),32):return False
    if plan.get('updatePreviewControllerSha256')!=previous.previous.previous.ROOT_SHA:return False
    if plan.get('actualSourceSha256')!=root.SOURCE_SHA:return False
    path=root.ROOT/'artifacts/designer-bridge'/('native-guardian-runtime-'+plan['operationId']+'.json')
    return path.exists()  # Full schema/proof audit must succeed before continue.


def _extra_factory(factory):
    reader=factory.__globals__['reader'];inspect=factory.__globals__['inspect']
    def namespace(parent):
        ns=reader._namespace(parent)
        ns.update(__renewable_guardian_candidate=_candidate,__renewable_guardian_audit=_checked_audit)
        return ns
    def getsource(target):
        text=inspect.getsource(target)
        if target is root.c._no_pending:
            anchor='        if prior_identity!=identity: continue\n'
            need(text.count(anchor)==1,'AUDIT_ANCHOR')
            text=text.replace(anchor,anchor+'        if __renewable_guardian_candidate(prior):\n'
                '            __renewable_guardian_audit(prior);continue\n',1)
        return text
    reader_proxy=SimpleNamespace(**dict(reader.__dict__));reader_proxy._namespace=namespace
    inspect_proxy=SimpleNamespace(**dict(inspect.__dict__));inspect_proxy.getsource=getsource
    return root.previous._private_factory(factory,reader=reader_proxy,inspect=inspect_proxy)


def _prepare_parent(path,pin):
    def composed(factory):return previous._extra_factory(_extra_factory(factory))
    fn=FunctionType(previous._prepare_parent.__code__,dict(previous._prepare_parent.__globals__,
        _extra_factory=composed,validate_scope=validate_scope),previous._prepare_parent.__name__,
        previous._prepare_parent.__defaults__,previous._prepare_parent.__closure__)
    return fn(path,pin)


def _check(s):
    previous._check(s);_pins()
    scope=root.reader._json(s.scope_path,s.scope_sha256);validate_scope(scope)
    need(scope==s.scope and scope['priorGuardianOperationId']!=s.plan['operationId'],'SCOPE_CHANGED')
    _checked_audit(_prior_plan(scope))


def prepare_root(path,pin,*,priorplan=None):
    """Return the original issued Root5a operation; no stage/start is implicit.

    Scope selects the prior by operation+canonical hash. Optional trusted input
    only cross-checks that same prior; it cannot override the selected file.
    """
    _pins();scope_path=root.c._plain(path,root.ROOT/'artifacts/designer-bridge')
    scope=root.reader._json(scope_path,pin);validate_scope(scope);prior=_prior_plan(scope)
    if priorplan is not None:need(type(priorplan) is dict and root.c.canonical(priorplan)==root.c.canonical(prior),'EXPLICIT_PRIOR')
    _checked_audit(prior)
    fn=FunctionType(previous.prepare_root.__code__,dict(previous.prepare_root.__globals__,_pins=_pins,
        validate_scope=validate_scope,_prepare_parent=_prepare_parent,_check=_check),previous.prepare_root.__name__,
        previous.prepare_root.__defaults__,previous.prepare_root.__closure__)
    s=fn(scope_path,pin)
    try:
        _check(s);return s
    except BaseException:
        root.abort_before_start(s);raise


def create_host(path,pin):
    """Construct the exact frozen host using new private admission globals.

    The original constructor and original issued operation/classes are used.
    No module global, class method, issuer or __file__ is forged or replaced.
    """
    _pins();host=importlib.import_module('native_guardian_host')
    def combined_scope(row):
        host.validate_scope(row);validate_scope(row)
    proxy=SimpleNamespace(**dict(host.admission.__dict__));proxy.prepare_root=prepare_root
    constructor=host.NativeGuardianHost.__init__
    fn=FunctionType(constructor.__code__,dict(constructor.__globals__,admission=proxy,validate_scope=combined_scope),
        constructor.__name__,constructor.__defaults__,constructor.__closure__)
    value=host.NativeGuardianHost.__new__(host.NativeGuardianHost)
    fn(value,path,pin)
    need(type(value) is host.NativeGuardianHost and type(value.operation) is root.ResidentOperation
        and value.operation.issuer is root._ISSUER,'ORIGINAL_ISSUER')
    return value
