"""Fixed technical context observer over the frozen retained-writer read route.

Only private function globals are adapted. The original reader, RAM owner and
shared SDK module stay unchanged; SDK terminal status is not native success.
"""
from pathlib import Path
from types import FunctionType,SimpleNamespace
import inspect
import json
import re
import uuid
import sheet_notify_pending_read as reader
import editor_modules_pending_save as lease_base

c=reader.c
ROOT=c.ROOT
HERE=c.HERE
READER_SHA='825e7926d8eb8ab360d6413251d661f64be415e97c6ff3073b97ff77d39b4d7a'
SOURCE_NAME='NativeCurrentComparisonProviderObserve.as'
SOURCE_SHA='20747c20e67b1de3f7f38bac2579c0eee1d058a861c7ef5e5fc716fad46c240c'
CHECK_NAME='current-comparison-provider-check-only-c758cdfc20364280a1ddf46f0814e4a2.json'
CHECK_SHA='203c9c2f3cdb822616f203841f9a9c54b7958de34f1e141f0e1583198edb1a11'
PROFILE='CURRENT_COMPARISON_PROVIDER_READ'
LEASE_BASE_SHA='971f50933e69527b1a55ad0dc7d2359d49740e2cdd69b8fe1b9050499f0bd246'
NATIVE_PID=48936
NATIVE_BIRTH='01dd5d0180299126'
NATIVE_GUI=8292
_ISSUER=object()


def need(ok,code):
    if not ok:raise ValueError('COMPARISON_PROVIDER_READ_'+code)


def _source():
    raw=c.read(HERE/SOURCE_NAME)
    need(c.digest(raw)==SOURCE_SHA,'SOURCE_PIN')
    need(set(re.findall(r'__[A-Z][A-Z0-9_]+__',raw.decode()))=={
        '__PROVIDER_SCOPE_ADMITTED__','__OPERATION_ID__','__SCOPE_SHA256__','__PROOF_PATH__'},'SOURCE_TOKENS')
    return raw


class _FixedSource:
    derive_source=staticmethod(_source)


def _profile(profile):
    need(profile==PROFILE,'FIXED_PROFILE')
    return _FixedSource,SOURCE_SHA,CHECK_NAME,CHECK_SHA,SOURCE_NAME,SOURCE_SHA


def _pins(profile=PROFILE):
    _profile(profile)
    need(c.digest(c.read(Path(reader.__file__)))==READER_SHA,'READER_PIN')
    need(c.digest(c.read(HERE/'editor_modules_pending_save.py'))==LEASE_BASE_SHA,'LEASE_HELPER_PIN')
    # Preserve the frozen carrier's dependency and compile checks as well.
    reader._pins(reader.EDITOR_PROFILE)
    _source()
    proof=reader._json(ROOT/'artifacts/designer-bridge'/CHECK_NAME,CHECK_SHA)
    need(proof.get('kind')=='CURRENT_COMPARISON_PROVIDER_CHECK_ONLY' and proof.get('entry')=='ahCurrentComparisonProviderObserve'
        and proof.get('sourceSha256')==SOURCE_SHA and proof.get('scopeAdmitted') is False
        and proof.get('positive',{}).get('compileVerified') is True
        and type(proof.get('positive',{}).get('exitCode')) is int and proof['positive']['exitCode']==0
        and proof.get('negative',{}).get('compileVerified') is False
        and type(proof.get('negative',{}).get('exitCode')) is int and proof['negative']['exitCode']!=0
        and all(proof.get(k) is True for k in ('negativeCoverage','ownRuntimeRemoved'))
        and all(proof.get(k) is False for k in ('goldStarted','scriptRunRequested')),'COLD_CHECK')


def _lease_binding(context):
    """Read the owned bootstrap identity only; no connection/credentials input."""
    raw=c.read(ROOT/'artifacts/designer-bridge'/('sheet-notify-bootstrap-result-'+context['heldNonce']+'.json'),65536)
    boot=c.parse(raw);need(type(boot) is dict,'LEASE_BOOTSTRAP_OBJECT');row=boot.get('context',{})
    need(type(row) is dict,'LEASE_BOOTSTRAP_CONTEXT')
    owner=row.get('leaseOwner')
    need(boot.get('passed') is True and type(owner) is str and c.HEX32.fullmatch(owner)
        and (row.get('processId'),row.get('processCreationFileTimeUtc'))==(context['processId'],context['birth']),
        'LEASE_BOOTSTRAP')
    return owner,c.digest(raw)


def _lease(r):
    owner,pin=_lease_binding(r.plan['context'])
    need((r.plan.get('goldLeaseOwner'),r.plan.get('goldLeaseBootstrapSha256'))==(owner,pin),'LEASE_BINDING')
    lease_base._lease(SimpleNamespace(plan=r.plan,scope={'goldLeaseOwner':owner}))


def _check_adapter(r):
    need(type(r) is reader.Read and r._issuer is _ISSUER,'ISSUED_READ')
    need(r.plan.get('comparisonProviderControllerSha256')==c.digest(c.read(Path(__file__)))
        and r.plan.get('pendingReadControllerSha256')==READER_SHA,'CONTROLLER_DRIFT')
    need(r.plan.get('pendingReadProfile')==PROFILE and r.plan.get('actualReadSourceSha256')==SOURCE_SHA
        and r.plan.get('writerAuthorized') is False and r.plan.get('captureAuthorized') is False
        and type(r.plan.get('applicationWrites')) is int and r.plan['applicationWrites']==0,'FIXED_PLAN')
    ctx=r.plan.get('context',{})
    need((ctx.get('processId'),ctx.get('birth'),ctx.get('guiThreadId'))==(NATIVE_PID,NATIVE_BIRTH,NATIVE_GUI),'FIXED_NATIVE')


def _namespace():
    """Clone only frozen reader functions; preserve all original owner checks."""
    ns=dict(reader.__dict__)
    for name,value in reader.__dict__.items():
        if isinstance(value,FunctionType) and value.__module__==reader.__name__:
            clone=FunctionType(value.__code__,ns,value.__name__,value.__defaults__,value.__closure__)
            clone.__kwdefaults__=value.__kwdefaults__;ns[name]=clone
    owner_check=ns['_check_owner'];carrier_namespace=ns['_namespace']
    def check(r):
        _check_adapter(r)
        intent=owner_check(r);_lease(r);return intent
    def carrier(r):
        private=carrier_namespace(r)
        def render(plan,raw):
            check(r);need(plan==r.plan,'RENDER_PLAN')
            files=c.render(plan,raw);header=files['sdk_probe_params.h'].decode()
            line=next(x for x in header.splitlines() if x.startswith('#define AH_SDK_FIXED_SOURCE '))
            source=_source().decode();values={
                '__PROVIDER_SCOPE_ADMITTED__':'true','__OPERATION_ID__':plan['operationId'],
                '__SCOPE_SHA256__':r.review_sha256,
                '__PROOF_PATH__':(Path(plan['outputDirectory'])/c._probe_spec(reader.PROBE)[3]).as_posix()}
            for token,value in values.items():
                need(source.count(token)==1,'RENDER_TOKEN');source=source.replace(token,value,1)
            header=c._replace_once(header,line,'#define AH_SDK_FIXED_SOURCE '+json.dumps(source,ensure_ascii=False))
            files['sdk_probe_params.h']=header.encode();return files
        private['render']=render;return private
    ns.update(_ISSUER=_ISSUER,_pins=_pins,_profile=_profile,_check_owner=check,_namespace=carrier)
    run=inspect.getsource(reader.run_root_once)
    anchors=(
        ("profile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],rootReadReviewSha256=review_sha256,",
         "profile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],rootReadReviewSha256=review_sha256,\n"
         "        comparisonProviderControllerSha256=p['comparisonProviderControllerSha256'],"),
        ("pendingReadProfile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],",
         "pendingReadProfile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],\n"
         "                    comparisonProviderControllerSha256=p['comparisonProviderControllerSha256'],"),
        ("result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=p['operationId'],",
         "result=dict(version=233,status='UNKNOWN_RETAIN',knownTerminal=False,operationId=p['operationId'],\n"
         "        pendingReadProfile=p['pendingReadProfile'],actualReadSourceSha256=p['actualReadSourceSha256'],\n"
         "        comparisonProviderControllerSha256=p['comparisonProviderControllerSha256'],"))
    for old,new in anchors:need(run.count(old)==1,'RUN_PROVENANCE_ANCHOR');run=run.replace(old,new,1)
    exec(compile(run,'<fixed-comparison-cache-read-run>','exec'),ns)
    return ns


def prepare_root(review_path,review_sha256,*,profile=PROFILE):
    """Issue a fixed read only after pin checks and retained-owner root review."""
    _pins(profile);ns=_namespace()
    path=c._plain(review_path,ROOT/'artifacts/designer-bridge');scope=reader._json(path,review_sha256)
    need(c.HEX32.fullmatch(scope['sessionNonce']) and c.HEX32.fullmatch(scope['writerOperationId']),'SCOPE_IDS')
    ctx=c._context(scope['sessionNonce']);sdk=c.inspect_owned(ctx);op=uuid.uuid4().hex;spec=c._probe_spec(reader.PROBE)
    plan=dict(version=233,probe=reader.PROBE,operationId=op,outputDirectory=str(ROOT/'build'/('designer-hot-v233-'+op)),
        context=ctx,sdkIdentity=sdk,probeSha256=spec[2],controllerSha256=reader.PARENT_SHA,
        testSha256=c.digest(c.read(HERE.parent/'tests/test_live_sdk_continuation_v233.py')),nativeDriverPins=dict(c.SOURCE_PINS),
        writerAuthorized=False,captureAuthorized=False,applicationWrites=0,configurationExports=0,configurationImports=0,
        oneShot=True,loadedDllRequiresTargetExitBeforeCleanup=True,pendingReadProfile=PROFILE,
        actualReadSourceSha256=SOURCE_SHA,pendingReadControllerSha256=READER_SHA,
        comparisonProviderControllerSha256=c.digest(c.read(Path(__file__))),
        pendingScopeSha256=review_sha256,parentWriterOperationId=scope['writerOperationId'])
    plan['goldLeaseOwner'],plan['goldLeaseBootstrapSha256']=_lease_binding(ctx)
    r=reader.Read(_ISSUER,path,review_sha256,scope,plan,c.canonical(plan),{})
    ns['_check_owner'](r);r.private=ns['_namespace'](r);r.private['_no_pending'](context=ctx);return r


def stage_root(r):
    """Stage the issued fixed observer; no native execution or parent release."""
    return _namespace()['stage_root'](r)


def run_root_once(r,review_path,review_sha256):
    """Use the original one-attempt audit/run route and report SDK facts only."""
    return _namespace()['run_root_once'](r,review_path,review_sha256)
