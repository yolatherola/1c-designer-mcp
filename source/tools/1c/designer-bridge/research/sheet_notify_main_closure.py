"""Pure source review of the explicit notification bootstrap/composite profile.

The old535+1 source closure is a baseline, not coverage of the extension.
No native/process/connection observation or writer permission is provided.
"""
from pathlib import Path
import json
import re
from zipfile import ZipFile
import io

import current_main_closure_v265 as base
import sheet_notify_bootstrap_recipe as recipe

ROOT=base.ROOT
HERE=Path(__file__).resolve().parent
PINS={'current_main_closure_v265.py':'b588f19f33f68c3081afc092a22d776eb079bffaaa77cd016f124ba8f6310ef2',
      'sheet_notify_bootstrap_recipe.py':'e98df896da014d4ad1d5524c527a91083788b864b2afcde9ac8794ea60470c25',
      'sheet_notify_bootstrap_controller.py':'92a3e7795de324e5a2352f2e2d6f0437dbd49e1f262ba7f20dcca86f288da996',
      'sheet_notify_bootstrap_runtime.py':'ecc7ffca6d8d6803a912292139bff136f8a4ef4cba5a875e2479c9e5faf15966'}
SDK40_SHA='4fbe3e82d2d81db858ec86b39f249fbb8ccf60a5f8e5901e1a5c12486b0fe485'
ARCHIVE_SHA='464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
ENTRY='ahRunnerCompositeSheetNotify'
NATIVE_HANDLE='ahSheetChangeNativeFixedCache'
BASE_EXTERNAL=set('ahContextWindowClassV211 ahContextWindowEnabledV211 ahContextWindowVisibleV211 ahGetCurrentProcessId ahGetCurrentThreadId ahGetTickCount ahGetTopWindow ahGetWindow ahGetWindowThreadProcessId ahListenerQueryPageV51 ahModuleFileName ahModuleFromAddress ahPartLookup ahPerformanceCounter ahPerformanceFrequency ahQueryOwnMemory ahRepositoryStatisticRead ahRepositoryStatusRead ahRoleWindowLongV211 ahWindowFromHwnd'.split())
sha=base.sha


def need(ok,code):
    if not ok:raise ValueError('SHEET_CLOSURE_'+code)


def canonical(row):return json.dumps(row,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _json(path,bound=2097152):
    raw=base._read(path,bound)
    def pairs(items):
        row={}
        for k,v in items:need(k not in row,'DUPLICATE_JSON');row[k]=v
        return row
    row=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE'))
    need(type(row) is dict,'OBJECT');return raw,row


def _strip_helper(main,helper):
    need('\r' not in helper,'HELPER_EOL')
    candidates=[part for part in (helper,helper.replace('\n','\r\n')) if main.count(part)==1]
    need(len(candidates)==1,'ONE_WHOLE_HELPER')
    exact=candidates[0];return main.replace(exact,'',1),exact


def _profile_closure(source,helper,old,new,old_prefix,new_prefix):
    a,b,h=base._functions(old),base._functions(new),base._functions(helper)
    need(set(h)=={'ahSheetNotifyPhaseFixed','ahSheetNotifyPrepare','ahSheetNotifyInvokeVerifiedBinding'},'HELPER_FUNCTION_SET')
    direct=base._calls(source)-{ENTRY};need(len(direct)==29,'DIRECT_29')
    pending=set(direct);seen=set();external=set();rows=[]
    while pending:
        name=pending.pop()
        if name in seen:continue
        if name not in b:
            need(name not in a and name in BASE_EXTERNAL|{NATIVE_HANDLE},'UNKNOWN_EXTERNAL')
            external.add(name);continue
        seen.add(name);right=base._one(b,name);relocations=0
        if name in h:
            left=base._one(h,name);need(right==left,'HELPER_FUNCTION_CHANGED');kind='EXTENSION'
        else:
            left=base._one(a,name);kind='BASELINE'
            if left!=right:relocations=base._diagnostic_relocation(name,left,right,old_prefix,new_prefix)
        rows.append(dict(name=name,kind=kind,sha256=sha(right.encode()),diagnosticPathRelocations=relocations))
        pending|=base._calls(right)-{name}-seen
    need(external==BASE_EXTERNAL|{NATIVE_HANDLE} and set(h)<=seen,'CLOSED_EXTERNALS')
    need(len(seen)==60,'TRANSITIVE_60')
    return dict(directFreeCalls=29,transitiveFunctions=len(seen),baselineFunctions=57,extensionFunctions=3,
                functions=sorted(rows,key=lambda r:r['name']),externalAliases=sorted(external))


def review_current(nonce):
    """Recompute whole tool/source evidence; never assert live freshness."""
    need(type(nonce) is str and re.fullmatch('[a-f0-9]{32}',nonce),'NONCE')
    for name,pin in PINS.items():need(sha(base._read(HERE/name))==pin,'PRODUCER_PIN')
    build=ROOT/'build'/('designer-v43-'+nonce);runtime=build/'runtime';module=runtime/'modules/snegopat'
    proof_raw,proof=_json(ROOT/'artifacts/designer-bridge'/('sheet-notify-bootstrap-result-'+nonce+'.json'),65536)
    old_receipt_raw,receipt=_json(ROOT/'artifacts/designer-bridge'/('v262-held-bootstrap-'+nonce+'.json'),65536)
    need(proof.get('kind')=='SHEET_NOTIFY_BOOTSTRAP_RESULT' and proof.get('nonce')==nonce
         and proof.get('passed') is True and proof.get('bootstrapState')=='READY_HELD'
         and proof.get('wholeExtensionHelperPresent') is True and proof.get('baselineManifestCoversExtension') is False
         and proof.get('nativeBootstrapReceiptSha256')==sha(old_receipt_raw)
         and receipt.get('passed') is True and receipt.get('bootstrapState')=='READY_HELD'
         and proof.get('context')==receipt.get('context') and proof.get('mainSha256')==receipt.get('mainSha256'),
         'EXPLICIT_BOOTSTRAP_PROFILE')
    need(all(type(proof.get(k)) is int and proof[k]==0 for k in ('applicationWrites','configurationSaves','databaseUpdates','repositoryMutations'))
         and proof.get('writerAuthorized') is False and proof.get('baselineSourceManifestSha256')==base.SOURCE536
         and type(proof.get('baselineSourceCount')) is int and proof['baselineSourceCount']==536,'BASELINE_SCOPE')
    private=build/('v208-private-'+nonce);extension_raw,extension=_json(private/'sheet-notify-extension.json')
    meta=extension['plan'];manifest=meta['extensionManifest']
    native_raw,native=_json(private/'plan.json')
    need(meta['nativePlan']==native and sha(canonical(meta))==proof.get('stagePlanSha256')
         and receipt.get('nativePlanSha256')==sha(canonical(native))
         and sha(canonical(manifest))==proof.get('extensionManifestSha256')
         and manifest['extensionSourceSha256']==recipe.source_snapshot(), 'EXTENSION_SOURCE_JOIN')
    for name,pin in native['privateSha256'].items():
        need(type(name) is str and '/' not in name and '\\' not in name and '..' not in name,'PRIVATE_NAME')
        need(sha(base._read(private/name))==pin,'PRIVATE_FILE')
    for name,pin in proof['runtimeSourceSha256'].items():need(sha(base._read(ROOT/name))==pin,'RUNTIME_SOURCE')
    main_raw=base._read(module/'engine/main.as');need(sha(main_raw)==proof['mainSha256'],'MAIN_PIN')
    main=main_raw.decode('utf-8');helper=recipe.derive_helper().decode('utf-8-sig')
    stripped,exact_helper=_strip_helper(main,helper)
    sdk={p.relative_to(runtime/'modules').as_posix():sha(base._read(p)) for p in sorted((runtime/'modules').rglob('*.v'))}
    need(len(sdk)==40 and sha(canonical(sdk))==SDK40_SHA,'ALL_SDK40')
    archive=base._read(build/'snegopat.zip',16777216);need(sha(archive)==ARCHIVE_SHA,'SDK_ARCHIVE')
    archive_checked=0
    with ZipFile(io.BytesIO(archive)) as zipped:
        for name in zipped.namelist():
            if not name.endswith('.as') or name.endswith('/main.as'):continue
            need(not name.startswith(('/', '\\')) and '..' not in Path(name).parts,'ARCHIVE_PATH')
            need(base._read(runtime/name)==zipped.read(name),'SDK_ENGINE_SOURCE');archive_checked+=1
    need(archive_checked==41,'SDK_ENGINE_COUNT')
    old_runtime=ROOT/'build'/('designer-v43-'+base.OLD_NONCE)/'runtime/modules/snegopat'
    old_raw=base._read(old_runtime/'engine/main.as');need(sha(old_raw)==base.MAIN_PIN,'OLD_MAIN')
    old=old_raw.decode('utf-8');sessions=set(re.findall('designer-v43-'+base.OLD_NONCE+'/session-([a-f0-9]{32})/',old))
    need(len(sessions)==1,'OLD_SESSION')
    session=proof['publication']['sessionId'];need(type(session) is str and re.fullmatch('[a-f0-9]{32}',session),'SESSION')
    old_prefix=(old_runtime.parents[2]/('session-'+next(iter(sessions)))).as_posix()
    new_prefix=(build/('session-'+session)).as_posix()
    composer=recipe.load_fixed('runner_composite_v249.py',recipe.COMPOSER_SHA)
    baseline_source=composer.derive_source().decode()
    legacy=base._compare(baseline_source,old,stripped,old_prefix,new_prefix,composer._NATIVE_FREE,composer._NATIVE_METHODS)
    source=recipe.derive_composite().decode()
    # Only the analyzed entry name changes here; actual generated source is
    # untouched. The verifier excludes that function's own declaration.
    analyzed=source.replace('void '+ENTRY+'()', 'void ahRunnerCompositeV249()',1)
    counts=composer.verify_closure(analyzed,main,(module/'v8api/ah_capture_status.v').read_text(encoding='utf-8'),
                                   (module/'v8api/textmgr.v').read_text(encoding='utf-8'))
    need(counts==(29,3),'DIRECT_NATIVE_CLOSURE')
    reviewed=_profile_closure(source,exact_helper,old,main,old_prefix,new_prefix)
    ctx=proof['context']
    return dict(kind='SHEET_NOTIFY_CURRENT_MAIN_CLOSURE',version=1,passed=True,nonce=nonce,
        processId=ctx['processId'],birth=ctx['processCreationFileTimeUtc'],mainSha256=sha(main_raw),
        baselineSourceManifestSha256=base.SOURCE536,baselineManifestCoversExtension=False,
        bootstrapReceiptSha256=sha(proof_raw),stageExtensionReceiptSha256=sha(extension_raw),
        extensionManifestSha256=proof['extensionManifestSha256'],helperSha256=sha(recipe.derive_helper()),
        compositeSha256=sha(recipe.derive_composite()),compositeEntry=ENTRY,sourcePins=dict(PINS),
        sdkFileCount=40,sdkFileClosureSha256=SDK40_SHA,unchangedSdkEngineSources=41,sdkArchiveSha256=ARCHIVE_SHA,
        baselineComparison=legacy,profileComparison=reviewed,commonModuleNativeMethods=3,
        liveFreshnessVerified=False,writerAuthorized=False,applicationExecutionAuthorized=False,sourceBodiesPrinted=False)
