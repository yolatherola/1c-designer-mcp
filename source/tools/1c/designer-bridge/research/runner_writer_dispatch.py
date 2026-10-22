"""Exact writer263 root dispatcher. Import inert; no CLI or arbitrary input.

Stage compiles fixed tools. Run is a separate typed, review-bound capability.
All outcomes retain the shared reservation, packet and native checkpoints until
an independent root saved/rollback/refusal finalization. No Save/DB/repository.
"""
from dataclasses import dataclass
import ctypes as ct
import hashlib
import json
from pathlib import Path
import subprocess
import time
import runner_write_admission_v258 as admission
import runner_writer_stage_v263 as package
from ram_transport_v238 import Lease,RamTransport

ROOT=Path(__file__).resolve().parents[4]
PACKAGE_SHA='f4fea8a7f7aeda99a904610d733e554f20f0cbaffdcea512a965c026f6c58208'
PS=Path('C:/Windows/SysWOW64/WindowsPowerShell/v1.0/powershell.exe')
_HOSTS={}


def _need(ok,reason):
    if not ok:raise ValueError('WRITER_'+reason)


def _sha(raw):return hashlib.sha256(raw).hexdigest()


def _canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()


def _controller():
    package._read('runner_writer_stage_v263.py',PACKAGE_SHA)
    return package._load('live_sdk_continuation_v233.py',package.PARENT_SHA)


def _facts(t):
    context=dict(heldNonce=t.held_nonce,buildDirectory=t.build_directory,registrySha256=t.registry_sha256,
        processId=t.process_id,birth=t.birth,guiThreadId=t.gui_thread_id,
        sourceManifestSha256=t.source_manifest_sha256,mainSha256=t.main_sha256,
        corePath=t.core_path,snegopatPath=t.snegopat_path)
    sdk=dict(engineAddress=t.engine_address,moduleAddress=t.module_address,coreBase=t.core_base,
        snegopatBase=t.snegopat_base,engineTableRva=t.engine_table_rva,moduleTableRva=t.module_table_rva,
        moduleCount=t.module_count,guiThreadId=t.gui_thread_id)
    return context,sdk


def _fresh(c,intent,lease,technical,*,ready):
    _need(type(intent) is admission.WriterIntent and type(lease) is Lease
          and type(technical) is package.TechnicalContext,'INPUT_TYPES')
    _need(lease.receipt==intent.request.receipt and lease.state in
          (('READY',) if ready else ('DISPATCHED','UNKNOWN')),'LEASE_SCOPE_STATE')
    intent.metadata()  # Revalidates current265 closure; no packet body logging.
    package._read('runner_writer_stage_v263.py',PACKAGE_SHA);package._pins(intent.request.review.composition_profile)
    context,sdk=_facts(technical)
    _need(c._context(technical.held_nonce)==context,'CURRENT_REGISTRY_SOURCE536_MAIN')
    _need(c.inspect_owned(context)==sdk,'CURRENT_TARGET_SDK_IDENTITY')
    return context


def _prepared(c,intent,lease,technical):
    files=package.render_stage(intent,lease,technical)
    proof=package.package_proof(intent,lease,technical)
    out=c._plain(proof['outputDirectory'],ROOT/'build')
    _need(out==ROOT/'build'/(package.NAMESPACE+intent.request.receipt.operation_id),'OUTPUT_SCOPE')
    _need(set(files)==package.FILES and all(type(v) is bytes and _sha(v)==proof['packageHashes'][n]
          for n,v in files.items()),'PACKAGE_JOIN')
    return files,proof,out


def _sealed(c,files,out):
    _need(all(c.read(out/name,262144)==raw for name,raw in files.items()),'SEALED_FILES_CHANGED')


@dataclass(frozen=True,slots=True)
class StageGrant:
    intent_sha256:str
    package_sha256:str
    root_authorized:bool=False
    mode:str='ROOT_STAGE_WRITER_V263'


@dataclass(frozen=True,slots=True)
class RunGrant:
    intent_sha256:str
    package_sha256:str
    build_sha256:str
    review_path:str
    review_sha256:str
    root_authorized:bool=False
    mode:str='ROOT_RUN_WRITER_V263'


def _grant(intent,proof,grant,kind):
    _need(type(grant) is kind and grant.root_authorized is True and grant.mode==
          ('ROOT_STAGE_WRITER_V263' if kind is StageGrant else 'ROOT_RUN_WRITER_V263')
          and grant.intent_sha256==intent.sha256() and grant.package_sha256==_sha(_canonical(proof)),'ROOT_GRANT')


def _carrier(c,files,out):
    compiler,compiler_sha=c._carrier_compiler()
    library=out/'OwnedCarrierPreflight.dll'
    result=subprocess.run([str(compiler),'/nologo','/target:library','/platform:x86','/out:'+str(library),
        str(out/'OwnedSdkDiagnosisHook.cs'),str(out/'OwnedSdkReadonlyAttach.cs')],cwd=out,
        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
        creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    _need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=16384,'CARRIER_COMPILE')
    library_sha=_sha(c.read(library))
    _need(c._carrier_compiler()==(compiler,compiler_sha),'CARRIER_COMPILER_CHANGED');_sealed(c,files,out)
    return dict(carrierCompilerSha256=compiler_sha,carrierAssemblySha256=library_sha,
        carrierCompileExitCode=0,carrierPreflightOnly=True,carrierAssemblyExecuted=False)


def stage_private(intent,lease,technical,grant,*,transport):
    """CREATE_NEW package + C# preflight + TCC, no intent, load or dispatch."""
    _need(type(transport) is RamTransport,'TRANSPORT_TYPE');transport._owned(lease)
    c=_controller();files,proof,out=_prepared(c,intent,lease,technical);_grant(intent,proof,grant,StageGrant)
    context=_fresh(c,intent,lease,technical,ready=True);c._no_pending(context=context)
    _need(not out.exists(),'NEW_OUTPUT');out.mkdir()
    c.write_new(out/'stage-package.json',proof)
    for name,raw in files.items():
        with (out/name).open('xb') as handle:
            handle.write(raw);handle.flush();c.os.fsync(handle.fileno())
    _sealed(c,files,out)
    try:
        carrier=_carrier(c,files,out)
        compiler=Path(technical.build_directory)/'compiler/tcc/tcc.exe'
        _need(_sha(c.read(compiler))==c.TCC_SHA,'TCC_PIN')
        result=subprocess.run([str(compiler),'-shared','-I'+str(out),str(out/'Continuation.c'),
            str(c.HERE/'NativeSdkCall.s'),'-lkernel32','-luser32','-o',str(out/'Continuation.dll')],cwd=out,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        _need(result.returncode==0 and len(result.stdout)+len(result.stderr)<=16384,'NATIVE_COMPILE')
        build=dict(version=263,kind='WRITER_BUILD_PROOF',passed=True,intentSha256=intent.sha256(),
            packageSha256=_sha(_canonical(proof)),packageHashes=proof['packageHashes'],
            librarySha256=_sha(c.read(out/'Continuation.dll')),compilerSha256=c.TCC_SHA,
            dispatcherSha256=_sha(c.read(Path(__file__))),compileExitCode=0,
            nativeInjectionPerformed=False,**carrier)
        files_again,proof_again,out_again=_prepared(c,intent,lease,technical)
        _need(files_again==files and proof_again==proof and out_again==out,'PACKAGE_REDERIVE')
        _sealed(c,files,out);_fresh(c,intent,lease,technical,ready=True)
        c.write_new(out/'build-proof.json',build);return build
    finally:
        _fresh(c,intent,lease,technical,ready=True)
        again,again_proof,again_out=_prepared(c,intent,lease,technical)
        _need((again,again_proof,again_out)==(files,proof,out),'PACKAGE_REDERIVE_FINALLY');_sealed(c,files,out)


def require_stage(intent,lease,technical,*,transport):
    """Re-derive current exact package, compiler and both assembly hashes."""
    _need(type(transport) is RamTransport,'TRANSPORT_TYPE');transport._owned(lease)
    c=_controller();files,proof,out=_prepared(c,intent,lease,technical)
    try:
        _fresh(c,intent,lease,technical,ready=True)
        _need(c.parse(c.read(out/'stage-package.json',32768))==proof,'STAGED_PACKAGE')
        build=c.parse(c.read(out/'build-proof.json',32768))
        _need(build.get('version')==263 and build.get('kind')=='WRITER_BUILD_PROOF' and build.get('passed') is True
            and build.get('intentSha256')==intent.sha256() and build.get('packageSha256')==_sha(_canonical(proof))
            and build.get('packageHashes')==proof['packageHashes'] and build.get('nativeInjectionPerformed') is False
            and build.get('dispatcherSha256')==_sha(c.read(Path(__file__)))
            and build.get('compilerSha256')==c.TCC_SHA and type(build.get('compileExitCode')) is int
            and build['compileExitCode']==0,'BUILD_PROOF')
        _need(build.get('carrierPreflightOnly') is True and build.get('carrierAssemblyExecuted') is False
            and type(build.get('carrierCompileExitCode')) is int and build['carrierCompileExitCode']==0
            and c._carrier_compiler()[1]==build.get('carrierCompilerSha256')
            and _sha(c.read(out/'OwnedCarrierPreflight.dll'))==build.get('carrierAssemblySha256'),'CARRIER_PROOF')
        _need(_sha(c.read(Path(technical.build_directory)/'compiler/tcc/tcc.exe'))==c.TCC_SHA
            and _sha(c.read(out/'Continuation.dll'))==build.get('librarySha256'),'NATIVE_LIBRARY_PIN')
        _sealed(c,files,out);return build
    finally:
        _fresh(c,intent,lease,technical,ready=True)
        _need(_prepared(c,intent,lease,technical)==(files,proof,out),'PACKAGE_REDERIVE_FINALLY');_sealed(c,files,out)


def _run_review(c,intent,proof,build,grant):
    _grant(intent,proof,grant,RunGrant)
    _need(grant.build_sha256==_sha(_canonical(build)),'BUILD_GRANT')
    path=c._plain(grant.review_path,ROOT/'artifacts/designer-bridge');raw=c.read(path,16384)
    _need(_sha(raw)==grant.review_sha256,'REVIEW_PIN');review=c.parse(raw)
    _need(review.get('version')==263 and review.get('kind')=='ROOT_WRITER_DISPATCH_REVIEW'
        and review.get('passed') is True and review.get('intentSha256')==intent.sha256()
        and review.get('packageSha256')==grant.package_sha256 and review.get('buildSha256')==grant.build_sha256
        and review.get('writerAuthorized') is True and review.get('applicationExecutionAuthorized') is True
        and all(review.get(k) is False for k in ('configurationSavesAuthorized','databaseUpdatesAuthorized',
                                                'repositoryMutationsAuthorized')),'ROOT_EXECUTION_REVIEW')


def _host_identity(host):
    """Original Popen handle only. Never enumerate/terminate another process."""
    from ctypes import wintypes as w
    k=ct.WinDLL('kernel32',use_last_error=True)
    k.GetProcessTimes.argtypes=[w.HANDLE]+[ct.POINTER(ct.c_uint64)]*4
    k.QueryFullProcessImageNameW.argtypes=[w.HANDLE,w.DWORD,w.LPWSTR,ct.POINTER(w.DWORD)]
    times=[ct.c_uint64() for _ in range(4)];buffer=ct.create_unicode_buffer(32768);size=w.DWORD(32768)
    _need(k.GetProcessTimes(int(host._handle),*(ct.byref(v) for v in times))
        and k.QueryFullProcessImageNameW(int(host._handle),0,buffer,ct.byref(size))
        and Path(buffer.value)==PS,'HOST_IDENTITY')
    return dict(processId=host.pid,birth=f'{times[0].value:016x}',image=str(PS),imageSha256=_sha(PS.read_bytes()))


def _receipt(intent,technical,intent_sha,status,**values):
    result=dict(version=263,kind='WRITER_SDK_RECEIPT',status=status,operationId=intent.request.receipt.operation_id,
        intentSha256=intent_sha,pid=technical.process_id,birth=technical.birth,
        sessionNonce=technical.held_nonce,knownTerminal=False,hookWorkersReleased=False,targetIdentityVerified=False,
        sdkResult=None,writerAuthorized=True,applicationWritesKnown=False,applicationWrites=None,
        savedVerified=False,configurationSavesAuthorized=False,databaseUpdatesAuthorized=False,
        repositoryMutationsAuthorized=False,releasePacketAllowed=False,releaseRefsAllowed=False,retryAuthorized=False)
    result.update(values);return result


def run_root_once(intent,lease,technical,grant,*,transport):
    """One reviewed writer launch. Every post-reservation failure retains state.

    No result.json is written: only independent root finalization can satisfy
    shared writer audit. Known SDK terminal still retains unsaved application.
    """
    _need(type(transport) is RamTransport,'TRANSPORT_TYPE');transport._owned(lease)
    c=_controller();files,proof,out=_prepared(c,intent,lease,technical)
    build=require_stage(intent,lease,technical,transport=transport);_run_review(c,intent,proof,build,grant)
    context=_fresh(c,intent,lease,technical,ready=True);c._no_pending(context=context)
    _need(not any((out/n).exists() for n in ('intent.json','sdk-receipt.json','host-identity.json','host-result.json',
        'sdk-result.bin','arm-result.bin','callback-observe.bin','native-prewrite-intent.json',
        'packet-proof.json','sheet-proof.json','composite-proof.json')),'ONE_ATTEMPT')
    marker=c._reservation(context)
    reservation=dict(version=233,nonce=technical.held_nonce,operationId=intent.request.receipt.operation_id,
        planSha256=proof['bindingSha256'],processId=technical.process_id,birth=technical.birth,
        writerPackageVersion=263,intentSha256=intent.sha256())
    c.write_new(marker,reservation)
    receipt=None
    try:
        transport.mark_dispatched(lease)  # Before durable intent and ANY remote attempt.
        c.write_new(out/'intent.json',intent.metadata())
        _need(c.parse(c.read(marker,8192))==reservation,'OWN_RESERVATION_CHANGED')
        _need(c.parse(c.read(out/'intent.json',32768))==intent.metadata(),'OWN_INTENT_CHANGED')
        _sealed(c,files,out);_fresh(c,intent,lease,technical,ready=False)
        _need(PS.is_file(),'X86_POWERSHELL')
        host=subprocess.Popen([str(PS),'-NoProfile','-ExecutionPolicy','Bypass','-File',str(out/'run-fixed.ps1')],
            cwd=out,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        _HOSTS[intent.request.receipt.operation_id]=host
        host_identity=_host_identity(host)
        _need(host_identity['processId']!=technical.process_id,'HOST_TARGET_ALIAS')
        c.write_new(out/'host-identity.json',host_identity)
        deadline=time.monotonic()+50
        while time.monotonic()<deadline:
            if (out/'host-result.json').exists():
                try:result=c.parse(c.read(out/'host-result.json',8192))
                except (OSError,ValueError):time.sleep(.05);continue
                _need(result.get('version')==263 and result.get('intentSha256')==intent.sha256()
                    and result.get('bindingSha256')==proof['bindingSha256']
                    and result.get('operationId')==intent.request.receipt.operation_id
                    and result.get('heldNonce')==technical.held_nonce
                    and type(result.get('targetPid')) is int and result['targetPid']==technical.process_id
                    and result.get('targetBirth')==technical.birth,'HOST_RESULT_SCOPE')
                if result.get('knownTerminal') is True and result.get('hookWorkersReleased') is True:
                    host.wait(timeout=5)
                    _need(host.returncode==0 and result.get('threadId')==technical.gui_thread_id
                        and type(result.get('sdkResult')) is int,'HOST_TERMINAL')
                    receipt=_receipt(intent,technical,proof['intentSha256'],'SDK_TERMINAL_UNSAVED_RETAIN',knownTerminal=True,
                        hookWorkersReleased=True,targetIdentityVerified=True,sdkResult=result['sdkResult'],
                        hostProcessId=host.pid)
                break
            if host.poll() is not None:break
            time.sleep(.05)
        if receipt is None:receipt=_receipt(intent,technical,proof['intentSha256'],'UNKNOWN_RETAIN',reason='HOST_NOT_KNOWN_TERMINAL')
    except BaseException:
        receipt=_receipt(intent,technical,proof['intentSha256'],'UNKNOWN_RETAIN',reason='DISPATCH_OR_METADATA_FAILURE')
    finally:
        try:
            _fresh(c,intent,lease,technical,ready=False);_sealed(c,files,out)
            _need(c.parse(c.read(marker,8192))==reservation,'OWN_RESERVATION_CHANGED')
            _need(c.parse(c.read(out/'intent.json',32768))==intent.metadata(),'OWN_INTENT_CHANGED')
        except BaseException:receipt=_receipt(intent,technical,proof['intentSha256'],'UNKNOWN_RETAIN',reason='FINAL_FRESHNESS_FAILURE')
        if receipt is None:receipt=_receipt(intent,technical,proof['intentSha256'],'UNKNOWN_RETAIN',reason='NO_RECEIPT')
        if receipt['knownTerminal'] is not True and lease.state in ('DISPATCHED','UNKNOWN'):transport.mark_unknown(lease)
        try:c.write_new(out/'sdk-receipt.json',receipt)
        except BaseException:
            if lease.state in ('DISPATCHED','UNKNOWN'):transport.mark_unknown(lease)
            receipt=_receipt(intent,technical,proof['intentSha256'],'UNKNOWN_RETAIN',reason='RECEIPT_WRITE_FAILURE')
    return receipt
