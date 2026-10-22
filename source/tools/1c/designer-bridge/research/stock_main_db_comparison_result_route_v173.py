"""Inert direct comparison-service/source-model prerequisite, not a delta DTO.

Reuse FULL V154 first. The opaque service factory and returned result virtual
method are precise missing callsites; no pointer is adopted or API invoked.
"""
import hashlib
import io
from pathlib import Path
import struct
import uuid
import zipfile

import database_configuration_read_route_v154 as parent

ROOT = Path(__file__).resolve().parents[4]
PARENT_SHA = 'e258d952d9b25b3954c8c2e1ef42982cb6ab2a2e94ec033496ef4e8417a70aa8'
BASE = parent.CONFIG_BASE
SERVICE_ID = '5c54d1a0-d0df-4550-bfc6-7deed8622790'
MODEL_INTERFACE_ID = '805a8ace-5c15-407a-8ec8-785fd57fb076'
PROCESS_MEMBER = 'modules/snegopat/v8api/process.v'
PROCESS_SIZE = 3239
PROCESS_SHA = '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef'
SPANS = {
    'serviceAccessor': (0x2270f0, 20, '99a0eafbb396afa60bbd97fe7312e731db17367fb2fb205058fc6519c0b59ef7'),
    'mainReferenceCopy': (0x233290, 119, 'ced266fbc5331671c4ad1ba76aca4007cadc7223dd84d881e463cf014bc91dbe'),
    'dbReferenceCopy': (0x233210, 119, '8ea33fd47ecf90ae90cd4501ab3479880e8b33263b7ef4a22031ea3584ac09a9'),
    'serviceForwarder': (0x2276a0, 19, 'c12fef840472057bc7c7853aa340a85ac9b3ffcc9f2e6a284c3deacceeb6f991'),
    'serviceId': (0x2b83b0, 16, 'd42b5e264d038c2e901ac0cf9bb2ab18a2c7fcc325e150ab721bba5a24da9c15'),
    'modelQI': (0x232f40, 26, '2164880d934d413cbdad3c430c6c297b99a507dc41b52ab4757b4abbb4bdd352'),
    'modelAddRef': (0x1f9010, 19, 'ac1d356752a560882ab09ed27ddec793fe11784e851b20f9adf7445f3d981d78'),
    'modelRelease': (0x232f60, 45, 'dbce5bc4226ff8b51c9979a7f2709d80a47b2f388ae9317c8fe9169fdfc546b5'),
    'modelMapWithInlineId': (0x2bac40, 40, 'bc1f3cd93013aa19beed8e00915a868496224e7f150335a489aeb86762494b51'),
    'commonQI': (0x1feb70, 252, '44f197ce4cff832ba653b0400191dff8e1263fc28bec8381f3e7ecb4478fe430'),
}
UNPROVEN = ('runtimeCurrentConfigContextIdentityVerified', 'wholeModelOwnerConstructorVerified',
    'contextLifetimeVerified', 'resultCountedAcquisitionVerified', 'resultClassAndInterfaceVerified',
    'serviceFactoryImplementationVerified', 'resultMethodImplementationVerified',
    'fullChildrenChangeKindPropertyModuleResourceIteratorVerified', 'completionEpochVerified',
    'cancellationAndErrorCompletionVerified', 'wholeRouteReadOnlyVerified', 'routeNeverSavesVerified',
    'modalBehaviorVerified', 'runtimeRefcountsMeasured', 'exceptionUnwindVerified',
    'onlyOwnPendingVerified', 'nativePermit', 'writerAuthorized', 'saveAuthorized', 'databaseUpdateAuthorized')


def need(ok, code):
    if not ok:
        raise ValueError('V173_'+code)


def word(raw, at):
    return struct.unpack_from('<I', raw, at)[0]


def relative(raw, at, rva):
    return rva+at+4+struct.unpack_from('<i', raw, at)[0]


def verify_linkage(bodies, inherited, process):
    """Normal byte links only; source models are not comparison result nodes."""
    need(type(bodies) is dict and set(bodies) == set(SPANS), 'SPAN_SET')
    need(all(type(bodies[n]) is bytes and len(bodies[n]) == s for n, (_, s, _) in SPANS.items()), 'SPAN_SIZE')
    parent.verify_structure(inherited)
    need(type(process) is bytes and b'IUnknown@+ getService(const Guid&in idService)' in process
         and b'SCOM_Process@ currentProcess()|?current_process@core@@' in process, 'PUBLISHED_SERVICE')
    a, f = bodies['serviceAccessor'], bodies['serviceForwarder']
    need(a[:6] == b'\xff\x15'+struct.pack('<I', BASE+0x2ad780)
         and a[12] == 0xe9 and relative(a, 13, 0x2270f0) == 0x2276a0
         and a[-3:] == bytes.fromhex('33c0c3'), 'CURRENT_PROCESS_SERVICE')
    need(f == bytes.fromhex('85c9740c8b0168')+struct.pack('<I', BASE+0x2b83b0)
         +bytes.fromhex('51ff5038c333c0c3') and bodies['serviceId'] == uuid.UUID(SERVICE_ID).bytes_le,
         'SERVICE_SLOT14_ID')
    for prefix, table, copy in (('main', 0x2b9ce0, 'mainReferenceCopy'), ('db', 0x2b9d28, 'dbReferenceCopy')):
        raw = bodies[copy]
        need(b'\x81\xf9'+struct.pack('<I', BASE+table) in raw
             and bytes.fromhex('83c00450ff1538d10e26') in raw
             and raw[0x5a:0x5d] == bytes.fromhex('c20400')
             and raw[0x6e:0x71] == bytes.fromhex('c20400')
             and raw[-6:] == bytes.fromhex('50ff5104ebe6'), 'COPY_NORMAL_AND_FORWARD_TAIL')
        install = inherited[prefix+'ModelInstall']; target = SPANS[copy][0]
        call = install.index(b'\xe8', install.index(b'\xc7\x00')+6)
        need(relative(install, call+1, parent.RANGES[prefix+'ModelInstall'][1]) == target, 'INSTALL_COPY_EDGE')
    q = bodies['modelQI']
    need(word(q, 10) == BASE+0x2bac40 and relative(q, 18, 0x232f40) == 0x1feb70
         and q[-3:] == bytes.fromhex('c20c00'), 'MODEL_QI')
    m = bodies['modelMapWithInlineId']
    need(struct.unpack('<6I', m[:24]) == (BASE+0x2bac58, 0, 1, 0, 0, 0)
         and m[24:] == uuid.UUID(MODEL_INTERFACE_ID).bytes_le, 'MAPPED_PRIVATE_MODEL_INTERFACE')
    add, release, common = bodies['modelAddRef'], bodies['modelRelease'], bodies['commonQI']
    need(add == bytes.fromhex('558bec8b450883c0048945085dff25')+struct.pack('<I', BASE+0x2ad138), 'MODEL_REF_FIELD')
    need(bytes.fromhex('8d470450ff153cd10e26') in release
         and bytes.fromhex('6a01ff5244') in release and release[-3:] == bytes.fromhex('c20400'), 'RELEASE_HAS_DESTRUCTOR')
    need(common[0x52:0x5f] == bytes.fromhex('568b06ff50048b4d0c33c08931')
         and common[0xdb:0xe6] == bytes.fromhex('568b06ff50048b4d0c8931')
         and common[-3:] == bytes.fromhex('c20800'), 'QI_ADDREF_BEFORE_OUTPUT')
    for prefix in ('main','db'):
        cells = struct.unpack('<16I', inherited[prefix+'Table'])
        need(cells[:3] == tuple(BASE+SPANS[n][0] for n in ('modelQI','modelAddRef','modelRelease')), 'MODEL_TABLE_FIRST3')
    execute, builder = inherited['compareExecute'], inherited['compareBuilder']
    need(bytes.fromhex('8b49248b4164') in execute and bytes.fromhex('ff512c') in execute,
         'RESULT_POST_FACTORY_CALL')
    need(relative(execute, 0x39, 0x141c20) == 0xc1420
         and relative(builder, 0x66, 0xc1420) == 0x2270f0
         and bytes.fromhex('8b401c') in builder and bytes.fromhex('ff95e0feffff') in builder,
         'OPAQUE_RESULT_FACTORY_CALL')
    result = dict(fullV154StructureReused=True, newDirectSliceCount=10,
        publishedServiceRequest='currentProcess().getService', publishedServiceSlot=14,
        serviceId=SERVICE_ID, serviceReturnAutoHandleConventionPublished=True,
        mappedSourceModelPrivateInterfaceId=MODEL_INTERFACE_ID, mappedSourceModelFacet=0,
        mappedSourceModelCountFlag=1, sourceModelReferenceCopyNormalPathsVerified=True,
        sourceModelMappedOutputAddRefBeforeStoreVerified=True,
        sourceModelReferenceCounterFieldOffset=4, sourceModelContextFieldOffset=16,
        sourceModelReleaseCanCallDestructor=True, destructorVirtualByteOffset=0x44,
        comparisonServiceFactoryVirtualByteOffset=0x1c, comparisonServiceFactoryCallsiteRva=0xc1604,
        comparisonResultPostFactoryVirtualByteOffset=0x2c, comparisonResultPostFactoryCallsiteRva=0x141c74,
        sourceModelsAreNotDeltaNodes=True, supportedResultOrDeltaShape=None,
        privateServiceCreationSideEffectsUnknown=True, sourceModelOwnerCreationSideEffectsUnknown=True,
        directSaveOrDbUpdateNotInvokedByThisChecker=True, safeCallableReadonlyBoundaryVerified=False,
        missingExistingPrimaryCallsites=['config.dll+0xc1604: virtual comparison-service slot7 implementation/result table.',
            'config.dll+0x141c74: result slot11 implementation, possible UI/modal/save effects and terminal completion.',
            'V154 ModelInstall parent: complete enclosing owner constructor/context retention, not only table-install slices.'])
    result.update({key: False for key in UNPROVEN})
    return result


def require_readonly_comparison_result(*unproven, **asserted):
    """No unknown result shape, empty rows or passed booleans grant admission."""
    raise ValueError('V173_OPAQUE_FACTORY_RESULT_AND_COMPLETION')


def verify_evidence(read_member, read_slice, read_help, version=parent.VERSION):
    """FULL inherited154 verification precedes the ten new direct slices."""
    need(callable(read_member) and callable(read_slice) and callable(read_help), 'READERS')
    captured = {}
    def inherited_reader(*key):
        raw = read_slice(*key); captured[key] = raw; return raw
    inherited_result = parent.verify_inventory(read_member, inherited_reader, read_help, version)
    try: process = read_member(PROCESS_MEMBER)
    except Exception: raise ValueError('V173_PROCESS_SDK_MISSING') from None
    need(type(process) is bytes and len(process) == PROCESS_SIZE and hashlib.sha256(process).hexdigest() == PROCESS_SHA, 'PROCESS_SDK_PIN')
    inherited = {name: captured[spec[:3]] for name,spec in parent.RANGES.items()}
    bodies = {}
    for name,(rva,size,pin) in SPANS.items():
        try: raw = read_slice('config.dll',rva,size)
        except Exception: raise ValueError('V173_PRIMARY_MISSING') from None
        need(type(raw) is bytes and len(raw) == size and size <= 12288 and hashlib.sha256(raw).hexdigest() == pin, 'PRIMARY_PIN')
        bodies[name] = raw
    result = verify_linkage(bodies,inherited,process)
    result['inheritedV154SpanCount'] = inherited_result['spanCount']
    return result


def verify_static():
    """Only existing fixed SDK/help and hash-pinned installed config PE reads."""
    from repository_pe_probe import PE
    need(hashlib.sha256(Path(parent.__file__).read_bytes()).hexdigest() == PARENT_SHA, 'PARENT_SOURCE_PIN')
    raw = parent.ARCHIVE.read_bytes(); need(len(raw) == parent.ARCHIVE_BYTES and hashlib.sha256(raw).hexdigest() == parent.ARCHIVE_SHA, 'SDK_PIN')
    pe = PE('config.dll'); help_body = parent._help_bytes(parent.HBK.read_bytes())
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        def member(name):
            need(name in set(parent.MEMBERS)|{PROCESS_MEMBER} and sum(x.filename == name for x in archive.infolist()) == 1, 'MEMBER')
            return archive.read(name)
        allowed = {s[:3] for s in parent.RANGES.values()}|{('config.dll',r,s) for r,s,_ in SPANS.values()}
        def sliced(module,rva,size):
            need((module,rva,size) in allowed, 'SLICE')
            at = pe.offset(pe.base+rva); return pe.data[at:at+size]
        result = verify_evidence(member,sliced,lambda name: help_body if name == parent.HELP else None)
    result.update(wholePlatformHashVerified=True, platformSha256=hashlib.sha256(pe.data).hexdigest(),
        sdkSha256=parent.ARCHIVE_SHA, processSdkSha256=PROCESS_SHA, inheritedSourceSha256=PARENT_SHA,
        newSpanSha256={name: spec[2] for name,spec in SPANS.items()})
    return result
