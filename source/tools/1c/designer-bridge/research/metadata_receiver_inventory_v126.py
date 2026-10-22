"""Fixed primary SDK/PE inventory only; no receiver/event method is executed.

The two published getter paths do not by themselves identify a DB receiver.
This inventory grants no registration, Save, update, capture or native permit.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import zipfile

from repository_pe_probe import PE, HASHES

ROOT = Path(__file__).resolve().parents[4]
ARCHIVE = ROOT / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
ARCHIVE_BYTES = 4630548
ARCHIVE_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
VERSION = '8.3.18.1208'
MEMBER_LIMIT = 65536
MEMBERS = {
    'modules/snegopat/v8api/metadata.v': (13362, 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed'),
    'modules/snegopat/engine/com_metadata.as': (35939, '752aa271e6350351e698ef865a0dc7f2650b9380f41536740886a1c15bcb8d45'),
    'modules/snegopat/v8api/event.v': (2497, 'd98bdc8f29209ca190f6f2870dd06852c77d0d8ff3d82c72be69c0f8fc4c03e8'),
}
RANGES = {
    'editServiceTable': ('frntend.dll', 0xc4848c, 68, '6a9dc3a7d149eff0595669e0bde90c5ac7090fe36cc426ad946dd516c9ca58a7'),
    'templatesMainUi16': ('frntend.dll', 0x3e8550, 137, '53ea5766e79bbbe36d15c30ae096326a961bca200953a03bad3ad7c3f22fc386'),
    'objectUi12': ('frntend.dll', 0x3e82f0, 411, '191ac5cbe14f105000d1ba87c622cc56b162cd280ad809574735d25181f2d2df'),
    'infoBaseTable65': ('rclient.dll', 0x670bc, 264, '994ad240f5da38027b5eacd4f16d56a7a1a97a0bb96b7463d418f561134599ac'),
    'infoBaseManager65': ('rclient.dll', 0x256b0, 16, 'd2dd60ff5fea4701696832957885cb7590830afd0fac334937c79c73de1a259f'),
    'typedUiTable26': ('frntend.dll', 0xc0e458, 108, 'a152d070d318c329d2299321a90cc484b4426f4dedaa1be4f843034aac507fb8'),
    'uiRoot26': ('frntend.dll', 0x147b90, 37, 'f73146874874d7174b722e93f104e572463c7607bc83d4d484d6334585a4b018'),
    'managerTable85': ('backend.dll', 0xede0a4, 344, '05250dc12f3b5647f2405f0113dfb3a2d80ae9c5e20385787bed29a431612362'),
    'managerCacheHead': ('backend.dll', 0x2aeb40, 126, 'c68f0f61c1233a62a3c24aee2369d6de42a8d5d453e10d213dc91f782277f01e'),
    'managerCacheReturn': ('backend.dll', 0x2af5b7, 30, 'a4ec316398c2c9bac8c49ddd3e2adbcb66f139f0c372c19f715db379b6fe18b9'),
}
AUTO_HANDLE_DOCUMENTATION = 'https://www.angelcode.com/angelscript/sdk/docs/manual/doc_obj_handle.html'
EVENT = '2282fcc8-bf58-47f6-a420-3ffeb8f193e5'
EVENT_FIELDS = ('request', 'result', 'kind', 'object', 'parent', 'id', 'changedPropId')
EVENT_KINDS = ('emdAddChild', 'emdPropChanged', 'emdDeleteChild', 'emdChanged', 'emdSave', 'emdClose', 'emdAfterSave')
OBSERVER_REQUIREMENTS = (
    'exact-metadata-event-id', 'bounded-known-payload-layout',
    'scalar-copy-only-no-info-result-write', 'own-root-and-object-identity-filter',
    'no-plugin-business-or-metadata-writer-callback', 'no-borrowed-handle-escape',
    'counted-service-and-recipient-retained', 'subscribe-once',
    'unsubscribe-same-service-event-recipient', 'callback-quiescence-before-release',
    'event-is-local-invalidation-not-db-completion-or-cas',
)


def need(ok, code):
    if not ok:
        raise ValueError('V126_' + code)


def _read(reader, key, size, sha, limit, code):
    try:
        raw = reader(key)
    except Exception:
        raise ValueError('V126_' + code) from None
    need(type(raw) is bytes and 0 < len(raw) <= limit and len(raw) == size
         and hashlib.sha256(raw).hexdigest() == sha, code)
    return raw


def verify_inventory(read_member, read_slice, version=VERSION):
    """Check fixed bytes and return honest static facts, never an execution cap.

    Readers are trusted read-only functions. Only three exact member names and
    ten exact (module,RVA,size) tuples are requested; no raw payload is returned.
    """
    need(type(version) is str and version == VERSION, 'VERSION_REJECTED')
    need(callable(read_member) and callable(read_slice), 'READER_REJECTED')
    members = {name: _read(read_member, name, size, sha, MEMBER_LIMIT, 'MEMBER_REJECTED')
               for name, (size, sha) in MEMBERS.items()}
    data = {}
    for name, (module, rva, size, sha) in RANGES.items():
        data[name] = _read(lambda spec: read_slice(*spec), (module, rva, size), size, sha, 4096, 'SLICE_REJECTED')
    metadata, wrapper, event = (members[name].decode('utf-8-sig').replace('\r\n', '\n') for name in MEMBERS)
    for token in ('IInfoBase@+ getDefault()', 'IConfigMngr@+ getConfigMgr()',
                  'IMDContainer@+ getMDCont(int i = 0)', 'IMDContainer@+ getMDCont()',
                  'uint getTemplatesMainConfigMngrUI(IConfigMngrUI@&)',
                  ':guid eventMetaData\t\t{2282FCC8-BF58-47F6-A420-3FFEB8F193E5}'):
        need(token in metadata, 'PUBLISHED_SIGNATURE_REJECTED')
    need('return getDefaultInfoBase().getConfigMgr().getMDCont();' in wrapper
         and 'getMDEditService().getTemplatesMainConfigMngrUI(pmdUI);' in wrapper
         and 'return pmdUI.getMDCont();' in wrapper, 'RECEIVER_CHAIN_REJECTED')
    field_block = metadata.split(':struct MDEventInfo\n', 1)[1].split(':struct', 1)[0]
    field_lines = tuple(line.strip() for line in field_block.splitlines() if line.strip() and line.strip() != ':props')
    need(field_lines == ('bool request', 'bool result', 'EventMetaDataKind kind', 'IMDObject@ object',
                        'IMDObject@ parent', 'Guid id', 'Guid changedPropId'), 'EVENT_FIELDS_REJECTED')
    kind_block = metadata.split(':enum EventMetaDataKind\n', 1)[1].split(':struct', 1)[0]
    need(tuple(line.strip() for line in kind_block.splitlines() if line.strip()) == EVENT_KINDS, 'EVENT_KINDS_REJECTED')
    need('void onEvent(const Guid&in eventID, long val, IUnknown& obj)' in event
         and ':service IEventService {EBF766AA-F32C-11D3-9851-008048DA1252}' in event
         and 'void  subscribe(const Guid&in eventID, IEventRecipient@ pRecipient)' in event
         and 'void  unsubscribe(const Guid&in eventID, IEventRecipient@ pRecipient)' in event,
         'EVENT_SERVICE_REJECTED')
    need('void onEvent(const Guid&in eventID, MDEventInfo& info, IUnknown& obj)' in wrapper
         and 'info.result = mde.result;' in wrapper
         and 'oneDesigner._events.fireEvent(mdd, "MetaDataEvent", args);' in wrapper, 'MUTABLE_BRIDGE_REJECTED')
    front, base, backend = 0x26dc0000, 0x2a1d0000, 0x1f400000
    word = lambda raw, at: struct.unpack_from('<I', raw, at)[0]
    need(word(data['editServiceTable'], 12 * 4) == front + 0x3e82f0
         and word(data['editServiceTable'], 16 * 4) == front + 0x3e8550
         and word(data['infoBaseTable65'], 65 * 4) == base + 0x256b0
         and word(data['typedUiTable26'], 26 * 4) == front + 0x147b90
         and word(data['managerTable85'], 85 * 4) == backend + 0x2aeb40, 'SLOTS_REJECTED')
    need(bytes.fromhex('8b8fa8000000') in data['templatesMainUi16']
         and bytes.fromhex('8b9398000000') in data['objectUi12']
         and data['infoBaseManager65'] == bytes.fromhex('558bec 8b4508 8b8020020000 5d c20400'),
         'RECEIVER_MEMBER_REJECTED')
    ui, cache = data['uiRoot26'], data['managerCacheHead']
    need(ui[6:12] == bytes.fromhex('8b8818010000')
         and ui[22:33] == bytes.fromhex('8b016a0051ff9054010000') and ui[-3:] == bytes.fromhex('c20400')
         and cache[0x4e:0x54] == bytes.fromhex('8b8784000000')
         and data['managerCacheReturn'][-3:] == bytes.fromhex('c20800'), 'UI_MANAGER_CACHE_REJECTED')
    return dict(
        staticInventoryVerified=True, platformVersion=VERSION, archiveSha256=ARCHIVE_SHA,
        archiveHashVerified=False, platformModuleHashesVerified=False,
        memberSha256={k: v[1] for k, v in MEMBERS.items()}, sliceSha256={k: v[3] for k, v in RANGES.items()},
        publishedInfoBaseChainVerified=True, publishedTemplatesMainChainVerified=True,
        templatesUiServiceMemberOffset=0xa8, objectUiServiceMapOffset=0x98,
        infoBaseManagerMemberOffset=0x220, uiManagerMemberOffset=0x118, managerCachedRootOffset=0x84,
        getterReturnAutoHandleDeclared=True, nativeGetterLacksAddRefIsOwnershipViolation=False,
        autoHandleDocumentation=AUTO_HANDLE_DOCUMENTATION, specificEngineAutoHandleImplementationTraced=False,
        manualRawAdoptionAllowed=False, runtimeTypedReceiverIdentityVerified=False,
        mainVersusDatabaseRoleVerified=False, rootUuidAloneProvesRole=False, managerWholeGetterReadOnlyVerified=False,
        eventId=EVENT, eventFieldOrder=EVENT_FIELDS, eventByteOffsetsVerified=False,
        saveEventKind=4, afterSaveEventKind=6, stockBridgeChangesResult=True, stockBridgeReadOnly=False,
        eventPayloadAddressAbiVerified=False, observerImplemented=False, observerLifetimeVerified=False,
        observerRequirements=OBSERVER_REQUIREMENTS, eventAfterSaveProvesDatabaseUpdate=False,
        observerProvesRepositoryCas=False, pendingOwnOnlyVerified=False, nativePermit=False,
        subscriptionAuthorized=False, saveAuthorized=False, databaseUpdateAuthorized=False, captureAuthorized=False,
        nativeCalls=0, registrations=0, configurationWrites=0, configurationSaves=0,
        databaseUpdates=0, repositoryMutations=0, businessCalls=0,
    )


def verify_static():
    """Read/hash one pinned archive and three PE images; no extraction/loads."""
    need(ARCHIVE.stat().st_size == ARCHIVE_BYTES, 'ARCHIVE_REJECTED')
    raw = ARCHIVE.read_bytes()
    need(len(raw) == ARCHIVE_BYTES and hashlib.sha256(raw).hexdigest() == ARCHIVE_SHA, 'ARCHIVE_REJECTED')
    images = {module: PE(module) for module in ('frntend.dll', 'rclient.dll', 'backend.dll')}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        for name, (size, _) in MEMBERS.items():
            entries = [entry for entry in archive.infolist() if entry.filename == name]
            need(len(entries) == 1 and entries[0].file_size == size and size <= MEMBER_LIMIT, 'ARCHIVE_MEMBER_REJECTED')
        def read_slice(module, rva, size):
            need((module, rva, size) in {spec[:3] for spec in RANGES.values()}, 'SLICE_SCOPE_REJECTED')
            image = images[module];at = image.offset(image.base + rva)
            return image.data[at:at + size]
        result = verify_inventory(archive.read, read_slice)
    result.update(archiveHashVerified=True, platformModuleHashesVerified=True,
                  platformSha256={name: HASHES[name].lower() for name in images})
    return result
