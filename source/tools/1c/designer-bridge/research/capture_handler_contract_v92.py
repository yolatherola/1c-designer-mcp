"""Whole fixed 8.3.18 handler bytes and ownership prerequisites, offline only.

No DLL is loaded, no interface pointer is read, and no handler is executed.
Byte identity does not prove current Gold bindings or grant a native permit.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct

from repository_pe_probe import HASHES, PE

HERE = Path(__file__).resolve().parent
DEPENDENCIES = {
    '../tests/NativeRepositorySource.as': '64c20dd68c7e79f3ad4ad77a313081fc4c842e0f9431df86a3703c939131ad25',
    '../tests/NativeFactoryCopyV49.as': '1dc54ce7cbf4e96a4efbfefc05eb864feacc66a5de06d403f291a8e0ef6915fb',
    '../tests/NativeCaptureNotificationV56.as': '7827bef256dd0d223b4932e2bbfa79232c318d5da8cf6d1f21299500637d64f1',
    'selected_controller_thunk_v46.py': '73f05eaa4fc91272c29fdb17e28d7349d59cfaa5765a810d119860cec2f6d97e',
    'NativeSdkCall.s': 'ab5c81990fe2838b366a3cde486e5b06c0650a1bc9bc9b85f43774eb47699374',
}
ENTRY_RVA = 0xb3b80
COLLECTION_IID = 'fba0e2df-588a-4931-8c83-01ee74f38fa2'
COLLECTION_TABLE_RVA = 0x18ddcc
COLLECTION_RELEASE_RVA = 0x14b8b0
RANGES = (
    ('handlerWhole', 0xb3b80, 4956, 'eab7b4c8ba0d9f0dc49bd19caa7c165dc624383fdad7b6437fd624c663843adb'),
    ('handlerColdTails', 0xb4e16, 198, 'c33c06f5d8c729780158e10b925bc733ca805375eb9ba1e4e42b359e6c95a841'),
    ('captureCaller', 0xbd414, 42, '4dbaa68f2bf633cd7ac48c512b7cdad7d810aefb3098748f2e69e6cd08883d13'),
    ('callerOwnershipCleanup', 0xbd4f1, 68, 'a4067a88ddd6f2bd6931d2d4db9ad4c93b6125ff9b24dbf23e4674f86b8e33c3'),
    ('result264Constructor', 0xb2ee0, 200, 'bd484e03505ad8009624026a11de08dbfa382880f8a09ddebc7eb240674e86e9'),
    ('result264Destructor', 0xb2fb0, 321, 'b7166e7afe713743ca98c9149df90a8c4fb22238a7b8686e2aee1db3c8ef16d3'),
    ('controllerCountedQi', 0xb3bde, 66, '7afab111a17c6990c2b2d09699dcd22137bedaf0d0093388720f1468fedcdb91'),
    ('nullApplicationRefresh', 0xb3e1a, 556, 'a6152163abf18d3cde09d98f5c0d454b5d86d0cf21e1167594719315d794e574'),
    ('provider50Prerequisites', 0xb40f1, 85, '855f15c87771460ea92ad401b2836a00bf93f2a11aca0ffd424c5e7f6eff2c51'),
    ('collectionTable', 0x18ddcc, 24, '79bccd24aba01420e24ef8ef764302d7c0e8fdc4e0a5293f20cd659df33c30e9'),
)
# Instruction-boundary witnesses independently decoded over all 4956 bytes.
# Exact whole hashes retain every branch and all exception/cleanup cold tails.
ANCHORS = (
    (0xb3bb1, '8bf1'),                         # ECX primary -> retained ESI
    (0xb3bb9, '8b450c'),                       # application at stack +0xc
    (0xb3bbc, '8b5d14'),                       # caller-owned result at +0x14
    (0xb3bbf, '8b7d08'),                       # selected at stack +8
    (0xb3bc2, '8985ccfdffff'),                 # application retained at -0x234
    (0xb3cd6, 'ff90c4000000'),                 # fetch packet49 before apply
    (0xb3d3d, 'e89e630000'),                   # platform processing before apply
    (0xb3e1a, '83bdccfdffff00'),               # application null gate
    (0xb3e21, '0f851f020000'),                 # nonnull -> boolean branch
    (0xb403f, 'b001'), (0xb4041, 'e9b20d0000'), # refresh-only true -> common exit
    (0xb4046, '807d1000'),                     # native boolean at +0x10
    (0xb4104, 'e8d7edffff'),                   # separate local constructed result264
    (0xb411e, '8bb8c8000000'),                 # provider slot50
    (0xb4134, '8d4114'), (0xb4137, '8b5510'),
    (0xb4140, '51'), (0xb4141, '52'), (0xb4142, '50'), (0xb4143, '56'),
    (0xb4144, 'ffd7'),                        # provider(app+14, flag, local264)
    (0xb4df6, '8ac3'), (0xb4e13, 'c21000'),    # AL result, native ret16
)


def need(ok, code):
    if not ok:
        raise ValueError('V92_STATIC_' + code)


def verify_slices(read_rva):
    """Compare only fixed byte spans supplied by the offline PE reader."""
    spans = {}
    for name, rva, count, expected in RANGES:
        data = read_rva(rva, count)
        need(type(data) is bytes and len(data) == count, 'RANGE_SIZE_REJECTED')
        need(hashlib.sha256(data).hexdigest() == expected, 'RANGE_CHANGED_' + name)
        spans[name] = data
    whole = spans['handlerWhole']
    for rva, hexbytes in ANCHORS:
        expected = bytes.fromhex(hexbytes)
        need(whole[rva-ENTRY_RVA:rva-ENTRY_RVA+len(expected)] == expected, 'INSTRUCTION_CHANGED')
    need(whole[-198:] == spans['handlerColdTails'], 'COLD_TAILS_OMITTED')
    return [{'name': name, 'module': 'devtool.dll', 'rva': rva, 'bytes': count, 'sha256': expected}
            for name, rva, count, expected in RANGES]


def verify_static():
    dependencies = {}
    for name, expected in DEPENDENCIES.items():
        actual = hashlib.sha256((HERE/name).read_bytes()).hexdigest()
        need(actual == expected, 'DEPENDENCY_CHANGED')
        dependencies[name] = actual
    pe = PE('devtool.dll')
    spans = verify_slices(lambda rva, count: pe.data[pe.offset(pe.base+rva):pe.offset(pe.base+rva)+count])
    table = pe.offset(pe.base+COLLECTION_TABLE_RVA)
    slots = [struct.unpack_from('<I', pe.data, table+4*n)[0]-pe.base for n in range(6)]
    need(slots == [0x14b890, 0x10e4e0, 0x14b8b0, 0x4460, 0xaca30, 0xaca70], 'COLLECTION_TABLE_CHANGED')
    return dict(stage='V92WholeCaptureHandlerStaticContract', staticCompatible=True,
        platform='8.3.18.1208', platformSha256=HASHES['devtool.dll'].lower(), ranges=spans,
        sourceSha256=dependencies, entryRva=ENTRY_RVA, nativeAbi='thiscall(ECX=self,selected,application,bool,result264)',
        nativeArgumentDwords=4, nativePopBytes=16, explicitSelfPopBytes=20, resultBytes=264,
        resultConstructorRva=0xb2ee0, resultDestructorRva=0xb2fb0,
        resultLifetimeAbi='thiscall(self,noargs); existing counted explicit-self thunk required',
        collectionIid=COLLECTION_IID, collectionTableRva=COLLECTION_TABLE_RVA,
        collectionReleaseRva=COLLECTION_RELEASE_RVA, nativeReturn='AL boolean, not DWORD/HRESULT',
        nullApplicationSkipsDirectProvider50=True, nullApplicationIsCaptureProof=False,
        stockSelectionEquivalentToPlanner=False, currentBindingsVerified=False, currentSingleUuidVerified=False,
        helperOwnershipVerified=False, staleRefreshVerified=False, transitiveEffectsVerified=False,
        modalFreeVerified=False, nativePermit=False, captureVerified=False,
        nativeMethodsExecuted=0, repositoryMutations=0, goldSourceWrites=0, configurationSaves=0,
        databaseUpdates=0, configurationExports=0, configurationImports=0)
