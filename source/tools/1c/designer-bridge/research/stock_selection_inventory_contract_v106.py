"""Fixed byte/SDK contract for address-only stock dependency inventory.

This imports only readers of pinned PE bytes. No DLL is loaded or dispatched.
The capture-model initializer calls aggregateInstance, not an existing service.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import struct
import zipfile

from repository_pe_probe import HASHES, PE
from stock_capture_selection_contract_v96 import verify_static as verify_v96
from owned_value_persistence_contract_v68 import verify_process_layout

HERE = Path(__file__).resolve().parent
CACHE = HERE.parents[3] / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40'
NATIVE_SHA256 = 'b85b55b0d164801b8d616a200c6ff6daba818b93aa115d7080f0a738e3fc77db'
SDK_MEMBER = 'modules/snegopat/v8api/process.v'
SDK_SHA256 = '92458b3e1a862051bf9b1d8b0cac750de5fddc62294324ca70a94820cdb1a9ef'
DEPENDENCIES = {
    'stock_capture_selection_contract_v96.py': '8eae6ecf727b98143bbeb2488cfda7685287707ae1f359db5332dc0d716e570f',
    'owned_value_persistence_contract_v68.py': '9dec5384e64fb83d056e59fee65edd3f08d629e323ed4e7c5957dac07daac3d2',
    '../tests/NativeGoldWriterInventory.as': '23abeb8a7b10a46502d8930c993f718af4e35202b5c932e2105e0b61413a680c',
    '../tests/NativeRepositoryObserve.as': 'd7ac427467016667ac2b9e84a97a92727ef6955a2bf5dc439d4da36871bff16d',
    '../tests/NativeRepositoryPlan.as': '77738f69fab72dafbd35c342bbd4e3a3090cc548f7dcd741df69a2dda4daeebd',
    '../tests/NativeCommandBufferGuard.as': '017e7d818b35ebc13f5e2d90c93d2216cf66c3c4d2be7347bc7577b5954c3eb9',
}
RANGES = (
    ('controllerFace', 0x18db1c, 56, '1621f17aa6b62ee92b367145ef773352b2d26b7eeac8b32f7c1cd48b7a2d5fd4'),
    ('provider', 0x1869bc, 200, 'e69186eb9b29054ac624b3b1d78c4d28991edca3c6df5b7d63bee7e13252c2d3'),
    ('aggregateCallSite', 0xd06b0, 40, 'a60013113cd6479fb2093eef8cef9ad33f2071bf9b4c4c77a2003c18caac494b'),
    ('eligibilityDependency', 0xccd32, 14, '9a07d1ce5baad82c6169d6f73916e74af552f7e2ac7a4858c3d8c2d684a8ca62'),
)
CURRENT_PROCESS = (0x1df6c0, 13, '350ffc6e1613ad41ba15f029b1fea8ff364933d736c06002d0e0636d814aaa6d')


def need(condition, code):
    if not condition:
        raise ValueError('V106_' + code)


def verify_slices(read_devtool, read_core, image_base):
    """Validate exact callsite/table bytes, including method slots never invoked."""
    need(type(image_base) is int and image_base == 0x30af0000, 'DEVTOOL_BASE_CHANGED')
    values = {}
    for name, rva, count, expected in RANGES:
        data = read_devtool(rva, count)
        need(type(data) is bytes and len(data) == count and hashlib.sha256(data).hexdigest() == expected,
             'STATIC_CHANGED_' + name)
        values[name] = data
    rva, count, expected = CURRENT_PROCESS
    data = read_core(rva, count)
    need(type(data) is bytes and len(data) == count and hashlib.sha256(data).hexdigest() == expected,
         'CURRENT_PROCESS_CHANGED')
    face, provider = values['controllerFace'], values['provider']
    need(struct.unpack_from('<I', face, 9*4)[0] - image_base == 0xbd600
         and struct.unpack_from('<I', face, 13*4)[0] - image_base == 0xbedf0, 'CONTROLLER_PREFIX_CHANGED')
    need(struct.unpack_from('<I', provider, 38*4)[0] - image_base == 0x198b0
         and struct.unpack_from('<I', provider, 49*4)[0] - image_base == 0x1c320, 'PROVIDER_PREFIX_CHANGED')
    # Eligibility reads [controller+38] and calls its slot16. We only inspect it.
    need(values['eligibilityDependency'].startswith(bytes.fromhex('8b4838518b01ff5040')),
         'DEPENDENCY_OFFSET_CHANGED')
    # Aggregate call uses slot6; it must never be mistaken for GetService14.
    need(values['aggregateCallSite'][15:18] == bytes.fromhex('8b7218')
         and values['aggregateCallSite'][33:35] == bytes.fromhex('ffd6'), 'AGGREGATE_SLOT_CHANGED')
    return [{'name': n, 'module': 'devtool.dll', 'rva': r, 'bytes': c, 'sha256': h}
            for n, r, c, h in RANGES]


def verify_static():
    """Check known bytes, published SDK order and the one fixed new AS source."""
    for name, expected in DEPENDENCIES.items():
        need(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == expected, 'DEPENDENCY_CHANGED')
    need(hashlib.sha256((HERE / '../tests/NativeStockSelectionInventoryV106.as').read_bytes()).hexdigest()
         == NATIVE_SHA256, 'NATIVE_SOURCE_CHANGED')
    with zipfile.ZipFile(CACHE / 'snegopat.zip') as archive:
        need(0 < archive.getinfo(SDK_MEMBER).file_size <= 65536, 'SDK_BOUND')
        process = archive.read(SDK_MEMBER)
    need(hashlib.sha256(process).hexdigest() == SDK_SHA256, 'SDK_CHANGED')
    verify_process_layout(process.decode('utf-8-sig'))
    devtool, core = PE('devtool.dll'), PE('core83.dll')
    def read(pe, rva, count):
        start = pe.offset(pe.base + rva)
        return pe.data[start:start+count]
    ranges = verify_slices(lambda r, c: read(devtool, r, c), lambda r, c: read(core, r, c), devtool.base)
    v96 = verify_v96()
    return dict(stage='V106StockSelectionInventoryStaticContract', staticCompatible=True,
        platform='8.3.18.1208', nativeSourceSha256=NATIVE_SHA256,
        devtoolSha256=HASHES['devtool.dll'].lower(), coreSha256=HASHES['core83.dll'].lower(),
        sdkProcessSha256=SDK_SHA256, ranges=ranges, stockGeneratorWholeRanges=len(v96['ranges']),
        currentProcess=dict(module='core83.dll', rva=CURRENT_PROCESS[0], bytes=CURRENT_PROCESS[1],
                            sha256=CURRENT_PROCESS[2], nativeAbi='published cdecl; scoped counted SDK handle'),
        processInventorySlots=[0, 1, 2, 6, 14], eligibilityControllerFieldOffset=0x38,
        eligibilityDependencySlot=16, stockModelUsesAggregateInstanceSlot=6,
        existingStockModelServicePublished=False, unresolvedEligibilityTarget=True,
        inventoryCallable=True, publishedNewPlatformCalls=1, privateMachineCalls=0,
        unknownVirtualCalls=0, getServiceCalls=0, aggregateCalls=0, constructorCalls=0,
        plannerCalls=0, stockSelectionGetterCalls=0, fullStockSelectionVerified=False,
        futureCtorVerified=False, nativePermit=False, captureVerified=False,
        externalFullComparisonRequired=True)
