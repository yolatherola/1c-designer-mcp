"""Pinned stock Main/DB comparison model; import does not read or invoke APIs.

This is static evidence, not a callable native getter or a Save/DB capability.
The DB model has a UI branch, so its complete method is not a read-only probe.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re
import struct
import uuid
import zipfile

VERSION = '8.3.18.1208'
ROOT = Path(__file__).resolve().parents[4]
ARCHIVE = ROOT / 'artifacts/designer-bridge/runtime-cache/core-as-snegopat-v40/snegopat.zip'
ARCHIVE_BYTES = 4630548
ARCHIVE_SHA = '464256ea84009d66f2d177ce92cb128479ba634da6a493a93aef579410710fde'
HBK = Path(r'C:/Program Files (x86)/1cv8/8.3.18.1208/bin/1cv8_ru.hbk')
HBK_BYTES = 1899142
HBK_SHA = '5b707daefd470873c166f330b4da7f32c3bf8a25c1e0776b90759b9b3194476a'
HELP = 'zif3_comparecfg'
HELP_BYTES = 7339
HELP_SHA = 'c1523daad3967d477659413028edf93dacb50736d303f1389e2deb4b527b7925'
MEMBERS = {
    'modules/snegopat/addins/std/commands.js': (26615, '4c7bcbd5703b87f1edb71c54e280ff78c8565b690b2ea2204c975c1dabfcc93f'),
    'modules/snegopat/v8api/metadata.v': (13362, 'd362afbaed27a811a9100dead71d8948343ea0281f9cacc8a983e7c6ba2ce7ed'),
}
RANGES = {
    'compareId': ('config.dll', 0x340494, 20, 'f69dfd38789cb44e9efd781b027db63db3e63a9572c654236388e0035b5bd903'),
    'openDbId': ('config.dll', 0x3404d0, 20, 'b795450c3e9f2544f51ed6d2bac28ed98e7f7a0e9b42b0033f9f0e80d71d4cb2'),
    'dispatcher': ('config.dll', 0xa3170, 3913, '7471cc738d5c610b5ca8d64453425da67913b4d109670761a08a3c4381170c76'),
    'compareExecute': ('config.dll', 0x141c20, 131, 'e164493a48cc4757e0ac407f0f75e3dc55b85d930ea04e4371f638d5c2b8c869'),
    'openDbExecute': ('config.dll', 0x141d00, 27, 'e0afae771b6faa71d935c01bf0c5e40711338e7d545a51c7c45c72d3111f966c'),
    'compareBuilder': ('config.dll', 0xc1420, 569, '9044841d2edf9d2cf2d11d05aec0134af6f38f58ea5323f5feafd012fac90cb2'),
    'compareBuilderThrowTail': ('config.dll', 0xc1659, 46, '4ecfa9e42fe32a5ff25ce024447cd097d35f73ef87b3c30f00d01fedf27989d1'),
    'mainTable': ('config.dll', 0x2b9ce0, 64, '73ebc936989cc6e29f0791105ddc787b02de2a1ab3d0454dbd13e280365ee44b'),
    'dbTable': ('config.dll', 0x2b9d28, 64, 'e084d999721aafd4f6f51533e8011122a60a8254e7e1c6b7b2925986b3588953'),
    'mainLabel': ('config.dll', 0x2c1254, 36, '7127fda2993c29754e45cc2cbb1a6891dcf738afe06e99119401c944b675f90d'),
    'dbLabel': ('config.dll', 0x2c1278, 32, 'b7b7831bfc27e805ae3a9f586f131a3b044a134e5d68e4929697d336c494fe08'),
    'mainLabelInit': ('config.dll', 0x11e700, 86, '2513bfefb915ce92943fa2c5cce0f72b9ed0fc4012437a03e7399203698f81da'),
    'dbLabelInit': ('config.dll', 0x11e780, 86, 'c7e4639a4c479e2bdeff2845cae0dd36b4f517aa9ae9b6dd8597660a610a7bc2'),
    'mainLabelGetter': ('config.dll', 0x17c2d0, 8, 'da6e855d9592650ea899bb29415ad38bdf84a96b01c5dc397523c461420f85ce'),
    'dbLabelGetter': ('config.dll', 0x17c3f0, 8, '422251147db4a7982e027d138334effa320d64bc756f649c7c1842a1bc663bcf'),
    'mainKind': ('config.dll', 0x17c2e0, 5, '16b05fa5f9ba0f4ff2fdb061c41acb7f1a7a65abd21be60136b864fa61a6d631'),
    'dbKind': ('config.dll', 0x17c400, 5, 'e21a8b64f5c7e230e09aa253b105f13de219493c4bc4a8863b9ade9059bc6cea'),
    # Main includes its seven-byte forward tail beyond the first normal ret.
    'mainManager': ('config.dll', 0x17c340, 157, '3d28e9baf9740e48cc4056758cfd96a00f325090519debc6c7bf92b098f5efa2'),
    'dbManager': ('config.dll', 0x17c440, 686, '001c004a76a992148a60ee1843385f915377063d63b8c5ce0cd8db4f8c9eac50'),
    # Bounded install slices, not whole constructors or registration functions.
    'mainModelInstall': ('config.dll', 0xb1acd, 44, 'a552b8dc8c55d644684d3632527739c35b41fbf9bfe5a654c4b3ee48a5d7e86c'),
    'dbModelInstall': ('config.dll', 0xb1b49, 50, 'ab74b320efef987261c750e28dbde8e2557dfa04fd57310b2601864572aed15c'),
}
CONFIG_BASE = 0x25e40000
GROUP = 'f10cbb81-f679-11d4-9dd3-0050bae2bc79'
COMPARE_PROFILE = {
    'first': 'DBConfiguration', 'second': 'MainConfiguration',
    'mapping': 'ByObjectIDs', 'report': 'Brief', 'format': 'txt',
    'includeChanged': True, 'includeDeleted': True, 'includeAdded': True,
    'objectsFilter': None,
}
FALSE_CLAIMS = (
    'nativePermit', 'saveAuthorized', 'databaseUpdateAuthorized', 'pendingOwnOnlyVerified',
    'runtimeIInfoBaseDatabaseRoleVerified', 'runtimeContextManagerAbiVerified',
    'publishedDirectDatabaseGetterVerified', 'wholeDatabaseGetterReadOnlyVerified',
    'wholeTransitiveMethodsVerified', 'exceptionUnwindVerified', 'mainColdForwarderVerified',
    'currentUnsavedDesignerCompared', 'captureAuthorized', 'repositoryPlacementAuthorized',
)


def need(ok, code):
    if not ok:
        raise ValueError('V154_' + code)


def validate_compare_profile(value):
    """Validate the data-only full report profile; never build/execute a process."""
    need(type(value) is dict and set(value) == set(COMPARE_PROFILE), 'PROFILE_KEYS')
    for key, expected in COMPARE_PROFILE.items():
        need(type(value[key]) is type(expected) and value[key] == expected, 'PROFILE_REJECTED')
    return dict(fullScope=True, byObjectIDs=True, brief=True, objectsFilter=False,
                persistedMainVersusDatabase=True, pendingOwnOnlyVerified=False,
                databaseUpdateAuthorized=False, currentUnsavedDesignerCompared=False)


def _read(reader, args, size, sha, limit, code):
    need(callable(reader), code)
    try:
        raw = reader(*args)
    except Exception:
        raise ValueError('V154_' + code) from None
    need(type(raw) is bytes and 0 < len(raw) <= limit and len(raw) == size
         and hashlib.sha256(raw).hexdigest() == sha, code)
    return raw


def verify_structure(parts):
    """Check only closed stock model layout bytes; this never adopts a pointer."""
    need(type(parts) is dict and set(parts) == set(RANGES), 'SPAN_KEYS')
    need(all(type(parts[k]) is bytes and len(parts[k]) == RANGES[k][2] for k in parts), 'SPAN_SIZE')
    for key, ident in (('compareId', 30), ('openDbId', 34)):
        need(parts[key] == uuid.UUID(GROUP).bytes_le + struct.pack('<I', ident), 'COMMAND_ID')
    for prefix, table, name, global_rva, label_rva, kind, getter in (
            ('main', 0x2b9ce0, 'MainConfiguration', 0x399000, 0x2c1254, b'\xd9\xee', 0x17c340),
            ('db', 0x2b9d28, 'DBConfiguration', 0x399018, 0x2c1278, b'\xd9\xe8', 0x17c440)):
        need(parts[prefix + 'Label'] == (name + '\0').encode('utf-16-le'), 'MODEL_LABEL')
        init = parts[prefix + 'LabelInit']
        need(b'\x68' + struct.pack('<I', CONFIG_BASE + label_rva) in init
             and b'\xb9' + struct.pack('<I', CONFIG_BASE + global_rva) in init, 'LABEL_INITIALIZER')
        need(parts[prefix + 'LabelGetter'][:8] == b'\xb8' + struct.pack('<I', CONFIG_BASE + global_rva)
             + b'\xc2\x04\x00', 'LABEL_GETTER')
        need(parts[prefix + 'Kind'] == kind + b'\xc2\x04\x00', 'MODEL_KIND')
        cells = struct.unpack('<16I', parts[prefix + 'Table'])
        need(cells[4] == CONFIG_BASE + RANGES[prefix + 'LabelGetter'][1]
             and cells[5] == CONFIG_BASE + RANGES[prefix + 'Kind'][1]
             and cells[13] == CONFIG_BASE + getter, 'MODEL_TABLE')
        install = parts[prefix + 'ModelInstall']
        need(b'\xc7\x00' + struct.pack('<I', CONFIG_BASE + table) in install
             and b'\x89\x46\x10' in install, 'CONTEXT_INSTALL')
    main, db, builder = parts['mainManager'], parts['dbManager'], parts['compareBuilder']
    need(b'\x8b\x70\x1c' in main and b'\x8b\x48\x24' in db, 'MANAGER_FIELDS')
    need(b'\x89\x37' in main and b'\x8b\x0e\x56\xff\x51\x04' in main
         and b'\x89\x0e' in db and b'\x8b\x01\x51\xff\x50\x04' in db, 'COUNTED_OUTPUT')
    need(main[-7:] == b'\x51\xff\xd0\x8b\xf0\xeb\xa3'
         and main[0x38:0x3a] == b'\x75\x5c' and db.endswith(b'\xc2\x14\x00'), 'NORMAL_TAIL')
    # The DB early old-version branch reaches UI paths. Pin the exact later
    # branch which copies +24 to output; do not mark the whole method read-only.
    need(db[0xa2:0xa8] == b'\x0f\x84\x9b\x01\x00\x00'
         and b'\xff\x50\x58' not in db[0x243:0x28f]
         and b'\xff\x50\x04' in db[0x243:0x28f], 'DB_BRANCH')
    need(b'\x8b\x56\x24\x8b\x76\x1c' in builder
         and builder.count(b'\x8b\x80\x54\x01\x00\x00') == 1
         and b'\x8b\x88\x54\x01\x00\x00' in builder
         and builder.endswith(b'\xc2\x08\x00'), 'PAIR_BUILDER')
    need(builder[0x55:0x5b] == b'\x0f\x84\xde\x01\x00\x00'
         and parts['compareBuilderThrowTail'][:2] == b'\x6a\x00'
         and parts['compareBuilderThrowTail'][-5:] == b'\xe8\x61\x48\x1b\x00', 'BUILDER_COLD_TAIL')
    return dict(stockModelsClassified=True, stockMainManagerField=0x1c,
                stockDatabaseManagerField=0x24, countedModelOutputAddRefVerified=True,
                pairSlot85CallSitesVerified=True, databaseModelHasUiBranch=True,
                compareBuilderColdThrowTailPinned=True,
                nativePermit=False, runtimeIInfoBaseDatabaseRoleVerified=False)


def verify_inventory(read_member, read_slice, read_help, version=VERSION):
    """Check trusted read-only fixed readers; return facts, no execution authority."""
    need(type(version) is str and version == VERSION, 'VERSION')
    members = {k: _read(read_member, (k,), n, h, 32768, 'SDK_PIN') for k, (n, h) in MEMBERS.items()}
    parts = {k: _read(read_slice, (m, r, n), n, h, 4096, 'PE_PIN') for k, (m, r, n, h) in RANGES.items()}
    help_bytes = _read(read_help, (HELP,), HELP_BYTES, HELP_SHA, 8192, 'HELP_PIN')
    commands, metadata = (members[k].decode('utf-8-sig') for k in MEMBERS)
    need('CompareDBCfg: new Command(30,' in commands and 'OpenDBCfg: new Command(34,' in commands
         and GROUP.upper() in commands.upper(), 'SDK_COMMAND')
    need('IMDContainer@+ getMDCont(int i = 0)' in metadata
         and 'IConfigMngr@+ getConfigMgr()' in metadata, 'SDK_GETTER')
    help_text = re.sub('<[^>]*>', '', help_bytes.decode('utf-8-sig')).replace('&nbsp;', ' ')
    need(all(x in help_text for x in ('MainConfiguration', 'DBConfiguration', 'ByObjectIDs', 'Brief',
         '-IncludeChangedObjects', '-IncludeDeletedObjects', '-IncludeAddedObjects',
         'Если не указан, отчет строится по всей конфигурации.')), 'HELP_SCOPE')
    result = verify_structure(parts)
    result.update(version=VERSION, spanCount=len(RANGES), sdkCount=len(MEMBERS),
                  fullUnfilteredReportScopeDocumented=True, onlyStaticEvidence=True,
                  sourceConfigurationExported=False,
                  spanSha256={k: v[3] for k, v in RANGES.items()},
                  sdkSha256={k: v[1] for k, v in MEMBERS.items()}, helpSha256=HELP_SHA)
    result.update({k: False for k in FALSE_CLAIMS})
    result['compareProfile'] = validate_compare_profile(dict(COMPARE_PROFILE))
    return result


def _help_bytes(raw):
    """Read the single pinned installed-help stream in memory; extract no files."""
    need(type(raw) is bytes and len(raw) == HBK_BYTES and hashlib.sha256(raw).hexdigest() == HBK_SHA, 'HBK_PIN')
    page = re.compile(rb'\r\n([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) ([0-9a-fA-F]{8}) \r\n')

    def stream(at):
        output, seen, total = bytearray(), set(), None
        while at != 0x7fffffff:
            need(type(at) is int and at not in seen and 16 <= at < len(raw) and len(seen) < 8192, 'HBK_CHAIN')
            seen.add(at); match = page.match(raw, at)
            need(match is not None, 'HBK_PAGE')
            size, capacity, following = (int(match[i], 16) for i in (1, 2, 3))
            if total is None:
                total = size
            need(0 < capacity and 0 <= total <= 2 * 1024 * 1024 and at + 31 + capacity <= len(raw), 'HBK_BOUNDS')
            output.extend(raw[at + 31:at + 31 + min(capacity, total - len(output))]); at = following
        need(total is not None and len(output) == total, 'HBK_SIZE')
        return bytes(output)

    directory = stream(16)
    need(len(directory) == 84, 'HBK_DIRECTORY')
    matches = []
    for at in range(0, len(directory), 12):
        name_at, body_at, sentinel = struct.unpack_from('<III', directory, at)
        need(sentinel == 0x7fffffff, 'HBK_SENTINEL')
        name = stream(name_at)[20:].decode('utf-16-le').rstrip('\0')
        if name == 'FileStorage':
            matches.append(stream(body_at))
    need(len(matches) == 1 and len(matches[0]) == 1853388
         and hashlib.sha256(matches[0]).hexdigest() == '1bfb665887c42d85d5b5f2f7dd58a81ffd16e643fe85a0d06bf3a4c00be03aaf', 'HELP_STORAGE')
    with zipfile.ZipFile(io.BytesIO(matches[0])) as archive:
        names = [entry for entry in archive.infolist() if entry.filename == HELP]
        need(len(names) == 1 and names[0].file_size == HELP_BYTES, 'HELP_MEMBER')
        return archive.read(names[0])


def verify_static():
    """Read hash-pinned SDK/help/PE files only; no DLL load or native invocation."""
    from repository_pe_probe import PE
    archive_bytes = ARCHIVE.read_bytes()
    need(len(archive_bytes) == ARCHIVE_BYTES and hashlib.sha256(archive_bytes).hexdigest() == ARCHIVE_SHA, 'ARCHIVE_PIN')
    image = PE('config.dll')
    help_bytes = _help_bytes(HBK.read_bytes())
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        def member(name):
            need(name in MEMBERS and sum(x.filename == name for x in archive.infolist()) == 1, 'MEMBER_NAME')
            return archive.read(name)

        def sliced(module, rva, size):
            need((module, rva, size) in {v[:3] for v in RANGES.values()}, 'SLICE_NAME')
            offset = image.offset(image.base + rva)
            return image.data[offset:offset + size]

        result = verify_inventory(member, sliced, lambda name: help_bytes if name == HELP else None)
    result.update(wholePlatformHashVerified=True, platformSha256=hashlib.sha256(image.data).hexdigest(),
                  archiveSha256=ARCHIVE_SHA, helpBookSha256=HBK_SHA)
    return result
