"""Name a future SDK compile by its actual payload; no SDK or filesystem calls.

Frozen loaders keep their original names. A new controller must include the
returned C bytes in its normal build review; this helper grants no authority.
"""
import hashlib
import json
import re

ANCHOR = b'args[0]=(uint32_t)"AH1C_FIXED_SDK_DIAGNOSIS_V14";'
PREFIX = '#define AH_SDK_FIXED_SOURCE '


def with_section_identity(files, *, operation_kind, operation_id):
    """Return copied build inputs and a text-free compile identity receipt.

    The source fingerprint is derived from the supplied header, never from a
    caller's claimed digest. Only the section-name literal in C is replaced.
    Nothing is compiled, loaded, written, or executed by this function.
    """
    def need(ok, code):
        if not ok:
            raise ValueError('SDK_SECTION_IDENTITY_' + code)

    need(type(operation_kind) is str and re.fullmatch('[A-Z][A-Z0-9_]{0,31}', operation_kind), 'KIND')
    need(type(operation_id) is str and re.fullmatch('[0-9a-f]{32}', operation_id), 'OPERATION')
    need(type(files) is dict and all(type(k) is str and type(v) is bytes for k, v in files.items()), 'FILES')
    need('Continuation.c' in files and 'sdk_probe_params.h' in files, 'INPUTS')
    carrier, header = files['Continuation.c'], files['sdk_probe_params.h']
    need(0 < len(carrier) <= 1048576 and 0 < len(header) <= 2097152, 'BOUNDS')
    need(carrier.count(ANCHOR) == 1, 'ONE_SECTION_ANCHOR')
    try:
        lines = [line for line in header.decode('utf-8').splitlines() if line.startswith(PREFIX)]
        need(len(lines) == 1, 'ONE_PAYLOAD')
        payload = json.loads(lines[0][len(PREFIX):])
        need(type(payload) is str and '\x00' not in payload and len(payload.encode('utf-8')) <= 1048576, 'PAYLOAD')
        payload_bytes = payload.encode('utf-8')
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError('SDK_SECTION_IDENTITY_PAYLOAD_ENCODING') from exc
    sha = lambda value: hashlib.sha256(value).hexdigest()
    payload_sha = sha(payload_bytes)
    section = 'AH1C_' + operation_kind + '_' + operation_id + '_' + payload_sha[:16]
    replacement = ('args[0]=(uint32_t)' + json.dumps(section) + ';').encode('ascii')
    output = dict(files)
    output['Continuation.c'] = carrier.replace(ANCHOR, replacement, 1)
    receipt = dict(kind='SDK_COMPILER_SECTION_IDENTITY', operationId=operation_id,
                   operationKind=operation_kind, compilerSection=section,
                   actualSourceSha256=payload_sha, inputCarrierSha256=sha(carrier),
                   outputCarrierSha256=sha(output['Continuation.c']),
                   sourceTextIncluded=False, warningSuppression=False,
                   nativeCalls=0, databaseUpdateAuthorized=False)
    return output, receipt
