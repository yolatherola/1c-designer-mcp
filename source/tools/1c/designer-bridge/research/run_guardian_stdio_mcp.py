"""Guardian stdio relay; fixed protected descriptor bootstrap is root-owned.

No native owner/launcher is imported or started. Capability stays encrypted on
disk and is decrypted only by the reviewed root descriptor reader into RAM.
"""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_mcp.guardian_client import GuardianRpcClient
from native_mcp.guardian_relay_server import create_guardian_relay_server


class RelayClosureUnproven(RuntimeError):
    """Local relay drain/closure could not be confirmed."""


async def serve(client):
    """Serve an exact root-injected RAM client; finally close only its relay."""
    if type(client) is not GuardianRpcClient:
        raise ValueError('GUARDIAN_CLIENT_TYPE')
    try:
        await create_guardian_relay_server(client).run_stdio_async()
    finally:
        if not await client.close():
            raise RelayClosureUnproven('GUARDIAN_RELAY_CLOSURE_UNPROVEN') from None
    return 0


def main():
    # The sole path is root-owned protected technical metadata, never a source,
    # command, native loader, connection string, or public MCP tool argument.
    if len(sys.argv) == 1:
        sys.stderr.write('GUARDIAN_RELAY_ENDPOINT_REQUIRED\n')
        return 2
    if len(sys.argv) != 3 or sys.argv[1] != '--endpoint':
        sys.stderr.write('GUARDIAN_RELAY_ARGUMENTS_REFUSED\n')
        return 2
    valid = True
    try:
        from native_mcp.guardian_descriptor import read_endpoint
        path = Path(sys.argv[2])
        allowed = Path(__file__).resolve().parents[4] / 'artifacts/designer-bridge'
        if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(allowed.resolve(strict=True)):
            raise ValueError('GUARDIAN_DESCRIPTOR_PATH')
        # Reader additionally enforces regular-file/no-reparse/profile/codepins,
        # DPAPI CurrentUser integrity, guardian identity and exact endpoint keys.
        client = GuardianRpcClient(read_endpoint(path))
    except Exception:
        valid = False
    if not valid:
        sys.stderr.write('GUARDIAN_RELAY_ENDPOINT_REFUSED\n')
        return 2
    failed = closure_failed = False
    try:
        return asyncio.run(serve(client))
    except KeyboardInterrupt:
        return 130
    except RelayClosureUnproven:
        closure_failed = True
    except Exception:
        failed = True
    if closure_failed:
        sys.stderr.write('GUARDIAN_RELAY_CLOSURE_UNPROVEN\n')
    elif failed:
        sys.stderr.write('GUARDIAN_RELAY_PROTOCOL_FAILED\n')
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
