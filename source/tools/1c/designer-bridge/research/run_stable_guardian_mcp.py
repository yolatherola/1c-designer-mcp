"""Zero-argument stable saved-source MCP frontend; no native bootstrap."""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_mcp.stable_gateway import StableGateway, create_stable_guardian_server


class StableRelayClosureUnproven(RuntimeError):
    """The frontend relay did not prove its own local closure."""


async def serve(gateway):
    if type(gateway) is not StableGateway: raise ValueError('STABLE_GATEWAY_TYPE')
    try:
        await create_stable_guardian_server(gateway).run_stdio_async()
    finally:
        if await gateway.close() is not True:
            raise StableRelayClosureUnproven('STABLE_RELAY_CLOSURE_UNPROVEN') from None
    return 0


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        sys.stderr.write('STABLE_GATEWAY_ARGUMENTS_REFUSED\n'); return 2
    failed = False
    try: return asyncio.run(serve(StableGateway()))
    except KeyboardInterrupt: return 130
    except Exception: failed = True
    if failed: sys.stderr.write('STABLE_GATEWAY_UNPROVEN\n')
    return 1


if __name__ == '__main__': raise SystemExit(main())
