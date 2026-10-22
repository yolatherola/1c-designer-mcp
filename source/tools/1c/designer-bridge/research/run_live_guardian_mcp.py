"""Zero-argument LIVE MCP relay; no native bootstrap or EOF native closure."""
import asyncio
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_mcp.live_gateway import LiveGateway, create_live_guardian_server


async def serve(gateway):
    if type(gateway) is not LiveGateway: raise ValueError('LIVE_GATEWAY_TYPE')
    try:
        await create_live_guardian_server(gateway).run_stdio_async()
    finally:
        if await gateway.close() is not True:
            raise RuntimeError('LIVE_RELAY_CLOSURE_UNPROVEN') from None
    return 0


def main(argv=None):
    if (sys.argv[1:] if argv is None else argv):
        sys.stderr.write('LIVE_GATEWAY_ARGUMENTS_REFUSED\n'); return 2
    try: return asyncio.run(serve(LiveGateway()))
    except KeyboardInterrupt: return 130
    except Exception: pass
    sys.stderr.write('LIVE_GATEWAY_UNPROVEN\n')
    return 1


if __name__ == '__main__': raise SystemExit(main())
