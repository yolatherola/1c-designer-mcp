"""One independently owned workday guardian; source and native profiles agree.

This owner is never launched by a stdio frontend. All application text stays
inside the trusted source provider in RAM; this module persists no source body.
"""
import hashlib
from pathlib import Path
import os
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import workday_saved_module_operation as root
from native_mcp.host_slot import HostSlot
from native_mcp.guardian_service import GuardianService
from native_mcp.guardian_descriptor import write_endpoint
from native_mcp.workday_receipt_observer import WorkdayReceiptObserver

# The honest controller pin is filled only after its final source review.
CONTROLLER_SHA = '071a49efd8f610e66fea01b1116623b13f145fe1c124aa2a862a5e1503d40df7'
PINS = {
    'native_mcp/host_slot.py': 'bb6882c1284106199a2f184ecc971fa97d249bb13011a8a1337d4a2ae158ea94',
    'native_mcp/guardian_service.py': '4c350782bc9cef3d5d0b74574471abee95c56faf547acd2e1424e47251b57e04',
    'native_mcp/guardian_descriptor.py': '244a2cecfbd7e12796807aa10ad3d13f9b87f11de74a82cc3ed30405aca3a0b3',
    'native_mcp/workday_wire.py': '06945271bfa4f22a474e400587ba8d558c4e6a8be2821ad9c4592bdd14790f46',
    'native_mcp/workday_pipe.py': '0d86fdc34b932c7a87b6286597308a44097447b3122a48be29966b7c3a2fe42f',
    'native_mcp/workday_channel.py': '3b601e1164fee759044cb3a77c43c9fb6f439ead0ce426eb9865df362f0bf6d8',
    'native_mcp/workday_provider.py': 'b9f43c59707aeecbd425c8be38aeb3dd6c14d9f94e14378743289dc2fa8eb71b',
    'native_mcp/workday_receipt_observer.py': 'fed1a725843aee2beee628229de5e383e6cd1d3f15b5074f585f3e614b4cdd2f',
    'research/workday_ram_carrier.py': 'ff59538b81fd2266e3e9f62912d79c20fb1f30b932c650a6659de0e1855f5f25',
}


def need(ok, code):
    if not ok:
        raise ValueError('WORKDAY_HOST_' + code)


def validate_scope(scope):
    root.validate_scope(scope)
    need(CONTROLLER_SHA != '0'*64 and hashlib.sha256(Path(root.__file__).read_bytes()).hexdigest()
         == CONTROLLER_SHA == scope.get('workdayControllerSha256'), 'CONTROLLER_PIN')
    for relative, pin in PINS.items():
        need(hashlib.sha256((HERE.parent/relative).read_bytes()).hexdigest() == pin, 'COMPOSITION_PIN')
    need(scope.get('workdayGuardianHostSha256') == hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
         and scope.get('independentGuardianProcessAuthorized') is True
         and scope.get('nativeOwnerUnderStdioJobAuthorized') is False, 'OWNERSHIP_SCOPE')


class WorkdayGuardianHost:
    """Own one honest v234 issued operation through verified native closure."""
    def __init__(self, scope_path, pin):
        path = root.c._plain(scope_path, root.ROOT/'artifacts/designer-bridge')
        scope = root.reader._json(path, pin)
        validate_scope(scope)
        self.operation = root.prepare_root(path, pin)
        self.slot = HostSlot()
        self.service = self.observer = None
        self.endpoint_path = None
        self.token = None
        self.finalizer_calls = 0
        self.root_result = None
        self.started = self.closed = False

    def stage(self):
        validate_scope(self.operation.scope)
        return root.stage_root(self.operation)

    def _finalize(self):
        need(self.finalizer_calls == 0, 'FINALIZER_ONCE')
        self.finalizer_calls += 1
        self.root_result = root.close_root(self.operation)
        return (self.root_result.get('knownTerminal') is True
                and type(self.root_result.get('sdkResult')) is int and self.root_result['sdkResult'] == 0
                and self.operation.phase == 'CLOSED' and self.operation.channel.closed
                and type(self.operation.host.returncode) is int and self.operation.host.returncode == 0)

    async def install(self, review_path, review_pin):
        """Install one reviewed native carrier, then publish its protected link."""
        validate_scope(self.operation.scope)
        need(not self.started, 'ONE_INSTALL')
        self.started = True
        connected = root.start_root_once(self.operation, review_path, review_pin)
        need(connected.get('status') == 'CONNECTED' and self.operation.phase == 'READY', 'NATIVE_READY')
        self.observer = WorkdayReceiptObserver(self.operation.provider.channel)
        self.operation.provider.channel = self.observer
        self.token = await self.slot.publish(self.operation.broker, self._finalize)
        self.service = GuardianService(self.slot)
        endpoint = await self.service.start()
        try:
            self.endpoint_path = root.ROOT/'artifacts/designer-bridge'/(
                'workday-guardian-endpoint-'+self.operation.plan['operationId']+'.json')
            write_endpoint(self.endpoint_path, endpoint)
        finally:
            endpoint.clear()
        return dict(status='WORKDAY_GUARDIAN_READY', operationId=self.operation.plan['operationId'],
                    ownerPid=os.getpid(), endpointPath=str(self.endpoint_path), sourceBodyFilesCreated=0)

    async def shutdown(self):
        """False retains this owner; no process kill, retry or DLL unload."""
        if self.closed:
            return True
        if not self.started:
            root.abort_before_start(self.operation)
            self.closed = self.operation.channel.closed
            return self.closed
        if self.operation.broker is None:
            return False
        known = await self.slot.shutdown()
        if not known or self.root_result is None or self.root_result.get('knownTerminal') is not True:
            return False
        if self.service is not None and not await self.service.stop(timeout=5):
            return False
        self.closed = True
        return True
