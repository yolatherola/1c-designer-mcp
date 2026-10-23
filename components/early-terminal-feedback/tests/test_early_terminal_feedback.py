"""Portable fake pipe tests; no platform process, native calls or private state."""
import ctypes
import ctypes.util
from dataclasses import replace
import importlib.util
from pathlib import Path
import sys
from types import ModuleType,SimpleNamespace
import unittest
from unittest.mock import Mock,patch

ROOT=Path(__file__).resolve().parents[3]
COMPONENT=Path(__file__).resolve().parents[1]
namespace=ModuleType('native_mcp')
namespace.__path__=[str(ROOT/'source/tools/1c/designer-bridge/native_mcp')]
sys.modules['native_mcp']=namespace
spec=importlib.util.spec_from_file_location('native_mcp.early_terminal_feedback',COMPONENT/'early_terminal_feedback.py')
feedback=importlib.util.module_from_spec(spec);sys.modules[spec.name]=feedback
with patch.object(ctypes,'WinDLL',side_effect=AssertionError('NATIVE_CALL_FORBIDDEN'),create=True):
    spec.loader.exec_module(feedback)


class Clock:
    def __init__(self):self.now=0.
    def monotonic(self):return self.now
    def sleep(self,seconds):self.now+=seconds


class FeedbackTests(unittest.TestCase):
    def setUp(self):
        guard=patch.object(ctypes,'WinDLL',side_effect=AssertionError('NATIVE_CALL_FORBIDDEN'),create=True)
        self.windows=guard.start();self.addCleanup(guard.stop)
        self.clock=Clock()
        for patcher in (patch.object(feedback.time,'monotonic',self.clock.monotonic),
                        patch.object(feedback.time,'sleep',self.clock.sleep)):
            patcher.start();self.addCleanup(patcher.stop)
        self.binding=feedback.command_wire.EditorBinding('11111111-1111-4111-8111-111111111111',
            1234,'0123456789abcdef',5678,'a'*32,'b'*64,'c'*64,'d'*64)
        self.command=SimpleNamespace(binding=self.binding,sequence=1,opcode=1)
        self.value=feedback.TerminalUnknownFeedback(self.binding,1,1,'e'*64,'f'*64)
        self.buffer=bytearray();self.reads=[]
        self.reader=feedback.HeaderObserver()
        self.reader._handle=object()
        self.reader._api=SimpleNamespace(w=SimpleNamespace(PeekNamedPipe=lambda handle,size:(len(self.buffer),0)))
        def read(count,deadline):
            self.reads.append(count);raw=bytes(self.buffer[:count]);del self.buffer[:count];return raw
        self.reader._read=read

    def wait(self,observer,deadline=1.,abandoned=lambda:False):
        return self.reader._read_header_observed(8,deadline,abandoned,observer,self.command)

    def test_bound_feedback_returns_early_without_issuing_read(self):
        with self.assertRaises(feedback.EditorTerminalUnknown):
            self.wait(lambda:self.value if self.clock.now>=.55 else None,60.)
        self.assertLess(self.clock.now,.61)
        self.assertEqual(self.reads,[]);self.assertEqual(self.windows.call_count,0)

    def test_available_bytes_precede_callback(self):
        self.buffer.extend(b'12345678');callback=Mock(side_effect=AssertionError('CALLBACK_NOT_NEEDED'))
        self.assertEqual(self.wait(callback),b'12345678');callback.assert_not_called()
        self.assertEqual(self.reads,[8])

    def test_fragmented_header_consumes_only_available_bytes(self):
        fragments=iter([b'12',b'345',b'678'])
        def peek(*args):self.buffer.extend(next(fragments,b''));return len(self.buffer),0
        self.reader._api.w.PeekNamedPipe=peek
        self.assertEqual(self.wait(lambda:None),b'12345678');self.assertEqual(self.reads,[2,3,3])

    def test_foreign_or_extra_authority_feedback_does_not_shorten_deadline(self):
        candidates=[True,replace(self.value,binding=replace(self.binding,process_id=4321)),
            replace(self.value,sequence=2),replace(self.value,opcode=2),
            replace(self.value,diagnostic_sha256='0'*64),replace(self.value,result_sha256='G'*64),
            replace(self.value,resources_closed=True),replace(self.value,no_authority=False),
            replace(self.value,retry_authorized=True),replace(self.value,worker_terminal_verified=True),
            object.__new__(feedback.TerminalUnknownFeedback)]
        for candidate in candidates:
            self.clock.now=0.
            with self.subTest(candidate=type(candidate).__name__),self.assertRaises(feedback.EditorPipeRefusal):
                self.wait(lambda:candidate)
            self.assertEqual(self.clock.now,1.);self.assertEqual(self.reads,[])

    def test_async_and_failed_callbacks_keep_deadline(self):
        async def asynchronous():return self.value
        def failed():raise RuntimeError('SYNTHETIC_CALLBACK_FAILURE')
        for callback in (asynchronous,failed):
            self.clock.now=0.
            with self.subTest(callback=callback.__name__),self.assertRaises(feedback.EditorPipeRefusal):
                self.wait(callback)
            self.assertEqual(self.clock.now,1.)

    def test_invalid_peek_or_truncated_read_refuses(self):
        for answer in ((True,0),(-1,0),(0,True),(2**32,0)):
            self.reader._api.w.PeekNamedPipe=lambda *args:answer
            with self.subTest(answer=answer),self.assertRaisesRegex(feedback.EditorPipeRefusal,'PEEK'):
                self.wait(lambda:None)
        self.reader._api.w.PeekNamedPipe=lambda *args:(8,0)
        self.reader._read=lambda *args:b''
        with self.assertRaisesRegex(feedback.EditorPipeRefusal,'TRUNCATED'):self.wait(lambda:None)

    def test_abandoned_and_expired_wait_do_not_call_observer(self):
        callback=Mock(side_effect=AssertionError('CALLBACK_FORBIDDEN'))
        with self.assertRaisesRegex(feedback.EditorPipeRefusal,'ABANDONED'):
            self.wait(callback,abandoned=lambda:True)
        with self.assertRaisesRegex(feedback.EditorPipeRefusal,'DEADLINE_BEFORE_READ'):
            self.wait(callback,deadline=0.)
        callback.assert_not_called();self.assertFalse(self.reads)

    def test_feedback_never_claims_native_closure_or_write_authority(self):
        self.assertTrue(feedback._terminal_feedback(self.value,self.command))
        self.assertTrue(self.value.no_authority)
        for name in ('resources_closed','retry_authorized','native_cleanup_authorized','sdk_epoch_clean','worker_terminal_verified'):
            self.assertIs(getattr(self.value,name),False)
        self.assertEqual(self.windows.call_count,0)


if __name__=='__main__':unittest.main()
