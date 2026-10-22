"""Saved-domain RAM MCP; native transport is supplied only by trusted root code."""
from .saved_source import SourceBinding, Target, GuardState, ReadRequest, SnapshotReceipt, SavedSnapshot, SavedRefusal
from .server import SavedSession, create_server
