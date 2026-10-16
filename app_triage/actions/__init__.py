"""Fix actions: the only code that changes the user's system."""
from .executor import ACTIONS, ExecResult, execute, is_protected, undo_session

__all__ = ["ACTIONS", "ExecResult", "execute", "is_protected", "undo_session"]
