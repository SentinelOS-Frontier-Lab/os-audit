"""OS-Audit: Attribution of Unauthorised Directives by Input Tracing."""
from .core import ASK, DATED, DICTATED, GO, HANDED, NAMED, NO_GO, SECRET, Evidence, Tools, Verdict, Watch, audit, echoed, is_action

__all__ = ["audit", "echoed", "Watch", "Verdict", "Evidence", "is_action", "Tools", "NAMED", "DICTATED", "DATED", "HANDED", "SECRET", "GO", "ASK", "NO_GO"]
__version__ = "0.1.0"
