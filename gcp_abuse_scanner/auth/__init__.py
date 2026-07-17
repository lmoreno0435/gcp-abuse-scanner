"""Authentication and scope resolution."""

from gcp_abuse_scanner.auth.manager import AuthManager, AuthError
from gcp_abuse_scanner.auth.scope import ScopeResolver

__all__ = ["AuthManager", "AuthError", "ScopeResolver"]
