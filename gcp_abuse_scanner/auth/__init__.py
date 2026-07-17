"""Authentication and scope resolution."""

from gcp_abuse_scanner.auth.manager import AuthError, AuthManager
from gcp_abuse_scanner.auth.scope import ScopeResolver

__all__ = ["AuthManager", "AuthError", "ScopeResolver"]
