"""Environment configuration for the MCP ClickHouse server.

This module handles all environment variable configuration with sensible defaults
and type conversion.
"""

from dataclasses import dataclass
import os
from typing import Optional
from enum import Enum


class TransportType(str, Enum):
    """Supported MCP server transport types."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"

    @classmethod
    def values(cls) -> list[str]:
        """Get all valid transport values."""
        return [transport.value for transport in cls]


@dataclass
class ClickHouseConfig:
    """Configuration for ClickHouse connection settings.

    This class handles all environment variable configuration with sensible defaults
    and type conversion. It provides typed methods for accessing each configuration value.

    Required environment variables (only when CLICKHOUSE_ENABLED=true):
        CLICKHOUSE_HOST: The hostname of the ClickHouse server
        CLICKHOUSE_USER: The username for authentication
        CLICKHOUSE_PASSWORD: The password for authentication

    Optional environment variables (with defaults):
        CLICKHOUSE_ROLE: The role to use for authentication (default: None)
        CLICKHOUSE_PORT: The port number (default: 8443 if secure=True, 8123 if secure=False)
        CLICKHOUSE_SECURE: Enable HTTPS (default: true)
        CLICKHOUSE_VERIFY: Verify SSL certificates (default: true)
        CLICKHOUSE_CONNECT_TIMEOUT: Connection timeout in seconds (default: 30)
        CLICKHOUSE_SEND_RECEIVE_TIMEOUT: Send/receive timeout in seconds (default: 300)
        CLICKHOUSE_DATABASE: Default database to use (default: None)
        CLICKHOUSE_PROXY_PATH: Path to be added to the host URL. For instance, for servers behind an HTTP proxy (default: None)
        CLICKHOUSE_ENABLED: Enable ClickHouse server (default: true)
        CLICKHOUSE_ALLOW_WRITE_ACCESS: Allow write operations (DDL and DML) (default: false)
        CLICKHOUSE_ALLOW_DROP: Allow destructive operations (DROP, TRUNCATE) when writes are also enabled (default: false)
    """

    def __init__(self):
        """Initialize the configuration from environment variables."""
        if self.enabled:
            self._validate_required_vars()

    @property
    def enabled(self) -> bool:
        """Get whether ClickHouse server is enabled.

        Default: True
        """
        return os.getenv("CLICKHOUSE_ENABLED", "true").lower() == "true"

    @property
    def host(self) -> str:
        """Get the ClickHouse host."""
        return os.environ["CLICKHOUSE_HOST"]

    @property
    def port(self) -> int:
        """Get the ClickHouse port.

        Defaults to 8443 if secure=True, 8123 if secure=False.
        Can be overridden by CLICKHOUSE_PORT environment variable.
        """
        if "CLICKHOUSE_PORT" in os.environ:
            return int(os.environ["CLICKHOUSE_PORT"])
        return 8443 if self.secure else 8123

    @property
    def username(self) -> str:
        """Get the ClickHouse username."""
        return os.environ["CLICKHOUSE_USER"]

    @property
    def password(self) -> str:
        """Get the ClickHouse password."""
        return os.environ["CLICKHOUSE_PASSWORD"]

    @property
    def role(self) -> Optional[str]:
        """Get the ClickHouse role."""
        return os.getenv("CLICKHOUSE_ROLE")

    @property
    def database(self) -> Optional[str]:
        """Get the default database name if set."""
        return os.getenv("CLICKHOUSE_DATABASE")

    @property
    def secure(self) -> bool:
        """Get whether HTTPS is enabled.

        Default: True
        """
        return os.getenv("CLICKHOUSE_SECURE", "true").lower() == "true"

    @property
    def verify(self) -> bool:
        """Get whether SSL certificate verification is enabled.

        Default: True
        """
        return os.getenv("CLICKHOUSE_VERIFY", "true").lower() == "true"

    @property
    def connect_timeout(self) -> int:
        """Get the connection timeout in seconds.

        Default: 30
        """
        return int(os.getenv("CLICKHOUSE_CONNECT_TIMEOUT", "30"))

    @property
    def send_receive_timeout(self) -> int:
        """Get the send/receive timeout in seconds.

        Default: 300 (ClickHouse default)
        """
        return int(os.getenv("CLICKHOUSE_SEND_RECEIVE_TIMEOUT", "300"))

    @property
    def proxy_path(self) -> str:
        return os.getenv("CLICKHOUSE_PROXY_PATH")

    @property
    def allow_write_access(self) -> bool:
        """Get whether write operations (DDL and DML) are allowed.

        Default: False
        """
        return os.getenv("CLICKHOUSE_ALLOW_WRITE_ACCESS", "false").lower() == "true"

    @property
    def allow_drop(self) -> bool:
        """Get whether DROP operations (DROP TABLE, DROP DATABASE) are allowed.

        This setting provides an additional safety layer when write access is enabled.
        Even with CLICKHOUSE_ALLOW_WRITE_ACCESS=true, DROP operations require this flag.

        Default: False
        """
        return os.getenv("CLICKHOUSE_ALLOW_DROP", "false").lower() == "true"

    def get_client_config(self) -> dict:
        """Get the configuration dictionary for clickhouse_connect client.

        Returns:
            dict: Configuration ready to be passed to clickhouse_connect.get_client()
        """
        config = {
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "password": self.password,
            "interface": "https" if self.secure else "http",
            "secure": self.secure,
            "verify": self.verify,
            "connect_timeout": self.connect_timeout,
            "send_receive_timeout": self.send_receive_timeout,
            "client_name": "mcp_clickhouse",
        }

        # Add optional role if set
        if self.role:
            config.setdefault("settings", {})["role"] = self.role

        # Add optional database if set
        if self.database:
            config["database"] = self.database

        if self.proxy_path:
            config["proxy_path"] = self.proxy_path

        return config

    def _validate_required_vars(self) -> None:
        """Validate that all required environment variables are set.

        Raises:
            ValueError: If any required environment variable is missing.
        """
        missing_vars = []
        for var in ["CLICKHOUSE_HOST", "CLICKHOUSE_USER", "CLICKHOUSE_PASSWORD"]:
            if var not in os.environ:
                missing_vars.append(var)

        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")


@dataclass
class ChDBConfig:
    """Configuration for chDB connection settings.

    This class handles all environment variable configuration with sensible defaults
    and type conversion. It provides typed methods for accessing each configuration value.

    Required environment variables:
        CHDB_DATA_PATH: The path to the chDB data directory (only required if CHDB_ENABLED=true)
    """

    def __init__(self):
        """Initialize the configuration from environment variables."""
        if self.enabled:
            self._validate_required_vars()

    @property
    def enabled(self) -> bool:
        """Get whether chDB is enabled.

        Default: False
        """
        return os.getenv("CHDB_ENABLED", "false").lower() == "true"

    @property
    def data_path(self) -> str:
        """Get the chDB data path."""
        return os.getenv("CHDB_DATA_PATH", ":memory:")

    def get_client_config(self) -> dict:
        """Get the configuration dictionary for chDB client.

        Returns:
            dict: Configuration ready to be passed to chDB client
        """
        return {
            "data_path": self.data_path,
        }

    def _validate_required_vars(self) -> None:
        """Validate that all required environment variables are set.

        Raises:
            ValueError: If any required environment variable is missing.
        """
        pass


# Global instance placeholders for the singleton pattern
_CONFIG_INSTANCE = None
_CHDB_CONFIG_INSTANCE = None


def get_config():
    """
    Gets the singleton instance of ClickHouseConfig.
    Instantiates it on the first call.
    """
    global _CONFIG_INSTANCE
    if _CONFIG_INSTANCE is None:
        # Instantiate the config object here, ensuring load_dotenv() has likely run
        _CONFIG_INSTANCE = ClickHouseConfig()
    return _CONFIG_INSTANCE


def get_chdb_config() -> ChDBConfig:
    """
    Gets the singleton instance of ChDBConfig.
    Instantiates it on the first call.

    Returns:
        ChDBConfig: The chDB configuration instance
    """
    global _CHDB_CONFIG_INSTANCE
    if _CHDB_CONFIG_INSTANCE is None:
        _CHDB_CONFIG_INSTANCE = ChDBConfig()
    return _CHDB_CONFIG_INSTANCE


@dataclass
class MCPServerConfig:
    """Configuration for MCP server-level settings.

    These settings control the server transport and tool behavior and are
    intentionally independent of ClickHouse connection validation.

    Optional environment variables (with defaults):
        CLICKHOUSE_MCP_SERVER_TRANSPORT: "stdio", "http", or "sse" (default: stdio)
        CLICKHOUSE_MCP_BIND_HOST: Bind host for HTTP/SSE (default: 127.0.0.1)
        CLICKHOUSE_MCP_BIND_PORT: Bind port for HTTP/SSE (default: 8000)
        CLICKHOUSE_MCP_QUERY_TIMEOUT: SELECT tool timeout in seconds (default: 30)
        CLICKHOUSE_MCP_AUTH_TOKEN: Authentication token for HTTP/SSE transports (required
            unless CLICKHOUSE_MCP_AUTH_DISABLED=true or CLICKHOUSE_MCP_OAUTH_PROXY_ENABLED=true)
        CLICKHOUSE_MCP_AUTH_DISABLED: Disable authentication (default: false, use
            only for development)
        CLICKHOUSE_MCP_OAUTH_PROXY_ENABLED: Enable OAuth proxy mode where nginx ingress
            handles OAuth2/Keycloak authentication and forwards group membership via
            X-Auth-Request-Groups header (default: false)
        CLICKHOUSE_MCP_ALLOWED_GROUPS: Comma-separated list of Keycloak groups whose
            members are allowed access (e.g. "Dastan-Team"). Used in both OAuth proxy
            mode and OIDC mode for group-based access control.
        CLICKHOUSE_MCP_OIDC_ENABLED: Enable OIDC mode — FastMCP acts as an OAuth2 proxy
            to Keycloak, serves /.well-known/oauth-authorization-server, and validates
            Keycloak JWTs. This is required for MCP clients like Claude Code that
            follow the MCP OAuth2 spec (default: false).
        CLICKHOUSE_MCP_OIDC_DISCOVERY_URL: Keycloak OIDC discovery URL, e.g.
            https://sso.example.com/realms/myrealm/.well-known/openid-configuration
        CLICKHOUSE_MCP_OIDC_CLIENT_ID: Keycloak client ID for the MCP server
        CLICKHOUSE_MCP_OIDC_CLIENT_SECRET: Keycloak client secret for the MCP server
        CLICKHOUSE_MCP_BASE_URL: Public base URL of this MCP server, e.g.
            https://clickhouse-mcp.yektanet.tech (required for OIDC mode)
        CLICKHOUSE_MCP_OIDC_SCOPES: Optional space or comma separated scopes sent to
            Keycloak on authorize, e.g. "openid profile email offline_access".
            Adding offline_access makes Keycloak issue offline refresh tokens that
            outlive the SSO session idle timeout (default: unset, Keycloak defaults).
    """

    @property
    def server_transport(self) -> str:
        transport = os.getenv("CLICKHOUSE_MCP_SERVER_TRANSPORT", TransportType.STDIO.value).lower()
        if transport not in TransportType.values():
            valid_options = ", ".join(f'"{t}"' for t in TransportType.values())
            raise ValueError(f"Invalid transport '{transport}'. Valid options: {valid_options}")
        return transport

    @property
    def bind_host(self) -> str:
        return os.getenv("CLICKHOUSE_MCP_BIND_HOST", "127.0.0.1")

    @property
    def bind_port(self) -> int:
        return int(os.getenv("CLICKHOUSE_MCP_BIND_PORT", "8000"))

    @property
    def query_timeout(self) -> int:
        return int(os.getenv("CLICKHOUSE_MCP_QUERY_TIMEOUT", "30"))

    @property
    def auth_token(self) -> Optional[str]:
        """Get the authentication token for HTTP/SSE transports."""
        return os.getenv("CLICKHOUSE_MCP_AUTH_TOKEN", None)

    @property
    def auth_disabled(self) -> bool:
        """Get whether authentication is disabled."""
        return os.getenv("CLICKHOUSE_MCP_AUTH_DISABLED", "false").lower() == "true"

    @property
    def oauth_proxy_enabled(self) -> bool:
        """Enable OAuth proxy mode.

        When true, the nginx ingress oauth2-proxy handles Keycloak authentication
        and forwards X-Auth-Request-Groups / X-Auth-Request-Email headers.
        Bearer token auth is disabled; group membership is validated by
        OAuthProxyGroupMiddleware instead.
        """
        return os.getenv("CLICKHOUSE_MCP_OAUTH_PROXY_ENABLED", "false").lower() == "true"

    @property
    def allowed_groups(self) -> list[str]:
        """Keycloak groups allowed to access the server (used in both auth modes)."""
        raw = os.getenv("CLICKHOUSE_MCP_ALLOWED_GROUPS", "")
        return [g.strip() for g in raw.split(",") if g.strip()]

    @property
    def oidc_enabled(self) -> bool:
        """Enable OIDC mode — FastMCP proxies OAuth2 to Keycloak and serves well-known endpoints."""
        return os.getenv("CLICKHOUSE_MCP_OIDC_ENABLED", "false").lower() == "true"

    @property
    def oidc_discovery_url(self) -> Optional[str]:
        """Keycloak OIDC discovery URL (openid-configuration endpoint)."""
        return os.getenv("CLICKHOUSE_MCP_OIDC_DISCOVERY_URL")

    @property
    def oidc_client_id(self) -> Optional[str]:
        """Keycloak client ID registered for this MCP server."""
        return os.getenv("CLICKHOUSE_MCP_OIDC_CLIENT_ID")

    @property
    def oidc_client_secret(self) -> Optional[str]:
        """Keycloak client secret for this MCP server."""
        return os.getenv("CLICKHOUSE_MCP_OIDC_CLIENT_SECRET")

    @property
    def oidc_scopes(self) -> list[str]:
        """Scopes forced on the upstream Keycloak authorize request (empty = default)."""
        raw = os.getenv("CLICKHOUSE_MCP_OIDC_SCOPES", "")
        return [s for s in raw.replace(",", " ").split() if s]

    @property
    def base_url(self) -> Optional[str]:
        """Public base URL of this MCP server (required for OIDC mode)."""
        return os.getenv("CLICKHOUSE_MCP_BASE_URL")


_MCP_CONFIG_INSTANCE = None


def get_mcp_config() -> MCPServerConfig:
    """Gets the singleton instance of MCPServerConfig."""
    global _MCP_CONFIG_INSTANCE
    if _MCP_CONFIG_INSTANCE is None:
        _MCP_CONFIG_INSTANCE = MCPServerConfig()
    return _MCP_CONFIG_INSTANCE
