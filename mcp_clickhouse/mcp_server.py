import logging
import json
from typing import Optional, List, Any, Dict
import concurrent.futures
import atexit
import os
import re
import uuid
from contextvars import ContextVar

import clickhouse_connect
from clickhouse_connect.driver.binding import format_query_value
from dotenv import load_dotenv
from fastmcp import FastMCP
from cachetools import TTLCache
from fastmcp.tools import Tool
from fastmcp.prompts import Prompt
from fastmcp.exceptions import ToolError
from dataclasses import dataclass, field, asdict, is_dataclass
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from mcp_clickhouse.mcp_env import get_config, get_chdb_config, get_mcp_config, TransportType
from mcp_clickhouse.chdb_prompt import CHDB_PROMPT
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier, JWTVerifier
from fastmcp.server.auth.oidc_proxy import OIDCProxy, OIDCConfiguration
from fastmcp.server.auth.auth import RemoteAuthProvider, AccessToken

# FastMCP remembers consent approvals in a 1-year cookie holding one entry per
# approved client_id:redirect_uri and never prunes it. Clients that re-register on
# every login (new client_id, new loopback port) grow it until the consent redirect
# response overflows the ingress proxy buffer and the browser gets a 502.
MAX_APPROVED_CLIENTS = 20

_approving_client_key: ContextVar[Optional[str]] = ContextVar(
    "approving_client_key", default=None
)


# The subclass below relies on private FastMCP hooks; fail loudly at import if a
# FastMCP upgrade renames them instead of silently going back to an unbounded cookie.
for _hook in ("_submit_consent", "_encode_list_cookie", "_make_client_key"):
    if not hasattr(OIDCProxy, _hook):
        raise ImportError(f"fastmcp OIDCProxy no longer has {_hook}; update BoundedConsentOIDCProxy")


class BoundedConsentOIDCProxy(OIDCProxy):
    """OIDCProxy that caps the remembered-consent cookie at MAX_APPROVED_CLIENTS.

    The client being approved is always kept. FastMCP sorts the list before encoding,
    so when the cap is exceeded the lowest-sorting other entries survive and the rest
    are dropped; this is not LRU. A dropped client only sees the consent page again.
    The denied-clients cookie goes through the same cap.
    """

    async def _submit_consent(self, request: Request):
        form = await request.form()
        txn_model = await self._transaction_store.get(key=str(form.get("txn_id", "")))
        if txn_model is None:
            return await super()._submit_consent(request)
        txn = txn_model.model_dump()
        token = _approving_client_key.set(
            self._make_client_key(txn["client_id"], txn["client_redirect_uri"])
        )
        try:
            return await super()._submit_consent(request)
        finally:
            _approving_client_key.reset(token)

    def _encode_list_cookie(self, values: List[str]) -> str:
        if len(values) > MAX_APPROVED_CLIENTS:
            approving = _approving_client_key.get()
            keep_approving = approving in values
            kept = [v for v in values if v != approving]
            kept = kept[: MAX_APPROVED_CLIENTS - int(keep_approving)]
            values = kept + [approving] if keep_approving else kept
        return super()._encode_list_cookie(values)


# chdb is an optional dependency (~600 MB embedded ClickHouse binary).
# It is imported lazily below when CHDB_ENABLED=true.
chs = None


@dataclass
class Column:
    database: str
    table: str
    name: str
    column_type: str
    default_kind: Optional[str]
    default_expression: Optional[str]
    comment: Optional[str]


@dataclass
class Table:
    database: str
    name: str
    engine: str
    create_table_query: str
    dependencies_database: str
    dependencies_table: str
    engine_full: str
    sorting_key: str
    primary_key: str
    total_rows: int
    total_bytes: int
    total_bytes_uncompressed: int
    parts: int
    active_parts: int
    total_marks: int
    comment: Optional[str] = None
    columns: List[Column] = field(default_factory=list)


MCP_SERVER_NAME = "mcp-clickhouse"

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(MCP_SERVER_NAME)

QUERY_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=10)
atexit.register(lambda: QUERY_EXECUTOR.shutdown(wait=True))

load_dotenv()

# Configure authentication for HTTP/SSE transports
auth_provider = None
mcp_config = get_mcp_config()
http_transports = [TransportType.HTTP.value, TransportType.SSE.value]

if mcp_config.server_transport in http_transports:
    if mcp_config.oidc_enabled:
        # OIDC mode: FastMCP acts as an OAuth2 proxy to Keycloak.
        # Serves /.well-known/oauth-authorization-server so MCP clients (e.g. Claude Code)
        # can discover the auth server and complete the OAuth2 PKCE flow.
        # Group membership is validated at token-exchange time via GroupAwareJWTVerifier.
        if not all([mcp_config.oidc_discovery_url, mcp_config.oidc_client_id,
                    mcp_config.oidc_client_secret, mcp_config.base_url]):
            raise ValueError(
                "OIDC mode requires CLICKHOUSE_MCP_OIDC_DISCOVERY_URL, "
                "CLICKHOUSE_MCP_OIDC_CLIENT_ID, CLICKHOUSE_MCP_OIDC_CLIENT_SECRET, "
                "and CLICKHOUSE_MCP_BASE_URL to be set."
            )

        class GroupAwareJWTVerifier(JWTVerifier):
            """JWTVerifier that additionally validates Keycloak group membership.

            Keycloak includes group membership in the 'groups' claim as a list of
            strings, optionally prefixed with '/'. A token is rejected if the user
            is not a member of at least one of the configured allowed groups.
            """

            def __init__(self, *args, allowed_groups: list[str], **kwargs):
                super().__init__(*args, **kwargs)
                self._allowed_groups = frozenset(allowed_groups)

            async def load_access_token(self, token: str) -> AccessToken | None:
                access_token = await super().load_access_token(token)
                if access_token is None:
                    return None
                if not self._allowed_groups:
                    return access_token  # No group restriction configured
                # Keycloak 'groups' claim: ["GroupName"] or ["/GroupName"]
                raw_groups = access_token.claims.get("groups", [])
                user_groups = {g.lstrip("/") for g in raw_groups}
                if not user_groups & self._allowed_groups:
                    logger.warning(
                        "OIDC token rejected: user groups %s not in allowed groups %s",
                        user_groups,
                        self._allowed_groups,
                    )
                    return None
                return access_token

        oidc_config = OIDCConfiguration.get_oidc_configuration(
            mcp_config.oidc_discovery_url,  # type: ignore[arg-type]
            strict=None,
            timeout_seconds=30,
        )
        token_verifier = GroupAwareJWTVerifier(
            jwks_uri=str(oidc_config.jwks_uri),
            issuer=str(oidc_config.issuer),
            allowed_groups=mcp_config.allowed_groups,
        )
        auth_provider = BoundedConsentOIDCProxy(
            config_url=mcp_config.oidc_discovery_url,  # type: ignore[arg-type]
            client_id=mcp_config.oidc_client_id,  # type: ignore[arg-type]
            client_secret=mcp_config.oidc_client_secret,  # type: ignore[arg-type]
            base_url=mcp_config.base_url,  # type: ignore[arg-type]
            token_verifier=token_verifier,
            # Disable CIMD (Client-Initiated Metadata Discovery) — the server cannot
            # reach https://claude.ai to fetch Claude Code's client metadata.
            # Instead, pre-approve localhost redirect URIs so Claude Code can complete
            # the PKCE flow without dynamic registration.
            enable_cimd=False,
            allowed_client_redirect_uris=["http://localhost:*", "http://127.0.0.1:*"],
        )
        logger.info(
            "OIDC authentication enabled. Discovery URL: %s, Allowed groups: %s",
            mcp_config.oidc_discovery_url,
            mcp_config.allowed_groups,
        )
    elif mcp_config.oauth_proxy_enabled:
        logger.info(
            "OAuth proxy authentication enabled. Auth delegated to nginx ingress. "
            "Allowed groups: %s",
            mcp_config.allowed_groups,
        )
        # No StaticTokenVerifier — nginx ingress oauth2-proxy handles Keycloak auth.
        # Group membership is enforced by OAuthProxyGroupMiddleware below.
    elif mcp_config.auth_disabled:
        logger.warning("WARNING: MCP SERVER AUTHENTICATION IS DISABLED")
        logger.warning("Only use this for local development/testing.")
        logger.warning("DO NOT expose to networks.")
    elif mcp_config.auth_token:
        auth_provider = StaticTokenVerifier(
            tokens={mcp_config.auth_token: {"client_id": "mcp-client", "scopes": []}},
            required_scopes=[],
        )
        logger.info("Authentication enabled for HTTP/SSE transport")
    else:
        # No token configured and auth not disabled
        raise ValueError(
            "Authentication token required for HTTP/SSE transports. "
            "Set CLICKHOUSE_MCP_AUTH_TOKEN environment variable or set "
            "CLICKHOUSE_MCP_AUTH_DISABLED=true (for development only)."
        )

mcp = FastMCP(name=MCP_SERVER_NAME, auth=auth_provider)


def _make_oauth_proxy_middleware(allowed_groups: list[str]):
    """Return a middleware class with allowed_groups captured in a closure.

    FastMCP.add_middleware() does not forward kwargs to the middleware constructor,
    so we bake the groups into the class at creation time.
    """
    _groups = frozenset(allowed_groups)

    class OAuthProxyGroupMiddleware(BaseHTTPMiddleware):
        """Validates Keycloak group membership forwarded by the nginx ingress oauth2-proxy.

        The oauth2-proxy sets X-Auth-Request-Groups to a comma-separated list of
        Keycloak groups the authenticated user belongs to. Requests are rejected with
        401/403 unless the user is a member of at least one configured allowed group.
        The /health path is exempted so Kubernetes liveness/readiness probes always pass.
        """

        async def dispatch(self, request: Request, call_next):
            # Exempt health endpoint so Kubernetes probes are never blocked
            if request.url.path == "/health":
                return await call_next(request)

            groups_header = request.headers.get("X-Auth-Request-Groups", "")
            if not groups_header:
                return Response("Unauthorized: missing X-Auth-Request-Groups header", status_code=401)

            user_groups = {g.strip() for g in groups_header.split(",") if g.strip()}
            if not user_groups & _groups:
                return Response(
                    f"Forbidden: not in allowed groups {sorted(_groups)}",
                    status_code=403,
                )
            return await call_next(request)

    return OAuthProxyGroupMiddleware


if mcp_config.oauth_proxy_enabled:
    if mcp_config.allowed_groups:
        mcp.add_middleware(_make_oauth_proxy_middleware(mcp_config.allowed_groups))
    else:
        logger.warning(
            "OAuth proxy mode enabled but CLICKHOUSE_MCP_ALLOWED_GROUPS is not set. "
            "All authenticated users will have access."
        )


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> PlainTextResponse:
    """Health check endpoint for monitoring server status.

    Returns OK if the server is running and can connect to ClickHouse.
    """
    if auth_provider is not None:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return PlainTextResponse("Unauthorized", status_code=401)

        token = auth_header[7:]
        access_token = await auth_provider.verify_token(token)
        if access_token is None:
            return PlainTextResponse("Unauthorized", status_code=401)

    try:
        # Check if ClickHouse is enabled by trying to create config
        # If ClickHouse is disabled, this will succeed but connection will fail
        clickhouse_enabled = os.getenv("CLICKHOUSE_ENABLED", "true").lower() == "true"

        if not clickhouse_enabled:
            # If ClickHouse is disabled, check chDB status
            chdb_config = get_chdb_config()
            if chdb_config.enabled:
                return PlainTextResponse("OK - MCP server running with chDB enabled")
            else:
                # Both ClickHouse and chDB are disabled - this is an error
                return PlainTextResponse(
                    "ERROR - Both ClickHouse and chDB are disabled. At least one must be enabled.",
                    status_code=503,
                )

        # Try to create a client connection to verify ClickHouse connectivity
        client = create_clickhouse_client()
        version = client.server_version
        return PlainTextResponse(f"OK - Connected to ClickHouse {version}")
    except Exception as e:
        # Return 503 Service Unavailable if we can't connect to ClickHouse
        return PlainTextResponse(f"ERROR - Cannot connect to ClickHouse: {str(e)}", status_code=503)


def result_to_table(query_columns, result) -> List[Table]:
    return [Table(**dict(zip(query_columns, row))) for row in result]


def result_to_column(query_columns, result) -> List[Column]:
    return [Column(**dict(zip(query_columns, row))) for row in result]


def to_json(obj: Any) -> str:
    if is_dataclass(obj):
        return json.dumps(asdict(obj), default=to_json)
    elif isinstance(obj, list):
        return [to_json(item) for item in obj]
    elif isinstance(obj, dict):
        return {key: to_json(value) for key, value in obj.items()}
    return obj


def list_databases():
    """List available ClickHouse databases"""
    logger.info("Listing all databases")
    client = create_clickhouse_client()
    result = client.command("SHOW DATABASES")

    # Convert newline-separated string to list and trim whitespace
    if isinstance(result, str):
        databases = [db.strip() for db in result.strip().split("\n")]
    else:
        databases = [result]

    logger.info(f"Found {len(databases)} databases")
    return json.dumps(databases)


# Store pagination state for list_tables with 1-hour expiry
# Using TTLCache from cachetools to automatically expire entries after 1 hour
table_pagination_cache: TTLCache = TTLCache(maxsize=100, ttl=3600)  # 3600 seconds = 1 hour


def fetch_table_names_from_system(
    client,
    database: str,
    like: Optional[str] = None,
    not_like: Optional[str] = None,
) -> List[str]:
    """Get list of table names from system.tables.

    Args:
        client: ClickHouse client
        database: Database name
        like: Optional pattern to filter table names (LIKE)
        not_like: Optional pattern to filter out table names (NOT LIKE)

    Returns:
        List of table names
    """
    query = f"SELECT name FROM system.tables WHERE database = {format_query_value(database)}"
    if like:
        query += f" AND name LIKE {format_query_value(like)}"

    if not_like:
        query += f" AND name NOT LIKE {format_query_value(not_like)}"

    result = client.query(query)
    table_names = [row[0] for row in result.result_rows]
    return table_names


def get_paginated_table_data(
    client,
    database: str,
    table_names: List[str],
    start_idx: int,
    page_size: int,
    include_detailed_columns: bool = True,
) -> tuple[List[Table], int, bool]:
    """Get detailed information for a page of tables.

    Args:
        client: ClickHouse client
        database: Database name
        table_names: List of all table names to paginate
        start_idx: Starting index for pagination
        page_size: Number of tables per page
        include_detailed_columns: Whether to include detailed column metadata (default: True)

    Returns:
        Tuple of (list of Table objects, end index, has more pages)
    """
    end_idx = min(start_idx + page_size, len(table_names))
    current_page_table_names = table_names[start_idx:end_idx]

    if not current_page_table_names:
        return [], end_idx, False

    query = f"""
        SELECT database, name, engine, create_table_query, dependencies_database,
               dependencies_table, engine_full, sorting_key, primary_key, total_rows,
               total_bytes, total_bytes_uncompressed, parts, active_parts, total_marks, comment
        FROM system.tables
        WHERE database = {format_query_value(database)}
        AND name IN ({", ".join(format_query_value(name) for name in current_page_table_names)})
    """

    result = client.query(query)
    tables = result_to_table(result.column_names, result.result_rows)

    if include_detailed_columns:
        for table in tables:
            column_data_query = f"""
                SELECT database, table, name, type AS column_type, default_kind, default_expression, comment
                FROM system.columns
                WHERE database = {format_query_value(database)}
                AND table = {format_query_value(table.name)}
            """
            column_data_query_result = client.query(column_data_query)
            table.columns = result_to_column(
                column_data_query_result.column_names,
                column_data_query_result.result_rows,
            )
    else:
        for table in tables:
            table.columns = []

    return tables, end_idx, end_idx < len(table_names)


def create_page_token(
    database: str,
    like: Optional[str],
    not_like: Optional[str],
    table_names: List[str],
    end_idx: int,
    include_detailed_columns: bool,
) -> str:
    """Create a new page token and store it in the cache.

    Args:
        database: Database name
        like: LIKE pattern used to filter tables
        not_like: NOT LIKE pattern used to filter tables
        table_names: List of all table names
        end_idx: Index to start from for the next page
        include_detailed_columns: Whether to include detailed column metadata

    Returns:
        New page token
    """
    token = str(uuid.uuid4())
    table_pagination_cache[token] = {
        "database": database,
        "like": like,
        "not_like": not_like,
        "table_names": table_names,
        "start_idx": end_idx,
        "include_detailed_columns": include_detailed_columns,
    }
    return token


def list_tables(
    database: str,
    like: Optional[str] = None,
    not_like: Optional[str] = None,
    page_token: Optional[str] = None,
    page_size: int = 50,
    include_detailed_columns: bool = True,
) -> Dict[str, Any]:
    """List available ClickHouse tables in a database, including schema, comment,
    row count, and column count.

    Args:
        database: The database to list tables from
        like: Optional LIKE pattern to filter table names
        not_like: Optional NOT LIKE pattern to exclude table names
        page_token: Token for pagination, obtained from a previous call
        page_size: Number of tables to return per page (default: 50)
        include_detailed_columns: Whether to include detailed column metadata (default: True).
            When False, the columns array will be empty but create_table_query still contains
            all column information. This reduces payload size for large schemas.

    Returns:
        A dictionary containing:
        - tables: List of table information (as dictionaries)
        - next_page_token: Token for the next page, or None if no more pages
        - total_tables: Total number of tables matching the filters
    """
    logger.info(
        "Listing tables in database '%s' with like=%s, not_like=%s, "
        "page_token=%s, page_size=%s, include_detailed_columns=%s",
        database,
        like,
        not_like,
        page_token,
        page_size,
        include_detailed_columns,
    )
    client = create_clickhouse_client()

    if page_token and page_token in table_pagination_cache:
        cached_state = table_pagination_cache[page_token]
        cached_include_detailed = cached_state.get("include_detailed_columns", True)

        if (
            cached_state["database"] != database
            or cached_state["like"] != like
            or cached_state["not_like"] != not_like
            or cached_include_detailed != include_detailed_columns
        ):
            logger.warning(
                "Page token %s is for a different database, filter, or metadata setting. "
                "Ignoring token and starting from beginning.",
                page_token,
            )
            page_token = None
        else:
            table_names = cached_state["table_names"]
            start_idx = cached_state["start_idx"]

            tables, end_idx, has_more = get_paginated_table_data(
                client,
                database,
                table_names,
                start_idx,
                page_size,
                include_detailed_columns,
            )

            next_page_token = None
            if has_more:
                next_page_token = create_page_token(
                    database, like, not_like, table_names, end_idx, include_detailed_columns
                )

            del table_pagination_cache[page_token]

            logger.info(
                "Returned page with %s tables (total: %s), next_page_token=%s",
                len(tables),
                len(table_names),
                next_page_token,
            )
            return {
                "tables": [asdict(table) for table in tables],
                "next_page_token": next_page_token,
                "total_tables": len(table_names),
            }

    table_names = fetch_table_names_from_system(client, database, like, not_like)

    start_idx = 0
    tables, end_idx, has_more = get_paginated_table_data(
        client,
        database,
        table_names,
        start_idx,
        page_size,
        include_detailed_columns,
    )

    next_page_token = None
    if has_more:
        next_page_token = create_page_token(
            database, like, not_like, table_names, end_idx, include_detailed_columns
        )

    logger.info(
        "Found %s tables, returning %s with next_page_token=%s",
        len(table_names),
        len(tables),
        next_page_token,
    )

    return {
        "tables": [asdict(table) for table in tables],
        "next_page_token": next_page_token,
        "total_tables": len(table_names),
    }


def _validate_query_for_destructive_ops(query: str) -> None:
    """Validate that destructive operations (DROP, TRUNCATE) are allowed.

    Args:
        query: The SQL query to validate

    Raises:
        ToolError: If the query contains destructive operations but CLICKHOUSE_ALLOW_DROP is not set
    """
    config = get_config()

    # If writes are not enabled, skip this check (readonly mode will catch it anyway)
    if not config.allow_write_access:
        return

    # If DROP is explicitly allowed, no validation needed
    if config.allow_drop:
        return

    # Simple pattern matching for destructive operations
    destructive_pattern = r'\b(DROP\s+(\S+\s+)*(TABLE|DATABASE|VIEW|DICTIONARY)|TRUNCATE\s+TABLE)\b'
    if re.search(destructive_pattern, query, re.IGNORECASE):
        raise ToolError(
            "Destructive operations (DROP, TRUNCATE) are not allowed. "
            "Set CLICKHOUSE_ALLOW_DROP=true to enable these operations. "
            "This is a safety feature to prevent accidental data deletion."
        )


def execute_query(query: str):
    client = create_clickhouse_client()
    try:
        _validate_query_for_destructive_ops(query)

        query_settings = build_query_settings(client)
        res = client.query(query, settings=query_settings)
        logger.info(f"Query returned {len(res.result_rows)} rows")
        return {"columns": res.column_names, "rows": res.result_rows}
    except ToolError:
        raise
    except Exception as err:
        logger.error(f"Error executing query: {err}")
        raise ToolError(f"Query execution failed: {str(err)}")


def run_query(query: str):
    """Execute a SQL query against ClickHouse.

    Queries run in read-only mode by default. Set CLICKHOUSE_ALLOW_WRITE_ACCESS=true
    to allow DDL and DML statements when your ClickHouse server permits them.
    """
    logger.info(f"Executing query: {query}")
    try:
        future = QUERY_EXECUTOR.submit(execute_query, query)
        try:
            timeout_secs = get_mcp_config().query_timeout
            result = future.result(timeout=timeout_secs)
            # Check if we received an error structure from execute_query
            if isinstance(result, dict) and "error" in result:
                logger.warning(f"Query failed: {result['error']}")
                # MCP requires structured responses; string error messages can cause
                # serialization issues leading to BrokenResourceError
                return {
                    "status": "error",
                    "message": f"Query failed: {result['error']}",
                }
            return result
        except concurrent.futures.TimeoutError:
            logger.warning(f"Query timed out after {timeout_secs} seconds: {query}")
            future.cancel()
            raise ToolError(f"Query timed out after {timeout_secs} seconds")
    except ToolError:
        raise
    except Exception as e:
        logger.error("Unexpected error in run_query: %s", str(e))
        raise RuntimeError(f"Unexpected error during query execution: {str(e)}")


def create_clickhouse_client():
    client_config = get_config().get_client_config()
    logger.info(
        f"Creating ClickHouse client connection to {client_config['host']}:{client_config['port']} "
        f"as {client_config['username']} "
        f"(secure={client_config['secure']}, verify={client_config['verify']}, "
        f"connect_timeout={client_config['connect_timeout']}s, "
        f"send_receive_timeout={client_config['send_receive_timeout']}s)"
    )

    try:
        client = clickhouse_connect.get_client(**client_config)
        # Test the connection
        version = client.server_version
        logger.info(f"Successfully connected to ClickHouse server version {version}")
        return client
    except Exception as e:
        logger.error(f"Failed to connect to ClickHouse: {str(e)}")
        raise


def build_query_settings(client) -> dict[str, str]:
    """Build query settings dict for ClickHouse queries.

    Always returns a dict (possibly empty) to ensure consistent behavior.
    """
    readonly_setting = get_readonly_setting(client)
    if readonly_setting is not None:
        return {"readonly": readonly_setting}
    return {}


def get_readonly_setting(client) -> Optional[str]:
    """Determine the readonly setting value for queries.

    This implements the following logic:
    1. If CLICKHOUSE_ALLOW_WRITE_ACCESS=true (writes enabled):
       - Allow writes if server permits (server readonly=None or "0")
       - Fall back to server's readonly setting if server enforces it
       - Log a warning when falling back

    2. If CLICKHOUSE_ALLOW_WRITE_ACCESS=false (default, read-only mode):
       - Enforce readonly=1 if server allows writes
       - Respect server's readonly setting if server enforces stricter mode

    Returns:
        "0" = writes allowed
        "1" = read-only mode (allows SET of non-privileged settings)
        "2" = strict read-only (server enforced; disallows SET)
        None = use server default (shouldn't happen in practice)
    """
    config = get_config()
    server_settings = getattr(client, "server_settings", {}) or {}
    server_readonly = _normalize_readonly_value(server_settings.get("readonly"))

    # Case 1: User wants write access (CLICKHOUSE_ALLOW_WRITE_ACCESS=true)
    if config.allow_write_access:
        if server_readonly in (None, "0"):
            logger.info("Write mode enabled (CLICKHOUSE_ALLOW_WRITE_ACCESS=true)")
            return "0"

        # If server forbids writes, respect server configuration
        logger.warning(
            "CLICKHOUSE_ALLOW_WRITE_ACCESS=true but server enforces readonly=%s; "
            "write operations will fail",
            server_readonly,
        )
        return server_readonly

    # Case 2: User wants read-only mode (CLICKHOUSE_ALLOW_WRITE_ACCESS=false, default)
    if server_readonly in (None, "0"):
        return "1"  # Enforce read-only since server allows writes

    return server_readonly  # Server already enforces readonly, respect it


def _normalize_readonly_value(value: Any) -> Optional[str]:
    """Normalize ClickHouse readonly setting to a simple string.

    The clickhouse_connect library represents settings as objects with a .value attribute.
    This function extracts the actual value for our logic.

    Args:
        value: The readonly setting value from ClickHouse server. Can be:
            - None (server has no readonly restriction)
            - A clickhouse_connect setting object with a .value attribute
            - An int (0, 1, 2)
            - A str ("0", "1", "2")

    Returns:
        Optional[str]: Normalized readonly value as string ("0", "1", "2") or None
    """
    if value is None:
        return None

    # Extract value from clickhouse_connect setting object
    if hasattr(value, "value"):
        value = value.value

    return str(value)


def create_chdb_client():
    """Create a chDB client connection."""
    if not get_chdb_config().enabled:
        raise ValueError("chDB is not enabled. Set CHDB_ENABLED=true to enable it.")
    return _chdb_client


def execute_chdb_query(query: str):
    """Execute a query using chDB client."""
    client = create_chdb_client()
    try:
        res = client.query(query, "JSON")
        if res.has_error():
            error_msg = res.error_message()
            logger.error(f"Error executing chDB query: {error_msg}")
            return {"error": error_msg}

        result_data = res.data()
        if not result_data:
            return []

        result_json = json.loads(result_data)

        return result_json.get("data", [])

    except Exception as err:
        logger.error(f"Error executing chDB query: {err}")
        return {"error": str(err)}


def run_chdb_select_query(query: str):
    """Run SQL in chDB, an in-process ClickHouse engine"""
    logger.info(f"Executing chDB SELECT query: {query}")
    try:
        future = QUERY_EXECUTOR.submit(execute_chdb_query, query)
        try:
            timeout_secs = get_mcp_config().query_timeout
            result = future.result(timeout=timeout_secs)
            # Check if we received an error structure from execute_chdb_query
            if isinstance(result, dict) and "error" in result:
                logger.warning(f"chDB query failed: {result['error']}")
                return {
                    "status": "error",
                    "message": f"chDB query failed: {result['error']}",
                }
            return result
        except concurrent.futures.TimeoutError:
            logger.warning(
                f"chDB query timed out after {timeout_secs} seconds: {query}"
            )
            future.cancel()
            return {
                "status": "error",
                "message": f"chDB query timed out after {timeout_secs} seconds",
            }
    except Exception as e:
        logger.error(f"Unexpected error in run_chdb_select_query: {e}")
        return {"status": "error", "message": f"Unexpected error: {e}"}


def chdb_initial_prompt() -> str:
    """This prompt helps users understand how to interact and perform common operations in chDB"""
    return CHDB_PROMPT


def _init_chdb_client():
    """Initialize the global chDB client instance."""
    try:
        if not get_chdb_config().enabled:
            logger.info("chDB is disabled, skipping client initialization")
            return None

        if chs is None:
            logger.error("Cannot initialize chDB client: chdb package is not installed")
            return None

        client_config = get_chdb_config().get_client_config()
        data_path = client_config["data_path"]
        logger.info(f"Creating chDB client with data_path={data_path}")
        client = chs.Session(path=data_path)
        logger.info(f"Successfully connected to chDB with data_path={data_path}")
        return client
    except Exception as e:
        logger.error(f"Failed to initialize chDB client: {e}")
        return None


# Register tools based on configuration
if os.getenv("CLICKHOUSE_ENABLED", "true").lower() == "true":
    mcp.add_tool(Tool.from_function(list_databases))
    mcp.add_tool(Tool.from_function(list_tables))
    mcp.add_tool(Tool.from_function(
        run_query,
        description=(
            "Execute SQL queries in ClickHouse. Queries run in read-only mode by default. "
            "Set CLICKHOUSE_ALLOW_WRITE_ACCESS=true to allow DDL and DML operations. "
            "Set CLICKHOUSE_ALLOW_DROP=true to additionally allow destructive operations (DROP, TRUNCATE)."
        )
    ))
    logger.info("ClickHouse tools registered")


if os.getenv("CHDB_ENABLED", "false").lower() == "true":
    try:
        import chdb.session as chs
    except ImportError:
        chs = None
        logger.error(
            "CHDB_ENABLED=true but the 'chdb' package is not installed. "
            "Install it with: pip install 'mcp-clickhouse[chdb]'"
        )
    _chdb_client = _init_chdb_client()
    if _chdb_client:
        atexit.register(lambda: _chdb_client.close())

    mcp.add_tool(Tool.from_function(run_chdb_select_query))
    chdb_prompt = Prompt.from_function(
        chdb_initial_prompt,
        name="chdb_initial_prompt",
        description="This prompt helps users understand how to interact and perform common operations in chDB",
    )
    mcp.add_prompt(chdb_prompt)
    logger.info("chDB tools and prompts registered")
