"""Asynchronous orchestration for blacklist checks."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, AsyncExitStack

import aiohttp

from blacklist_checker.checkers import (
    AsyncDnsResolver,
    AsyncHttpSession,
    check_dnsbl,
    check_local_static,
    check_remote_static,
)
from blacklist_checker.models import (
    AppConfig,
    BlacklistSourceConfig,
    CheckFailure,
    CheckResult,
    CheckStatus,
    ErrorKind,
    SourceKind,
    Target,
)

type HttpSessionFactory = Callable[
    [],
    AbstractAsyncContextManager[AsyncHttpSession],
]


def _create_http_session() -> aiohttp.ClientSession:
    return aiohttp.ClientSession()


async def scan(
    target: Target,
    config: AppConfig,
    *,
    resolver: AsyncDnsResolver | None = None,
    http_session_factory: HttpSessionFactory = _create_http_session,
) -> tuple[CheckResult, ...]:
    """Check one validated target against all enabled configured sources."""
    sources = tuple(source for source in config.sources if source.enabled)
    if not sources:
        return ()

    requires_http = any(
        source.kind is SourceKind.HTTP_STATIC and target.type in source.supports
        for source in sources
    )
    if not requires_http:
        return await _run_sources(
            sources,
            target,
            config,
            resolver=resolver,
            http_session=None,
        )

    async with AsyncExitStack() as stack:
        try:
            http_session = await stack.enter_async_context(http_session_factory())
        except asyncio.CancelledError:
            raise
        except Exception:
            http_session = None
        return await _run_sources(
            sources,
            target,
            config,
            resolver=resolver,
            http_session=http_session,
        )


async def _run_sources(
    sources: tuple[BlacklistSourceConfig, ...],
    target: Target,
    config: AppConfig,
    *,
    resolver: AsyncDnsResolver | None,
    http_session: AsyncHttpSession | None,
) -> tuple[CheckResult, ...]:
    results = await asyncio.gather(
        *(
            _run_source_safely(
                source,
                target,
                config,
                resolver=resolver,
                http_session=http_session,
            )
            for source in sources
        )
    )
    return tuple(results)


async def _run_source_safely(
    source: BlacklistSourceConfig,
    target: Target,
    config: AppConfig,
    *,
    resolver: AsyncDnsResolver | None,
    http_session: AsyncHttpSession | None,
) -> CheckResult:
    if target.type not in source.supports:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.SKIPPED,
            reason=f"source does not support {target.type.value} targets",
        )

    try:
        return await _dispatch_source(
            source,
            target,
            config,
            resolver=resolver,
            http_session=http_session,
        )
    except asyncio.CancelledError:
        raise
    except Exception:
        return CheckResult(
            source_name=source.name,
            source_kind=source.kind,
            category=source.category,
            target=target,
            status=CheckStatus.ERROR,
            failure=CheckFailure(
                kind=ErrorKind.UNEXPECTED,
                message="source check failed unexpectedly",
            ),
        )


async def _dispatch_source(
    source: BlacklistSourceConfig,
    target: Target,
    config: AppConfig,
    *,
    resolver: AsyncDnsResolver | None,
    http_session: AsyncHttpSession | None,
) -> CheckResult:
    """Dispatch one source; a semaphore can wrap this boundary later."""
    if source.kind is SourceKind.DNSBL:
        return await check_dnsbl(
            source,
            target,
            default_timeout_seconds=config.dns_timeout_seconds,
            resolver=resolver,
        )
    if source.kind is SourceKind.HTTP_STATIC:
        if http_session is None:
            return CheckResult(
                source_name=source.name,
                source_kind=source.kind,
                category=source.category,
                target=target,
                status=CheckStatus.ERROR,
                failure=CheckFailure(
                    kind=ErrorKind.HTTP_CONNECTION,
                    message="HTTP client session could not be initialized",
                ),
            )
        return await check_remote_static(
            source,
            target,
            session=http_session,
            default_timeout_seconds=config.http_timeout_seconds,
            default_max_static_bytes=config.max_static_bytes,
        )
    if source.kind is SourceKind.LOCAL_STATIC:
        return await check_local_static(
            source,
            target,
            default_max_static_bytes=config.max_static_bytes,
        )
    raise TypeError(f"unsupported source kind: {source.kind}")
