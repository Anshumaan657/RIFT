"""Database engine, sessions, and readiness helpers."""

from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from rift.settings import Settings, get_settings


def create_engine(settings: Settings) -> AsyncEngine:
    return create_async_engine(settings.database_url.get_secret_value(), pool_pre_ping=True)


def create_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def session_scope(
    factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    async with factory() as session:
        yield session


async def get_session() -> AsyncIterator[AsyncSession]:
    engine = create_engine(get_settings())
    try:
        async for session in session_scope(create_session_factory(engine)):
            yield session
    finally:
        await engine.dispose()


async def database_is_ready(engine: AsyncEngine) -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
