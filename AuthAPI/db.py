# AuthAPI/db.py
from __future__ import annotations

from typing import AsyncGenerator, Optional, Any

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


_engine: Optional[AsyncEngine] = None
_SessionLocal: Optional[async_sessionmaker[AsyncSession]] = None


def init_db(*, database_url: str, engine_kwargs: dict[str, Any] | None = None, session_kwargs: dict[str, Any] | None = None) -> None:
    global _engine, _SessionLocal
    if not database_url:
        raise RuntimeError("init_db: database_url required")

    ekw: dict[str, Any] = {"pool_pre_ping": True}
    if engine_kwargs:
        ekw.update(engine_kwargs)

    _engine = create_async_engine(database_url, **ekw)

    skw: dict[str, Any] = {"expire_on_commit": False}
    if session_kwargs:
        skw.update(session_kwargs)

    _SessionLocal = async_sessionmaker(_engine, **skw)


def get_engine() -> AsyncEngine:
    if _engine is None:
        raise RuntimeError("db not initialized: call init_db(database_url=...)")
    return _engine


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    if _SessionLocal is None:
        raise RuntimeError("db not initialized: call init_db(database_url=...)")
    async with _SessionLocal() as session:
        yield session


async def create_tables() -> None:
    eng = get_engine()
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def dispose_engine() -> None:
    global _engine, _SessionLocal
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _SessionLocal = None