# AuthAPI/auth.py
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Type

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from . import security
from .db import init_db, dispose_engine
from .db_models import User


@dataclass(frozen=True)
class TokenUser:
    id: int
    admin: bool
    claims: dict[str, Any]


class _State:
    initialized: bool = False
    bearer: HTTPBearer
    access_cookie_name: str
    use_db: bool = False
    sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None
    user_model: Optional[Type[Any]] = None
    user_id_attr: str = "id"
    admin_attr: str = "admin"


_STATE = _State()


def _req_init() -> None:
    if not _STATE.initialized:
        raise RuntimeError("AuthAPI not initialized: call API.init(...) at startup")


def _req_db() -> None:
    if not _STATE.use_db:
        raise RuntimeError("auth DB disabled (API.init(use_db=True, ...))")
    if _STATE.sessionmaker is None or _STATE.user_model is None:
        raise RuntimeError("auth DB enabled but not configured")


def _token_from_creds(creds: HTTPAuthorizationCredentials | None) -> str:
    return creds.credentials if creds else ""


def _token_from_cookie(request: Request) -> str:
    try:
        return request.cookies.get(_STATE.access_cookie_name, "") or ""
    except Exception:
        return ""


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _unauthorized(detail: str = "unauthorized") -> None:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
    )


def _authenticated(token: str) -> bool:
    if not token:
        return False
    try:
        claims = security.decode_token(token)
    except Exception:
        return False

    exp = claims.get("exp")
    if exp is None:
        return False

    if isinstance(exp, (int, float)):
        exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
    elif isinstance(exp, datetime):
        exp_dt = exp
    else:
        return False

    return exp_dt > _now_utc()


def _claims_or_401(token: str) -> dict[str, Any]:
    try:
        return security.decode_token(token)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")


def _uid_from_claims(claims: dict[str, Any]) -> int:
    sub = claims.get("sub")
    if sub is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid user")
    try:
        return int(sub)
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid user")


async def _db_session_dep() -> AsyncSession:
    _req_init()
    _req_db()
    SessionLocal = _STATE.sessionmaker
    async with SessionLocal() as session:
        yield session


class API:
    @staticmethod
    def init(
        *,
        secret_key: str,
        algorithm: str,
        access_minutes: int,
        refresh_days: int,
        bcrypt_rounds: int,
        access_cookie_name: str = "access_token",
        bearer: Optional[HTTPBearer] = None,
        use_db: bool = True,
        database_url: Optional[str] = None,
        engine_kwargs: Optional[dict[str, Any]] = None,
        session_kwargs: Optional[dict[str, Any]] = None,
        user_model: Type[Any] = User,
        user_id_attr: str = "id",
        admin_attr: str = "admin",
    ) -> None:

        security.init_security(
            secret_key=secret_key,
            algorithm=algorithm,
            access_minutes=access_minutes,
            refresh_days=refresh_days,
            bcrypt_rounds=bcrypt_rounds,
        )

        _STATE.access_cookie_name = access_cookie_name or "access_token"
        _STATE.bearer = bearer or HTTPBearer(auto_error=False)

        _STATE.use_db = bool(use_db)
        _STATE.user_model = user_model
        _STATE.user_id_attr = user_id_attr
        _STATE.admin_attr = admin_attr

        if _STATE.use_db:
            if not database_url:
                raise RuntimeError("API.init: use_db=True requires database_url")
            init_db(database_url=database_url, engine_kwargs=engine_kwargs, session_kwargs=session_kwargs)
            from .db import _SessionLocal as SessionLocal  # type: ignore
            if SessionLocal is None:
                raise RuntimeError("db init failed")
            _STATE.sessionmaker = SessionLocal
        else:
            _STATE.sessionmaker = None

        _STATE.initialized = True

    @staticmethod
    async def close() -> None:
        await dispose_engine()


def RequireUser(data: bool = False):
    _req_init()

    if data:
        _req_db()

        async def dependency(
            request: Request,
            creds: HTTPAuthorizationCredentials | None = Depends(_STATE.bearer),
            db: AsyncSession = Depends(_db_session_dep),
        ):
            token = _token_from_creds(creds) or _token_from_cookie(request)

            if not _authenticated(token):
                _unauthorized("invalid auth token")

            claims = _claims_or_401(token)
            uid = _uid_from_claims(claims)

            model = _STATE.user_model
            id_col = getattr(model, _STATE.user_id_attr)

            obj = await db.scalar(select(model).where(id_col == uid))
            if not obj:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="user not found")

            return obj

        return dependency

    async def dependency(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(_STATE.bearer),
    ) -> TokenUser:
        token = _token_from_creds(creds) or _token_from_cookie(request)

        if not _authenticated(token):
            _unauthorized("invalid auth token")

        claims = _claims_or_401(token)
        uid = _uid_from_claims(claims)

        return TokenUser(
            id=uid,
            admin=bool(claims.get(_STATE.admin_attr)),
            claims=claims,
        )

    return dependency


def RequireAdminUser(data: bool = False):
    async def dependency(user=Depends(RequireUser(data=data))):
        if not getattr(user, _STATE.admin_attr, False):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin required")
        return user

    return dependency