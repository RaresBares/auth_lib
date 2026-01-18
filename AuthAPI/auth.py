from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional, Type

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from . import security


@dataclass(frozen=True)
class TokenUser:
    id: int
    admin: bool
    claims: dict[str, Any]


class _State:
    initialized: bool = False

    bearer: HTTPBearer
    login_url: str
    access_cookie_name: str

    use_db: bool = False
    db_url: Optional[str] = None
    engine: Any = None
    sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None

    user_model: Optional[Type[Any]] = None
    user_id_attr: str = "id"
    admin_attr: str = "admin"


_STATE = _State()


def _require_init() -> None:
    if not _STATE.initialized:
        raise RuntimeError("auth toolbox not initialized: call API.init(...) at startup")


def _require_db() -> None:
    if not _STATE.use_db:
        raise RuntimeError("auth DB disabled (init(..., use_db=True, ...))")
    if _STATE.sessionmaker is None or _STATE.user_model is None:
        raise RuntimeError("auth DB enabled but not configured (missing db_url/user_model)")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _token_from_creds(creds: HTTPAuthorizationCredentials | None) -> str:
    return creds.credentials if creds else ""


def _token_from_cookie(request: Request) -> str:
    try:
        return request.cookies.get(_STATE.access_cookie_name, "") or ""
    except Exception:
        return ""


def _redirect_unauth() -> None:
    raise HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        detail="invalid auth token",
        headers={"Location": _STATE.login_url},
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
    _require_init()
    _require_db()
    SessionLocal = _STATE.sessionmaker
    async with SessionLocal() as session:
        yield session


class API:
    @staticmethod
    def init(
        *,
        # Security config (NO ENV)
        secret_key: str,
        algorithm: str,
        access_minutes: int,
        refresh_days: int,
        bcrypt_rounds: int,
        # HTTP
        login_url: str,
        access_cookie_name: str = "access_token",
        bearer: Optional[HTTPBearer] = None,
        # DB (optional)
        use_db: bool = False,
        db_url: Optional[str] = None,
        user_model: Optional[Type[Any]] = None,
        user_id_attr: str = "id",
        admin_attr: str = "admin",
        engine_kwargs: Optional[dict[str, Any]] = None,
        sessionmaker_kwargs: Optional[dict[str, Any]] = None,
    ) -> None:
        if not login_url:
            raise RuntimeError("API.init: login_url required")

        security.init_security(
            secret_key=secret_key,
            algorithm=algorithm,
            access_minutes=access_minutes,
            refresh_days=refresh_days,
            bcrypt_rounds=bcrypt_rounds,
        )

        _STATE.login_url = login_url
        _STATE.access_cookie_name = access_cookie_name or "access_token"
        _STATE.bearer = bearer or HTTPBearer(auto_error=False)

        _STATE.use_db = bool(use_db)
        _STATE.user_model = user_model
        _STATE.user_id_attr = user_id_attr
        _STATE.admin_attr = admin_attr

        if _STATE.use_db:
            if not db_url:
                raise RuntimeError("API.init: use_db=True requires db_url")
            if user_model is None:
                raise RuntimeError("API.init: use_db=True requires user_model")

            ekw = {"pool_pre_ping": True}
            if engine_kwargs:
                ekw.update(engine_kwargs)

            engine = create_async_engine(db_url, **ekw)

            smkw = {"expire_on_commit": False}
            if sessionmaker_kwargs:
                smkw.update(sessionmaker_kwargs)

            SessionLocal = async_sessionmaker(engine, **smkw)

            _STATE.db_url = db_url
            _STATE.engine = engine
            _STATE.sessionmaker = SessionLocal
        else:
            _STATE.db_url = None
            _STATE.engine = None
            _STATE.sessionmaker = None

        _STATE.initialized = True

    @staticmethod
    async def close() -> None:
        if _STATE.engine is not None:
            await _STATE.engine.dispose()
        _STATE.engine = None
        _STATE.sessionmaker = None


def RequireUser(data: bool = False):
    _require_init()

    if data:
        _require_db()

        async def dependency(
            request: Request,
            creds: HTTPAuthorizationCredentials | None = Depends(_STATE.bearer),
            db: AsyncSession = Depends(_db_session_dep),
        ):
            token = _token_from_creds(creds) or _token_from_cookie(request)

            if not _authenticated(token):
                _redirect_unauth()

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
            _redirect_unauth()

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