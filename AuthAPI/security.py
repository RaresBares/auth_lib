from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import jwt
from jose.exceptions import JWTError
from passlib.context import CryptContext


@dataclass
class _SecCfg:
    initialized: bool = False
    secret_key: str = ""
    algorithm: str = "HS256"
    access_minutes: int = 15
    refresh_days: int = 14
    bcrypt_rounds: int = 12
    pwd_context: Optional[CryptContext] = None


_CFG = _SecCfg()


def init_security(
    *,
    secret_key: str,
    algorithm: str = "HS256",
    access_minutes: int = 15,
    refresh_days: int = 14,
    bcrypt_rounds: int = 12,
) -> None:
    if not secret_key:
        raise RuntimeError("init_security: secret_key required")

    _CFG.secret_key = secret_key
    _CFG.algorithm = algorithm
    _CFG.access_minutes = int(access_minutes)
    _CFG.refresh_days = int(refresh_days)
    _CFG.bcrypt_rounds = int(bcrypt_rounds)

    _CFG.pwd_context = CryptContext(
        schemes=["bcrypt"],
        deprecated="auto",
        bcrypt__rounds=_CFG.bcrypt_rounds,
    )
    _CFG.initialized = True


def _require_init() -> None:
    if not _CFG.initialized:
        raise RuntimeError("security not initialized: call init_security(...) first")


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _exp_dt(minutes: int | None = None, days: int | None = None) -> datetime:
    base = _now_utc()
    if minutes is not None:
        return base + timedelta(minutes=int(minutes))
    if days is not None:
        return base + timedelta(days=int(days))
    return base


def create_access_token(*, sub: str | int, admin: bool = False, extra: dict[str, Any] | None = None) -> str:
    _require_init()
    claims: dict[str, Any] = {
        "sub": str(sub),
        "admin": bool(admin),
        "exp": _exp_dt(minutes=_CFG.access_minutes),
        "type": "access",
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, _CFG.secret_key, algorithm=_CFG.algorithm)


def create_refresh_token(*, sub: str | int, extra: dict[str, Any] | None = None) -> str:
    _require_init()
    claims: dict[str, Any] = {
        "sub": str(sub),
        "exp": _exp_dt(days=_CFG.refresh_days),
        "type": "refresh",
    }
    if extra:
        claims.update(extra)
    return jwt.encode(claims, _CFG.secret_key, algorithm=_CFG.algorithm)


def decode_token(token: str) -> dict[str, Any]:
    _require_init()
    if not token:
        raise JWTError("empty token")
    return jwt.decode(token, _CFG.secret_key, algorithms=[_CFG.algorithm])


def hash_password(password: str) -> str:
    _require_init()
    if not password:
        raise ValueError("empty password")
    return _CFG.pwd_context.hash(password)  # type: ignore[union-attr]


def verify_password(password: str, hashed_password: str) -> bool:
    _require_init()
    if not password or not hashed_password:
        return False
    return bool(_CFG.pwd_context.verify(password, hashed_password))  # type: ignore[union-attr]