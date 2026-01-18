# AuthAPI/security.py
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from jose import jwt
from jose.exceptions import JWTError
from passlib.context import CryptContext


@dataclass
class _SecState:
    initialized: bool = False
    secret_key: str = ""
    algorithm: str = "HS256"
    access_minutes: int = 15
    refresh_days: int = 14
    bcrypt_rounds: int = 12
    pwd: Optional[CryptContext] = None


_STATE = _SecState()


def init_security(*, secret_key: str, algorithm: str, access_minutes: int, refresh_days: int, bcrypt_rounds: int) -> None:
    if not secret_key:
        raise RuntimeError("init_security: secret_key required")
    _STATE.secret_key = secret_key
    _STATE.algorithm = algorithm or "HS256"
    _STATE.access_minutes = int(access_minutes)
    _STATE.refresh_days = int(refresh_days)
    _STATE.bcrypt_rounds = int(bcrypt_rounds)
    _STATE.pwd = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=_STATE.bcrypt_rounds)
    _STATE.initialized = True


def _req() -> None:
    if not _STATE.initialized:
        raise RuntimeError("security not initialized: call init_security(...) first")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256((token or "").encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    _req()
    if not password:
        raise ValueError("empty password")
    return _STATE.pwd.hash(password)  # type: ignore[union-attr]


def verify_password(password: str, hashed_password: str) -> bool:
    _req()
    if not password or not hashed_password:
        return False
    return bool(_STATE.pwd.verify(password, hashed_password))  # type: ignore[union-attr]


def decode_token(token: str) -> dict[str, Any]:
    _req()
    if not token:
        raise JWTError("empty token")
    return jwt.decode(token, _STATE.secret_key, algorithms=[_STATE.algorithm])


def create_access_token(user: Any) -> str:
    _req()
    exp = _now() + timedelta(minutes=_STATE.access_minutes)
    claims: dict[str, Any] = {
        "sub": str(getattr(user, "id")),
        "admin": bool(getattr(user, "admin", False)),
        "typ": "access",
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(claims, _STATE.secret_key, algorithm=_STATE.algorithm)


def create_refresh_token(user: Any) -> tuple[str, str, datetime]:
    _req()
    exp = _now() + timedelta(days=_STATE.refresh_days)
    jti = uuid.uuid4().hex
    claims: dict[str, Any] = {
        "sub": str(getattr(user, "id")),
        "typ": "refresh",
        "jti": jti,
        "exp": int(exp.timestamp()),
    }
    token = jwt.encode(claims, _STATE.secret_key, algorithm=_STATE.algorithm)
    return token, jti, exp