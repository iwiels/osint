"""
WraithOSINT - High-Performance Persistent Cache Layer
Capa de caché de alta concurrencia y persistencia basada en diskcache (SQLite + WAL).
Thread-safe y process-safe con soporte TTL y decorador para colectores sync y async.
"""

from __future__ import annotations

import contextlib
import fnmatch
import functools
import hashlib
import inspect
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import diskcache
from specter import config as specter_config

_cache_instance: diskcache.Cache | None = None
_cache_lock = threading.Lock()
_SENTINEL = object()


def get_cache(directory: str | Path | None = None) -> diskcache.Cache:
    """Devuelve la instancia singleton de diskcache.Cache.

    Thread-safe y process-safe. Si no se especifica directorio, utiliza
    specter.config.cache_dir() (data/cache/ por defecto).
    """
    global _cache_instance
    with _cache_lock:
        if directory is not None:
            target = Path(directory)
            target.mkdir(parents=True, exist_ok=True)
            if _cache_instance is not None:
                if Path(_cache_instance.directory).resolve() != target.resolve():
                    with contextlib.suppress(Exception):
                        _cache_instance.close()
                    _cache_instance = diskcache.Cache(str(target))
            else:
                _cache_instance = diskcache.Cache(str(target))
            return _cache_instance

        if _cache_instance is None:
            target = specter_config.cache_dir()
            target.mkdir(parents=True, exist_ok=True)
            _cache_instance = diskcache.Cache(str(target))
        return _cache_instance


def close_cache() -> None:
    """Cierra la instancia activa de caché y libera descriptores."""
    global _cache_instance
    with _cache_lock:
        if _cache_instance is not None:
            with contextlib.suppress(Exception):
                _cache_instance.close()
            _cache_instance = None


def cache_get(key: str, default: Any = None) -> Any:
    """Recupera un valor de la caché por su clave.

    Si no existe o ha expirado por TTL, retorna default (None por defecto).
    """
    cache = get_cache()
    return cache.get(key, default=default)


def cache_set(key: str, value: Any, ttl: int | float | None = None) -> bool:
    """Almacena un valor en la caché con un tiempo de vida (TTL) opcional en segundos.

    Retorna True tras almacenar exitosamente.
    """
    cache = get_cache()
    cache.set(key, value, expire=ttl)
    return True


def cache_invalidate(pattern: str | None = None) -> int:
    """Invalida entradas en la caché según un patrón fnmatch o prefijo.

    Si pattern es None o "*", purga toda la caché.
    Retorna el número de entradas invalidadas.
    """
    cache = get_cache()
    if pattern is None or pattern == "*":
        count = len(cache)
        cache.clear()
        return count

    count = 0
    keys = list(cache)
    for k in keys:
        k_str = str(k)
        if (fnmatch.fnmatch(k_str, pattern) or k_str.startswith(pattern)) and cache.delete(k):
            count += 1
    return count


def _normalize_arg(arg: Any) -> Any:
    if isinstance(arg, (str, int, float, bool, bytes, type(None))):
        return arg
    if isinstance(arg, (list, tuple)):
        return tuple(_normalize_arg(x) for x in arg)
    if isinstance(arg, (set, frozenset)):
        return tuple(sorted(_normalize_arg(x) for x in arg))
    if isinstance(arg, dict):
        return tuple(sorted((str(k), _normalize_arg(v)) for k, v in arg.items()))
    if hasattr(arg, "model_dump_json"):
        return arg.model_dump_json()
    if hasattr(arg, "name") and isinstance(arg.name, str):
        return f"{arg.__class__.__name__}:{arg.name}"
    r = repr(arg)
    if " at 0x" in r:
        return arg.__class__.__qualname__
    return r


def _build_cache_key(
    func: Callable[..., Any], key_prefix: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> str:
    norm_args = tuple(_normalize_arg(a) for a in args)
    norm_kwargs = tuple(sorted((str(k), _normalize_arg(v)) for k, v in kwargs.items()))
    digest = hashlib.sha256(repr((norm_args, norm_kwargs)).encode("utf-8")).hexdigest()[:24]

    prefix = key_prefix.strip()
    if prefix:
        return f"{prefix}:{func.__name__}:{digest}"
    return f"{func.__module__}.{func.__qualname__}:{digest}"


def osint_cache(
    ttl_seconds: int | float | Callable[..., Any] = 3600,
    key_prefix: str = "",
) -> Any:
    """Decorador para cachear resultados de funciones síncronas o asíncronas de recolección OSINT.

    Uso:
        @osint_cache(ttl_seconds=3600, key_prefix="dns")
        async def collect_dns(domain: str) -> dict: ...

        @osint_cache
        def resolve_sync(ip: str) -> str: ...
    """
    if callable(ttl_seconds):
        func = ttl_seconds
        return _create_cache_wrapper(func, ttl=3600, key_prefix=key_prefix)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        return _create_cache_wrapper(fn, ttl=ttl_seconds, key_prefix=key_prefix)

    return decorator


def _create_cache_wrapper(
    func: Callable[..., Any], ttl: int | float | None, key_prefix: str
) -> Callable[..., Any]:
    if inspect.iscoroutinefunction(func):

        @functools.wraps(func)
        async def async_cached_wrapper(*args: Any, **kwargs: Any) -> Any:
            key = _build_cache_key(func, key_prefix, args, kwargs)
            cache = get_cache()
            val = cache.get(key, default=_SENTINEL)
            if val is not _SENTINEL:
                return val
            result = await func(*args, **kwargs)
            cache.set(key, result, expire=ttl)
            return result

        async_cached_wrapper.__cache_key_builder__ = lambda *a, **kw: _build_cache_key(  # type: ignore[attr-defined]
            func, key_prefix, a, kw
        )
        return async_cached_wrapper
    else:

        @functools.wraps(func)
        def sync_cached_wrapper(*args: Any, **kwargs: Any) -> Any:
            key = _build_cache_key(func, key_prefix, args, kwargs)
            cache = get_cache()
            val = cache.get(key, default=_SENTINEL)
            if val is not _SENTINEL:
                return val
            result = func(*args, **kwargs)
            cache.set(key, result, expire=ttl)
            return result

        sync_cached_wrapper.__cache_key_builder__ = lambda *a, **kw: _build_cache_key(  # type: ignore[attr-defined]
            func, key_prefix, a, kw
        )
        return sync_cached_wrapper
