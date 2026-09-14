from __future__ import annotations

import os
from pathlib import Path

from platformdirs import PlatformDirs

from v2rm.constants import APP_NAME, ENV_CACHE_HOME, ENV_CONFIG_HOME, ENV_DATA_HOME, ENV_STATE_HOME

_dirs = PlatformDirs(appname=APP_NAME, appauthor=False)


def _resolve(env_var: str, default: Path) -> Path:
    override = os.environ.get(env_var)
    return Path(override).expanduser() if override else default


def config_dir() -> Path:
    return _resolve(ENV_CONFIG_HOME, Path(_dirs.user_config_dir))


def data_dir() -> Path:
    return _resolve(ENV_DATA_HOME, Path(_dirs.user_data_dir))


def state_dir() -> Path:
    return _resolve(ENV_STATE_HOME, Path(_dirs.user_state_dir))


def cache_dir() -> Path:
    return _resolve(ENV_CACHE_HOME, Path(_dirs.user_cache_dir))


def profiles_file() -> Path:
    return config_dir() / "profiles.json"


def subscriptions_file() -> Path:
    return config_dir() / "subscriptions.json"


def state_file() -> Path:
    return config_dir() / "state.json"


def routes_dir() -> Path:
    return config_dir() / "routes"


def custom_routes_file() -> Path:
    return routes_dir() / "custom.yaml"


def engines_dir() -> Path:
    return data_dir() / "bin"


def engine_dir(engine: str) -> Path:
    return engines_dir() / engine


def engine_current_link(engine: str) -> Path:
    return engine_dir(engine) / "current"


def engine_binary_path(engine: str) -> Path:
    binary_name = "xray" if engine == "xray" else "sing-box"
    return engine_current_link(engine) / binary_name


def run_dir() -> Path:
    return state_dir() / "run"


def logs_dir() -> Path:
    return state_dir() / "logs"


def runtime_config_file() -> Path:
    return run_dir() / "config.json"


def pid_file() -> Path:
    return run_dir() / "engine.pid"


def engine_meta_file() -> Path:
    return run_dir() / "engine.json"


def engine_log_file() -> Path:
    return logs_dir() / "engine.log"


def lock_file() -> Path:
    return state_dir() / "store.lock"


def geo_assets_dir() -> Path:
    return cache_dir() / "assets"


def ensure_dirs() -> None:
    for d in (
        config_dir(),
        routes_dir(),
        data_dir(),
        engines_dir(),
        state_dir(),
        run_dir(),
        logs_dir(),
        cache_dir(),
        geo_assets_dir(),
    ):
        d.mkdir(parents=True, exist_ok=True)
