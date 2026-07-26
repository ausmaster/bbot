from importlib import import_module
from types import ModuleType
from typing import Any, Literal

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.errors import BBOTError
from bbot.modules.base import BaseModule
from onyxweb import AsyncClient, OnyxwebError, OnyxwebDownloadError


def _load_onyxweb_client_presets() -> dict[str, dict[str, Any]]:
    """Loads all the onyxweb presets dynamically."""
    try:
        from onyxweb.presets import __all__ as engines
    except ImportError:
        raise BBOTError("onyxweb client presets missing, ensure onyxweb is correctly installed.")

    preset_mods: dict[str, ModuleType] = {}
    for engine in engines:
        engine_preset_modules: list[str]
        engine_mod = import_module(f"onyxweb.presets.{engine}")
        if not (engine_preset_modules := getattr(engine_mod, "__all__", None)):  # type: ignore
            raise BBOTError("onyxweb client presets missing, ensure onyxweb is correctly installed.")

        # For each engine, extract out all the preset modules
        for preset_module in engine_preset_modules:
            path = f"{engine}.{preset_module}"
            preset_mods[path] = import_module(f"onyxweb.presets.{path}")

    bw_presets: dict[str, dict[str, Any]] = {}
    for mod_str, mod in preset_mods.items():
        for var_name, preset in vars(mod).items():
            # Filter out all the regular imports + _INTERNAL stuff
            if var_name.startswith("_") or not var_name.isupper():
                continue
            bw_presets[f"{mod_str}.{var_name}"] = preset

    return bw_presets


onyxweb_PRESETS = _load_onyxweb_client_presets()


class Web(BaseModule):
    __slots__ = ("client", "chrome_path")

    watched_events = ["URL"]
    produced_events = ["HTTP_RESPONSE"]
    flags = ["active", "safe", "web"]
    meta = {
        "description": "Retrieve fully rendered HTML webpages using onyxweb",
        "created_date": "2026-07-09",
        "author": "@ausmaster",
    }
    deps_pip = ["onyxweb"]
    _shuffle_incoming_queue = False
    _batch_size = 100

    class Config(BaseModuleConfig):
        preset: str | None = Field(
            None, description="onyxweb client preset, must be in the form <engine>.<presetmodule>.<PRESET_NAME>"
        )
        engine: Literal["shell", "full"] = Field(
            "shell",
            description="Chromium engine onyxweb uses to navigate to websites, "
            "must be either 'shell' or 'full'. Defaults to 'shell'.",
        )
        bypass_anti_bot: bool = Field(
            False, description="Bypass anti-bot/WAF with special techniques, effective only with 'shell' engine."
        )
        timeout: int | None = Field(None, description="Render timeout (seconds). Defaults to web.http_timeout.")

    async def setup_deps(self):
        from onyxweb import aensure_chrome, find_chrome

        engine: str = self.config.get("engine")  # type: ignore
        ow_in_tool_dir = self.helpers.tools_dir / "onyxweb"
        ow_in_tool_dir.mkdir(exist_ok=True)
        try:
            self.chrome_path = find_chrome(engine=engine, dest=ow_in_tool_dir)
            if not self.chrome_path:
                self.hugeinfo(f"Downloading Chromium {engine}...")
                self.chrome_path = await aensure_chrome(engine=engine, dest=ow_in_tool_dir)
        except OnyxwebDownloadError as e:
            return False, f"Error upon downloading Chromium {engine}: {e}"

        return True

    async def setup(self):
        web_cfg = self.scan.web_config
        preset: str = self.config.get("preset")  # type: ignore
        engine: str = self.config.get("engine")  # type: ignore
        bypass_anti_bot: bool = self.config.get("bypass_anti_bot")  # type: ignore
        navigation_timeout_ms: int = (self.config.get("timeout") or web_cfg.get("http_timeout")) * 1000
        launch_timeout_ms: int = web_cfg.get("http_timeout_infrastructure") * 1000
        ignore_https_errors: bool = not web_cfg.get("ssl_verify_target", False)  # type: ignore

        onyxweb_kwargs = {
            "chrome_path": str(self.chrome_path),
            "bypass_anti_bot": bypass_anti_bot,
            "engine": engine,
            "navigation_timeout_ms": navigation_timeout_ms,
            "launch_timeout_ms": launch_timeout_ms,
            "ignore_https_errors": ignore_https_errors,
        }

        if preset:
            preset_path = f"{engine}.{preset}"
            if not preset_path in onyxweb_PRESETS:
                return False, f"{preset_path} is not a valid onyxweb preset"
            onyxweb_kwargs.update(onyxweb_PRESETS[preset_path])

        self.client = AsyncClient(**onyxweb_kwargs)
        return True

    async def filter_event(self, event):
        if event.http_status not in (200, 403, 429, 503):
            return False, f"Non-worth status code: {event.http_status}"

        return True

    async def handle_batch(self, *events):
        urls = [x.data["url"] for x in events]
        results = await self.client.batch(urls)

        for index, result in enumerate(results):
            if isinstance(result, OnyxwebError):
                self.log.warning(f"Onyxweb error fetching {result.url}: {str(result)}")
                continue
            if isinstance(result, TimeoutError):
                self.log.warning(f"Onyxweb timeout fetching {result.url}")
                continue
            final_url = result.final_url
            body_hashes = result.metadata.body_hashes
            header_hashes = result.headers.hashes
            await self.emit_event(
                {
                    "url": final_url,
                    "method": result.metadata.request_method,
                    "status_code": result.status_code,
                    "host": self.helpers.urlparse(final_url).hostname,
                    "raw_header": result.headers.raw,
                    "header": dict(result.headers),
                    "body": str(result),
                    "content_length": result.metadata.content_length,
                    "hash": {
                        "body_md5": body_hashes.md5,
                        "body_mmh3": body_hashes.mmh3,
                        "body_sha256": body_hashes.sha256,
                        "header_md5": header_hashes.md5,
                        "header_mmh3": header_hashes.mmh3,
                        "header_sha256": header_hashes.sha256,
                    },
                    "source": "web",
                },
                "HTTP_RESPONSE",
                parent=events[index],
            )
