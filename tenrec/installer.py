import json
import sys
from collections.abc import Iterator
from enum import Enum
from pathlib import Path

from loguru import logger

from tenrec.environment import get_environment
from tenrec.plugins.models import PluginBase
from tenrec.plugins.plugins import DEFAULT_PLUGINS
from tenrec.server import Server
from tenrec.utils import console


class ConfigTarget(Enum):
    CLINE = "Cline"
    ROO_CODE = "Roo Code"
    KILO_CODE = "Kilo Code"
    CLAUDE = "Claude"
    CURSOR = "Cursor"
    WINDSURF = "Windsurf"
    CLAUDE_CODE = "Claude Code"
    LM_STUDIO = "LM Studio"

    @property
    def path(self) -> Path | None:
        """Return the platform-specific config path for this target."""
        home = Path.home()

        # Pick the platform-specific root prefix
        if sys.platform == "win32":
            code_prefix = home / "AppData" / "Roaming" / "Code" / "User" / "globalStorage"
            claude_prefix = home / "AppData" / "Roaming"
        elif sys.platform == "darwin":
            support = home / "Library" / "Application Support"
            code_prefix = support / "Code" / "User" / "globalStorage"
            claude_prefix = support
        elif sys.platform == "linux":
            code_prefix = home / ".config" / "Code" / "User" / "globalStorage"
            claude_prefix = None  # not supported
        else:
            return None

        mapping = {
            ConfigTarget.CLINE: code_prefix / "saoudrizwan.claude-dev" / "settings" / "cline_mcp_settings.json",
            ConfigTarget.ROO_CODE: code_prefix / "rooveterinaryinc.roo-cline" / "settings" / "mcp_settings.json",
            ConfigTarget.KILO_CODE: code_prefix / "kilocode.kilo-code" / "settings" / "mcp_settings.json",
            ConfigTarget.CLAUDE: claude_prefix / "Claude" / "claude_desktop_config.json" if claude_prefix else None,
            ConfigTarget.CURSOR: home / ".cursor" / "mcp.json",
            ConfigTarget.WINDSURF: home / ".codeium" / "windsurf" / "mcp_config.json",
            ConfigTarget.CLAUDE_CODE: home / ".claude.json",
            ConfigTarget.LM_STUDIO: home / ".lmstudio" / "mcp.json",
        }
        return mapping.get(self)


class Action(Enum):
    INSTALL = "install"
    UNINSTALL = "uninstall"


class Installer:
    MCP_SERVERS = "mcpServers"
    NAME = "tenrec"

    def __init__(self, plugins: list[PluginBase] | None = None) -> None:
        if plugins is None:
            plugins = []
        plugins = DEFAULT_PLUGINS + plugins
        self.server = Server(plugins=plugins)

    def install(self) -> None:
        successful_installs = []
        for target, mcp_config in self._load_mcp_configs():
            if target is None or target.path is None or not target.path.exists():
                logger.warning("Skipping {}: unsupported platform", target.value)
                continue
            if self.MCP_SERVERS not in mcp_config:
                mcp_config[self.MCP_SERVERS] = {}
            mcp_config[self.MCP_SERVERS][self.NAME] = self._generate_config()
            with target.path.open("w", encoding="utf-8") as f:
                json.dump(mcp_config, f, indent=2)
            successful_installs.append(target)

        if not successful_installs:
            logger.warning("No supported MCP clients found to install tenrec into.")
            return
        logger.success("Installation complete! Successfully installed to:")
        for target in successful_installs:
            console.print(f"[cyan]  * {target.value} ([dim]{target.path}[/])")

    def _generate_config(self) -> dict:
        env = get_environment()
        safe_functions = self._get_safe_functions()
        return {
            "command": "uvx",
            "args": ["tenrec", "run"],
            "env": {
                "IDADIR": str(env.ida.absolute()),
            },
            "timeout": 1800,
            "disabled": False,
            "autoApprove": safe_functions,
            "alwaysAllow": safe_functions,
        }

    def _get_safe_functions(self) -> list[str]:
        safe_functions = set()
        for tools in self.server.plugin_manager.get_tools().values():
            for tool in tools:
                is_unsafe = getattr(tool, "__unsafe__", False)
                if is_unsafe:
                    continue
                safe_functions.add(tool.__name__)
        return list(safe_functions)

    def uninstall(self) -> None:
        successful_uninstalls = []
        for target, mcp_config in self._load_mcp_configs():
            if target is None or target.path is None or not target.path.exists():
                logger.warning("Skipping {}: unsupported platform", target.value)
                continue
            if self.MCP_SERVERS not in mcp_config:
                continue
            mcp_servers = mcp_config[self.MCP_SERVERS]
            if self.NAME in mcp_servers:
                del mcp_servers[self.NAME]
                with target.path.open("w", encoding="utf-8") as f:
                    json.dump(mcp_config, f, indent=2)
                successful_uninstalls.append(target)
        if not successful_uninstalls:
            logger.warning("No supported MCP clients found to uninstall tenrec from.")
            return
        logger.success("Uninstallation complete! Successfully uninstalled from:")
        for target in successful_uninstalls:
            console.print(f"[cyan]  * {target.value} ([dim]{target.path}[/])")

    @staticmethod
    def _load_mcp_configs() -> Iterator[tuple[ConfigTarget, dict]]:
        for target in ConfigTarget:
            path = target.path
            if not path.parent.exists():
                logger.warning("Skipping {}: config file not found at {}", target.value, path)
                continue
            if path.exists():
                with path.open("r") as f:
                    yield target, json.load(f)
                    continue
            yield target, {}
