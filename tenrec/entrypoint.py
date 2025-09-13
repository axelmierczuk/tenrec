import sys

import rich_click as click
from fastmcp.server.server import Transport
from loguru import logger

from tenrec.options import PostGroup, docs_options, plugin_options, run_options
from tenrec.utils import console


@click.group(cls=PostGroup, name="tenrec")
@click.version_option("1.0.0", prog_name="tenrec")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress non-error log messages.")
def cli(quiet: bool) -> None:
    """Tenrec cli utility."""
    if quiet:
        logger.remove()
        logger.add(sys.stderr, level="ERROR", colorize=True)


@cli.command()
def install() -> None:
    """Install tenrec with MCP clients."""
    from tenrec.installer import Installer  # noqa: PLC0415

    installer = Installer()
    installer.install()


@cli.command()
def uninstall() -> None:
    """Uninstall tenrec and MCP clients."""
    from tenrec.installer import Installer  # noqa: PLC0415

    installer = Installer()
    installer.uninstall()


@cli.group("plugins")
def plugin_manager() -> None:
    """Manage tenrec plugins."""


@plugin_manager.command("list")
def list_plugins() -> None:
    """List installed plugins."""
    from tenrec.config import Config, Plugin  # noqa: PLC0415
    from tenrec.plugins.plugin_loader import load_plugins  # noqa: PLC0415

    config = Config.load_config()
    loaded_plugins = load_plugins(config.plugin_paths)

    if len(loaded_plugins) == 0:
        logger.warning("No plugins found!")
        logger.warning('To get started, add a plugin with "[green]tenrec plugins add[/]".')
        return

    load_fails: list[Plugin] = []
    for i, plugin in enumerate(config.plugins):
        if plugin.location not in config.plugin_paths:
            load_fails.append(plugin)
            continue
        console.print(f"[green]{plugin.name} ({plugin.version})[/]")
        console.print(f"  [dim]Description:[/] {plugin.description}")
        console.print(f"  [dim]Location:[/] {plugin.location}", highlight=False)
        if plugin.git:
            console.print(f"  [dim]Repo:[/] {plugin.git}", highlight=False)
    if len(load_fails) == 0:
        return

    logger.error("Could not load plugin(s) at the following locations:")
    missing_locations = []
    for missing in load_fails:
        missing_locations.append(missing.location)
        logger.error("  [dim]{}[/]", missing.location)
    logger.warning("Would you like to remove them from your config? (y/N) ")
    choice = input().lower()
    if choice == "y":
        config.plugins = [f for f in config.plugins if f.location not in missing_locations]
        config.save_config()
        logger.success("Removed missing plugins from config.")
    else:
        logger.info("Fair enough! They'll remain in your config.")


@plugin_manager.command("add")
@plugin_options(required=True)
def add_plugin(plugin: tuple) -> None:
    """Add a new plugin."""
    from tenrec.config import Config, Plugin  # noqa: PLC0415
    from tenrec.plugins.plugin_loader import load_plugins  # noqa: PLC0415

    plugin = list(plugin)
    if len(plugin) == 0:
        logger.error("No plugin paths provided!")
        return
    plugins = load_plugins(plugin)
    if len(plugins) == 0:
        logger.error("No valid plugins found at the provided paths!")
        return
    config = Config.load_config()
    added = 0
    for p in plugins:
        path_str = str(p.path)
        if path_str in config.plugin_paths:
            remove_index = -1
            for i, cp in enumerate(config.plugins):
                if cp.location == path_str:
                    remove_index = i
                    break
            if remove_index != -1:
                logger.warning("Plugin [dim]{}[/] already exists in config, updating entry.", p.plugin.name)
                del config.plugins[remove_index]

        config_plugin = Plugin(
            name=p.plugin.name,
            description=p.plugin.__doc__,
            version=p.plugin.version,
            location=path_str,
            git=p.git,
        )
        logger.success("Adding plugin [dim]{}[/] from file [dim]{}[/]", p.plugin.name, p.path)
        config.plugins.append(config_plugin)
        added += 1

    config.save_config()
    logger.success("Added {} plugin(s) added successfully!", added)


@plugin_manager.command("remove")
@click.option(
    "--name",
    "-n",
    type=str,
    multiple=True,
    required=True,
    help="Plugin name(s) to remove from the configuration",
)
def remove_plugin(name: tuple) -> None:
    """Remove an existing plugin."""
    from tenrec.config import Config  # noqa: PLC0415

    plugin = list(name)

    if len(plugin) == 0:
        logger.error("No plugin paths provided!")
        return

    config = Config.load_config()
    initial = set(config.plugin_paths)
    config.plugins = [f for f in config.plugins if f.name not in plugin]
    removed = initial - set(config.plugin_paths)

    if len(removed) == 0:
        logger.warning("No matching plugins found to remove!")
        return

    for f in removed:
        logger.success("Removed plugin: [dim]{}[/]", f)
    config.save_config()
    logger.success("Plugin(s) removed successfully!")


@cli.command()
@run_options
@plugin_options(required=False)
def run(
    transport: Transport,
    no_default_plugins: bool,
    no_config: bool,
    plugin: tuple,
) -> None:
    """Run the tenrec server."""
    from tenrec.config import Config  # noqa: PLC0415
    from tenrec.plugins.plugin_loader import load_plugins  # noqa: PLC0415
    from tenrec.plugins.plugins import DEFAULT_PLUGINS  # noqa: PLC0415
    from tenrec.server import Server  # noqa: PLC0415

    plugin = list(plugin)

    plugins = []
    custom_plugins = len(plugin) != 0
    if no_config and not custom_plugins and no_default_plugins:
        logger.error("No plugin paths provided and default plugins are disabled.")
        return

    if custom_plugins:
        loaded = load_plugins(plugin)
        plugins = [p.plugin for p in loaded]
        logger.debug("Loaded plugins: ")
        for p in loaded:
            logger.debug("  [dim]{}[/]", p.path)
    if not no_default_plugins:
        logger.debug("Loading default plugins")
        plugins.extend(DEFAULT_PLUGINS)
    if not no_config:
        config_data = Config.load_config()
        if len(config_data.plugin_paths) == 0:
            logger.warning("No plugins found in config to load.")
        else:
            logger.debug("Loading plugins from config")
            loaded = load_plugins(config_data.plugin_paths)
            plugins.extend([p.plugin for p in loaded])
            logger.debug("Loaded plugins: ")
            for p in loaded:
                logger.debug("  [dim]{}[/]", p.path)
    if len(plugins) == 0:
        logger.warning("Weird, no plugins found to run. Continuing anyway...")

    server = Server(transport=transport, plugins=plugins)
    server.run(show_banner=False)


@cli.command()
@docs_options
@plugin_options(required=True)
def docs(name: str, repo: str, readme: str, plugin: tuple, output: str, base_path: str) -> None:
    """Generate documentation."""
    from tenrec.documentation.generator import DocumentationGenerator  # noqa: PLC0415
    from tenrec.plugins.plugin_loader import load_plugins  # noqa: PLC0415
    from tenrec.server import Server  # noqa: PLC0415

    plugin_path = list(plugin)

    logger.debug("Attempting to load plugins from:")
    for p in plugin_path:
        logger.debug("  [dim]{}[/]", p)
    plugins = load_plugins(plugin_path)
    logger.debug("Found {} plugins", len(plugins))
    if len(plugins) == 0:
        logger.error("No plugins found to document!")
        return

    logger.debug("Loaded plugins: ")
    for p in plugins:
        logger.debug("  [dim]{}[/]", p.path)
    logger.info("Generating documentation")
    server = Server(plugins=[p.plugin for p in plugins])
    doc = DocumentationGenerator(
        server,
        name=name,
        readme=readme,
        directory=output,
        repo=repo,
        base_path=base_path,
    )
    doc.build_docs()
