import sys

import rich_click as click
from fastmcp.server.server import Transport
from loguru import logger

from tenrec import __version__
from tenrec.options import PostGroup, docs_options, plugin_options, run_options
from tenrec.utils import console


@click.group(cls=PostGroup, name="tenrec")
@click.version_option(__version__, prog_name="tenrec")
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
    from tenrec.config import Config  # noqa: PLC0415

    config = Config.load_config()
    if len(config.plugins) == 0:
        logger.warning("No plugins found!")
        logger.warning('To get started, add a plugin with "[green]tenrec plugins add[/]".')
        return

    for name, plugin in config.plugins.items():
        console.print(
            f"[cyan bold]{plugin.dist_name}[/] - [green]{name}=={plugin.plugin.version}[/] [dim]({plugin.plugin.__doc__})[/]"
        )


@plugin_manager.command("add")
@plugin_options(required=True)
def add_plugin(plugin: tuple) -> None:
    """Add a new plugin."""
    from tenrec.config import Config  # noqa: PLC0415

    plugin = list(plugin)
    if len(plugin) == 0:
        logger.error("No plugin paths provided!")
        return

    config = Config.load_config()
    added = config.add_plugins(plugin)
    if added == 0:
        logger.warning("No new plugins were added to the config.")
        return
    config.save_config()
    logger.success("Added {} plugin(s) added successfully!", added)


@plugin_manager.command("remove")
@click.option(
    "--dist",
    "-d",
    type=str,
    multiple=True,
    required=True,
    help="Plugin dist(s) to remove from the configuration",
)
def remove_plugin(dist: tuple) -> None:
    """Remove an existing plugin."""
    from tenrec.config import Config  # noqa: PLC0415

    dist = list(dist)

    if len(dist) == 0:
        logger.error("No plugin paths provided!")
        return

    config = Config.load_config()
    removed = config.remove_plugins(dist)
    if removed == 0:
        logger.warning("No matching plugins found to remove!")
        return
    config.save_config()


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
        loaded, _ = load_plugins(plugin)
        logger.debug("Loaded plugins: ")
        for p in loaded.values():
            plugins.append(p.plugin)
            logger.debug("  [dim]{}[/]", p.path)
    if not no_default_plugins:
        logger.debug("Loading default plugins")
        plugins.extend(DEFAULT_PLUGINS)
    if not no_config:
        config_data = Config.load_config()
        if len(config_data.plugins) == 0:
            logger.warning("No plugins found in the config.")
        else:
            logger.debug("Getting config plugins")
            for p in config_data.plugins.values():
                plugins.append(p.plugin)
                logger.debug("  [dim]{}:{}[/]", p.dist_name, p.ep_name)
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
    plugins, load_failures = load_plugins(plugin_path)
    if len(plugins) == 0:
        logger.error("No plugins found to document!")
        return

    logger.debug("Found {} plugins", len(plugins))
    logger.debug("Loaded plugins: ")

    plugin_instances = []
    for p in plugins.values():
        plugin_instances.append(p.plugin)
        logger.debug("  [dim]{}:{}[/]", p.dist_name, p.ep_name)

    logger.info("Generating documentation")

    server = Server(plugins=plugin_instances)
    doc = DocumentationGenerator(
        server,
        name=name,
        readme=readme,
        directory=output,
        repo=repo,
        base_path=base_path,
    )
    doc.build_docs()
