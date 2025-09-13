import os
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar

import rich_click as click
from loguru import logger


F = TypeVar("F", bound=Callable[..., object])


def plugin_options(required: bool = True) -> Callable[[F], F]:
    def decorator(f: F) -> F:
        f = click.option(
            "--plugin",
            "-p",
            type=str,
            multiple=True,
            required=required,
            help="Plugin path(s) or git repository URL(s) to load the plugin from.",
        )(f)
        return f  # noqa: RET504

    return decorator


def run_options(f: F) -> F:  # noqa: UP047
    f = click.option(
        "--transport",
        "-t",
        type=click.Choice(["stdio", "http", "sse", "streamable-http"], case_sensitive=True),
        default="stdio",
        help="Transport type to use for communication (default: stdio)",
    )(f)
    f = click.option(
        "--no-default-plugins",
        type=bool,
        default=False,
        is_flag=True,
        show_default=True,
        help="If set, default plugins will not be loaded.",
    )(f)
    f = click.option(
        "--no-config",
        type=bool,
        default=False,
        is_flag=True,
        show_default=True,
        help="If set, the configuration file will not be used to load plugins.",
    )(f)
    return f  # noqa: RET504


def docs_options(f: F) -> F:  # noqa: UP047
    f = click.option(
        "--name",
        type=str,
        default="tenrec",
        show_default=True,
        help="Name of the documentation set.",
    )(f)
    f = click.option(
        "--repo",
        type=str,
        required=False,
        help="The URL of the repository for the project.",
    )(f)
    f = click.option(
        "--base-path",
        type=str,
        required=False,
        help="The base path for the URL. ",
    )(f)
    f = click.option(
        "--readme",
        type=click.Path(exists=True, file_okay=True, readable=True, resolve_path=True),
        default=None,
        help="Path to a README file to include in the documentation.",
    )(f)
    f = click.option(
        "--output",
        "-o",
        type=click.Path(file_okay=False, dir_okay=True, writable=True, resolve_path=True),
        default="docs",
        show_default=True,
        help="Output directory for the generated documentation.",
    )(f)
    return f  # noqa: RET504


class PostGroup(click.RichGroup):
    def main(self, *a: tuple[Any, ...], **k: dict[str, Any]) -> None:
        try:
            return super().main(*a, **k)
        except Exception as e:
            logger.exception("An error occurred: {}", e)
        finally:
            # TODO: Find a better way to suppress these warnings
            # This is really annoying, but we have to do this to suppress output from IDA
            # If we don't do this, we get the following output at the end:
            #     <sys>:0: DeprecationWarning: builtin type swigvarlink has no __module__ attribute
            with Path(os.devnull).open("w") as devnull:
                os.dup2(devnull.fileno(), 2)  # stderr
                os.dup2(devnull.fileno(), 1)  # stdout
