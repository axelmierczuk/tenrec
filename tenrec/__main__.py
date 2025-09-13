import sys

from loguru import logger

from tenrec.environment import EnvironmentVariables, get_environment
from tenrec.utils import console, diable_warnings, disable_print, rich_sink


def configure_logger(env: EnvironmentVariables) -> None:
    logger.remove()
    level = "DEBUG" if env.debug else "INFO"
    logger.add(rich_sink, level=level, backtrace=False, diagnose=False, colorize=True)


def main() -> None:
    # Suppress deprecation warnings from IDA python
    # This is not ideal, but IDA generates a lot of these warnings that we can't do much about.
    diable_warnings()
    # IDA plugins will often print to stdout, which can clutter the output and cause issues with "stdout" transport.
    disable_print()
    # Try to load environment variables first
    try:
        env = get_environment()
    except RuntimeError as e:
        console.print(f"Failed to get environment variables: {e!s}")
        sys.exit(1)
    try:
        configure_logger(env)

        # Importing here to ensure logging is configured first, any import errors are caught
        from tenrec.entrypoint import cli

        cli()
    except Exception as e:
        logger.exception("An error occurred: {}", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
