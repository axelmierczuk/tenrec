import inspect
from collections import defaultdict
from collections.abc import Callable, Iterator
from functools import wraps
from typing import Any

from ida_domain import Database
from loguru import logger
from mcp.server import FastMCP

from tenrec.main_thread import MainThreadExecutor
from tenrec.plugins.models import PluginBase
from tenrec.plugins.models.operation import OperationProperties


class PluginManager:
    def __init__(self, plugins: list[PluginBase], db: Database | None = None) -> None:
        self._plugins = plugins
        self._database = db
        self._tools_registered = 0

    @property
    def tools_registered(self) -> int:
        return self._tools_registered

    @property
    def plugins(self) -> list[PluginBase]:
        return self._plugins

    @property
    def instructions(self) -> str:
        results = []
        for plugin in self._plugins:
            results.append(plugin.name + "\n\n" + str(plugin.instructions))
        return "\n\n---\n\n".join(results)

    def set_database(self, db: Database) -> None:
        self._database = db

    def register_plugins(self, mcp: FastMCP) -> None:
        for plugin in self._plugins:
            for tool in self.prepare_plugin_tools(plugin):
                mcp.tool(tool)
                self._tools_registered += 1

    def prepare_plugin_tools(self, plugin: PluginBase) -> Iterator[Callable]:
        for name, fn in inspect.getmembers(plugin.__class__, predicate=inspect.isfunction):
            properties = OperationProperties.get_from_function(fn)
            if properties is None:
                continue
            dispatcher = self._make_plugin_dispatcher(name, fn, properties, plugin)

            # Debug logging!
            formatted_name = f"{plugin.name}_{name}"
            if properties.options:
                loaded_options = ", ".join([x.name for x in properties.options])
                logger.debug(
                    "Registering tool: [red]{}[/] with properties: [yellow]{}[/]",
                    formatted_name,
                    loaded_options,
                )
            else:
                logger.debug("Registering tool: [red]{}[/]  with no properties", formatted_name)
            yield dispatcher

    def _make_plugin_dispatcher(
        self, function_name: str, function: Callable, properties: OperationProperties, plugin: PluginBase
    ) -> Callable:
        @wraps(function)
        def dispatcher(*args: tuple[Any, ...], **kwargs: dict[str, Any]):  # noqa: ANN202
            """Dispatch a call to the plugin function, injecting the database if available.

            Will call multiple hooks from OperationProperties if defined.
                1. hook_pre_call - This is an opportunity to modify args/kwargs before the call.
                2. hook_post_call - This is an opportunity to modify the result before returning it to the model.

            :param args: The positional arguments provided by the model.
            :param kwargs: The keyword arguments provided by the model.
            :return: The result of the function call, possibly modified by hook_post_call.
            """
            from tenrec.server import Server  # noqa: PLC0415

            if not self._database and not isinstance(plugin, Server):
                return {"error": "Session not found"}

            context = {}
            args, kwargs = properties.hook_pre_call(context, *args, **kwargs)

            plugin.database = self._database
            args = (plugin, *args[1:])
            bound = inspect.signature(function).bind(*args, **kwargs)
            bound.apply_defaults()

            def _call():
                return function(*bound.args, **bound.kwargs)

            try:
                # Route IDA API calls to the main thread. FastMCP dispatches
                # sync handlers to a worker thread pool, but IDA requires all
                # API calls to originate from the main thread.
                result = MainThreadExecutor.instance().execute(_call)
                return properties.hook_post_call(context, result)
            except Exception as e:
                return {"exception": type(e).__name__, "value": str(e)}

        # The hook_prepare_tool_definition modifies the signature and annotations to include
        # any parameters defined in the OperationProperties (e.g. PaginatedParameter).
        signature, annotations = properties.hook_prepare_tool_definition(function)
        dispatcher.__original_function__ = function
        dispatcher.__name__ = f"{plugin.name}_{function_name}"
        dispatcher.__signature__ = signature
        dispatcher.__annotations__ = annotations
        dispatcher.__doc__ = function.__doc__
        dispatcher.__unsafe__ = properties.unsafe
        return dispatcher

    def get_tools(self) -> dict[PluginBase, list[Callable]]:
        results = defaultdict(list)
        for plugin in self._plugins:
            for tool in self.prepare_plugin_tools(plugin):
                results[plugin].append(tool)
        return results
