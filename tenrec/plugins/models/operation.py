import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any

from .parameters import OperationParameterBase


Scalar = None | bool | str | int | float | complex

DefaultPropertyAttribute = "__operation_properties__"


class OperationProperties:
    def __init__(self, options: list[OperationParameterBase] | None = None, unsafe: bool = False) -> None:
        if options is None:
            options = []
        self.options = options
        self.unsafe = unsafe

    def hook_prepare_tool_definition(self, function: Callable) -> tuple[inspect.Signature, dict]:
        func = function.__func__ if inspect.ismethod(function) else function
        signature = inspect.signature(func)
        annotations = dict(getattr(func, "__annotations__", {}))

        for option in self.options:
            if option is None:
                continue
            if not isinstance(option, OperationParameterBase):
                continue
            signature = option.hook_apply_signature(signature)
            annotations = option.hook_apply_annotations(annotations)
        annotations.pop("self", None)
        annotations["return"] = dict
        params = list(signature.parameters.values())[1:]
        signature = inspect.Signature(parameters=params, return_annotation=dict)
        return signature, annotations

    def hook_pre_call(self, context: dict, *args, **kwargs) -> tuple[tuple, dict]:
        for option in self.options:
            if option is None:
                continue
            if not isinstance(option, OperationParameterBase):
                continue
            args, kwargs = option.hook_pre_call(context, *args, **kwargs)
        return args, kwargs

    def hook_post_call(self, context: dict, result: Any) -> Any:
        for option in self.options:
            if option is None:
                continue
            if not isinstance(option, OperationParameterBase):
                continue
            result = option.hook_post_call(context, result)

        if result is None:
            return {"result": "No results found"}
        if isinstance(result, Scalar):
            return {"result": result}
        if isinstance(result, bytes):
            return {"result": result.hex()}
        return result

    @classmethod
    def get_from_function(cls, function: Callable) -> "OperationProperties | None":
        properties = getattr(function, DefaultPropertyAttribute, None)
        if properties and isinstance(properties, OperationProperties):
            return properties
        return None

    def set_to_function(self, function: Callable) -> None:
        setattr(function, DefaultPropertyAttribute, self)


def operation(*, options: list[OperationParameterBase] | None = None, unsafe: bool = False) -> Callable:
    """Operation wrapper, responsible for setting the mcp properties on the function such that the server can prepare the tools correctly.

    :param options: Parameter options for the operation
    :return:
    """
    if options is None:
        options = []

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args: tuple[Any, ...], **kwargs: dict[str, Any]):  # noqa: ANN001, ANN202
            return func(self, *args, **kwargs)

        properties = OperationProperties(options=options, unsafe=unsafe)
        properties.set_to_function(wrapper)
        return wrapper

    return decorator
