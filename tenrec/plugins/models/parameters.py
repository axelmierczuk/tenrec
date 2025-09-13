import inspect
from typing import Any

from pydantic import BaseModel, ConfigDict


class OperationParameterBase:
    name = "base"

    def hook_apply_signature(self, signature: inspect.Signature) -> inspect.Signature:
        """Allows modification of the function signature."""
        raise NotImplementedError

    def hook_apply_annotations(self, annotations: dict) -> dict:
        """Allows modification of the function annotations."""
        raise NotImplementedError

    def hook_pre_call(self, context: dict, *args, **kwargs) -> tuple[tuple, dict]:
        """Allows modification of the function arguments before the call to the operation."""
        raise NotImplementedError

    def hook_post_call(self, context: dict, result: Any) -> Any:
        """Allows modification of the function result after the call to the operation."""
        raise NotImplementedError


class PaginatedParameter(OperationParameterBase):
    name = "paginated"

    def __init__(self, default_offset: int = 0, default_limit: int = 100) -> None:
        self.offset = default_offset
        self.limit = default_limit
        self._params = [
            inspect.Parameter(
                name="offset",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default_offset,
                annotation=int,
            ),
            inspect.Parameter(
                name="limit",
                kind=inspect.Parameter.POSITIONAL_OR_KEYWORD,
                default=default_limit,
                annotation=int,
            ),
        ]

    def hook_apply_signature(self, signature: inspect.Signature) -> inspect.Signature:
        params = list(signature.parameters.values())
        params.extend(self._params)
        return signature.replace(parameters=params)

    def hook_apply_annotations(self, annotations: dict) -> dict:
        ann = dict(annotations)
        ann.update({param.name: param.annotation for param in self._params})
        return ann

    def hook_pre_call(self, context: dict, *args, **kwargs) -> tuple[tuple, dict]:
        context["offset"] = kwargs.pop("offset", self.offset)
        context["limit"] = kwargs.pop("limit", self.limit)
        return args, kwargs

    def hook_post_call(self, context: dict, result: Any) -> Any:
        if not isinstance(result, list):
            return result

        offset = context.get("offset", self.offset)
        limit = context.get("limit", self.limit)

        return {"total": len(result), "offset": offset, "limit": limit, "data": result[offset : offset + limit]}


class ParameterOptions(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    paginated: PaginatedParameter | None = None
