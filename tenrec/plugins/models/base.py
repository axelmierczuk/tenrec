from ida_domain import Database
from pydantic import BaseModel


class Instructions(BaseModel):
    purpose: str
    interaction_style: list[str]
    examples: list[str]
    anti_examples: list[str]

    @staticmethod
    def __list(items: list[str]) -> str:
        return "\n".join(f"- {item}" for item in items)

    def __str__(self) -> str:
        instruction_parts = [
            "# Purpose",
            self.purpose,
            "\n# Interaction Style",
            self.__list(self.interaction_style),
            "\n# Examples",
            self.__list(self.examples),
            "\n# Anti-Examples",
            self.__list(self.anti_examples),
        ]
        return "\n".join(instruction_parts)


class PluginBase:
    database: Database
    name: str
    version: str
    instructions: Instructions

    def __new__(cls, *args: tuple[object, ...], **kwargs: dict[str, object]) -> "PluginBase":
        # Ensure name is snake_case
        if (
            not hasattr(cls, "name")
            or not isinstance(cls.name, str)
            or not cls.name.isidentifier()
            or not cls.name.islower()
        ):
            msg = f"Plugin name must be a valid snake_case identifier, got: {getattr(cls, 'name', None)}"
            raise ValueError(msg)
        # Ensure version is set
        if (
            not hasattr(cls, "version")
            or not isinstance(cls.version, str)
            or not cls.version
            or len(cls.version.split(".")) != 3
        ):
            msg = f"Plugin version must be a non-empty string, got: {getattr(cls, 'version', None)}"
            raise ValueError(msg)
        return super().__new__(cls)
