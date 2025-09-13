from ida_domain.strings import StringItem

from tenrec.plugins.models import Instructions, PaginatedParameter, PluginBase, operation


class SamplePluginA(PluginBase):
    """A sample plugin that demonstrates the structure and capabilities of a Tenrec plugin."""

    name = "plugin_a"
    version = "1.0.0"
    instructions = Instructions(
        purpose="This plugin serves as a template for creating new plugins.",
        interaction_style=[
            "Use clear and concise commands.",
            "Ensure all operations are safe and reversible.",
            "Provide meaningful feedback for each action.",
        ],
        examples=[
            "Example 1: `sample_operation(param1, param2)` - Performs a sample operation.",
            "Example 2: `get_all_strings()` - Gets all the strings from the database.",
        ],
        anti_examples=[],
    )

    @operation()
    def sample_operation(self, param1: int, param2: str) -> str:
        """A sample operation that demonstrates the plugin structure.

        :param param1: An integer parameter.
        :param param2: A string parameter.
        :return: A string message indicating the operation was successful.
        """
        return f"Sample operation executed with param1={param1} and param2='{param2}'"

    @operation(options=[PaginatedParameter(default_offset=0, default_limit=200)])
    def get_all_strings(self) -> list[StringItem]:
        """Retrieve a list of all strings in the database.

        :return: A list of strings.
        """
        return list(self.database.strings.get_all())


plugin = SamplePluginA()
