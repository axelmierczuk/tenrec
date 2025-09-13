import inspect
import re
import typing
from collections.abc import Callable
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from tenrec.plugins.models import Instructions


class SectionType(Enum):
    DESCRIPTION = "description"
    ARGS = "Args"
    PARAMETERS = "Parameters"
    RETURNS = "Returns"
    RAISES = "Raises"
    EXAMPLES = "Examples"


class ParameterInfo(BaseModel):
    name: str
    type: str = "Any"
    default: str | None = None
    description: str = ""


class DocstringSection(BaseModel):
    description: str = ""
    parameters: dict[str, str] = Field(default_factory=dict)
    returns: str = ""
    raises: dict[str, str] = Field(default_factory=dict)
    examples: list[str] = Field(default_factory=list)


class FunctionInfo(BaseModel):
    name: str
    signature: str = ""
    docstring: str | None = None
    file: str | None = None
    line_number: int | None = None
    is_async: bool = False
    is_generator: bool = False
    parameters: list[ParameterInfo] = Field(default_factory=list)
    return_type: str = "Any"
    docstring_sections: DocstringSection = Field(default_factory=DocstringSection)


class Formatter:
    def describe_callable(self, func: Callable) -> FunctionInfo:
        """Extract function information for documentation."""
        name = getattr(func, "__name__", "<unnamed>")

        # Basic info
        info = FunctionInfo(
            name=name,
            is_async=inspect.iscoroutinefunction(func),
            is_generator=inspect.isgeneratorfunction(func),
        )

        # File info
        try:
            info.file = inspect.getfile(func)
            info.line_number = inspect.getsourcelines(func)[1]
        except (OSError, TypeError):
            pass

        # Signature and parameters
        try:
            sig = inspect.signature(func)

            # Store signature without return annotation for cleaner formatting
            params_only = str(sig).split(" -> ")[0] if " -> " in str(sig) else str(sig)
            info.signature = f"{name}{params_only}"
            if func.__original_function__:
                info.return_type = self._format_type(inspect.signature(func.__original_function__).return_annotation)
            else:
                info.return_type = self._format_type(sig.return_annotation)

            for param_name, param in sig.parameters.items():
                param_info = ParameterInfo(
                    name=param_name,
                    type=self._format_type(param.annotation),
                    default=str(param.default) if param.default != inspect.Parameter.empty else None,
                )
                info.parameters.append(param_info)
        except (ValueError, TypeError):
            pass

        # Docstring
        info.docstring = inspect.getdoc(func)
        if info.docstring:
            info.docstring_sections = self._parse_docstring(info.docstring)
            self._match_param_descriptions(info)

        return info

    @staticmethod
    def _format_type(annotation: Any) -> str:
        """Format type annotation for display."""
        if annotation == inspect.Signature.empty or annotation is None:
            return "Any"

        # Check for generic types first (list[str], dict[str, int], etc.)
        if hasattr(annotation, "__origin__") or (hasattr(typing, "get_origin") and typing.get_origin(annotation)):
            # This is a generic type, use full string representation
            type_str = str(annotation)
        elif hasattr(annotation, "__name__"):
            # Simple type with name attribute
            return annotation.__name__
        else:
            # Fallback to string representation
            type_str = str(annotation)

        # Clean up type string artifacts
        type_str = (
            type_str.replace("typing.", "")
            .replace("<class '", "")
            .replace("'>", "")
            .replace("<enum '", "")
            .replace("'", "")
        )

        return type_str

    def _parse_docstring(self, docstring: str) -> DocstringSection:
        """Parse docstring into structured sections."""
        if ":param" in docstring or ":return" in docstring:
            return self._parse_sphinx_docstring(docstring)
        return self._parse_google_docstring(docstring)

    def _parse_sphinx_docstring(self, docstring: str) -> DocstringSection:
        """Parse Sphinx-style docstring with :param: and :return: directives."""
        sections = DocstringSection()

        # Extract description (everything before first directive)
        lines = docstring.split("\n")
        description_lines = []
        directive_text = ""

        for line in lines:
            if re.match(r"^\s*:[a-z]+", line):
                directive_text += "\n\t" + line.strip()
            elif not directive_text:
                description_lines.append(line.strip())
            else:
                directive_text += "\n\t - " + line.strip()

        sections.description = "\n".join(description_lines).strip()

        # Parse directives
        param_pattern = r":param\s+(\w+):\s*(.*?)(?=\s*:(?:param|return|raises|type)|$)"
        return_pattern = r":return:\s*(.*?)(?=\s*:(?:param|return|raises|type)|$)"

        # Extract parameters
        for match in re.finditer(param_pattern, directive_text, re.DOTALL):
            param_name = match.group(1)
            param_desc = match.group(2).strip()
            sections.parameters[param_name] = param_desc

        # Extract return
        return_match = re.search(return_pattern, directive_text, re.DOTALL)
        if return_match:
            sections.returns = return_match.group(1).strip()

        return sections

    def _parse_google_docstring(self, docstring: str) -> DocstringSection:
        """Parse Google-style docstring with Args:, Returns: sections."""
        sections = DocstringSection()
        lines = docstring.split("\n")

        current_section = SectionType.DESCRIPTION
        content = []

        for line in lines:
            stripped = line.strip()

            # Check for section headers
            section_found = None
            if stripped.endswith(":"):
                section_name = stripped[:-1]
                for section_type in SectionType:
                    if section_type.value == section_name:
                        section_found = section_type
                        break

            if section_found:
                self._process_section(sections, current_section, content)
                current_section = section_found
                content = []
            else:
                content.append(stripped)

        self._process_section(sections, current_section, content)
        return sections

    def _process_section(self, sections: DocstringSection, section: SectionType, content: list[str]) -> None:
        """Process a docstring section."""
        text = "\n".join(content).strip()

        match section:
            case SectionType.DESCRIPTION:
                sections.description = text
            case SectionType.ARGS | SectionType.PARAMETERS:
                sections.parameters = self._parse_parameter_list(content)
            case SectionType.RETURNS:
                sections.returns = text
            case SectionType.RAISES:
                sections.raises = self._parse_parameter_list(content)
            case SectionType.EXAMPLES:
                sections.examples = content

    @staticmethod
    def _parse_parameter_list(lines: list[str]) -> dict[str, str]:
        """Parse parameter list from Google-style docstring."""
        params = {}
        current_param = None
        desc_lines = []

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for param: description pattern (Google style)
            if ":" in line and not line.startswith(" "):
                if current_param:
                    params[current_param] = " ".join(desc_lines).strip()

                parts = line.split(":", 1)
                current_param = parts[0].strip()
                desc_lines = [parts[1].strip()] if len(parts) > 1 else []
            else:
                desc_lines.append(line)

        if current_param:
            params[current_param] = " ".join(desc_lines).strip()

        return params

    @staticmethod
    def _match_param_descriptions(info: FunctionInfo) -> None:
        """Match parameter descriptions from docstring to parameters."""
        for param in info.parameters:
            if param.name in info.docstring_sections.parameters:
                param.description = info.docstring_sections.parameters[param.name]

    @staticmethod
    def _format_signature_with_wrapping(func_info: FunctionInfo, max_length: int = 80) -> str:
        """Format function signature with line wrapping for long signatures."""
        if func_info.return_type != "Any":
            full_sig = f"{func_info.signature} -> {func_info.return_type}"
        else:
            full_sig = func_info.signature

        # If signature is short enough, return as-is
        if len(full_sig) <= max_length:
            return full_sig

        # Extract function name and parameters
        if "(" not in func_info.signature:
            return full_sig

        func_name = func_info.signature.split("(")[0]

        # Parse parameters for wrapping
        if len(func_info.parameters) == 0:
            return full_sig

        # Build wrapped signature
        lines = [f"{func_name}("]

        for i, param in enumerate(func_info.parameters):
            param_str = f"    {param.name}: {param.type}"
            if param.default:
                param_str += f" = {param.default}"

            # Add comma except for last parameter
            if i < len(func_info.parameters) - 1:
                param_str += ","

            lines.append(param_str)

        # Close and add return type
        if func_info.return_type != "Any":
            lines.append(f") -> {func_info.return_type}")
        else:
            lines.append(")")

        return "\n".join(lines)

    def generate_markdown(self, func_info: FunctionInfo) -> str:
        """Generate IDA domain-style markdown documentation with CSS classes."""
        lines = [f"### {func_info.name}", ""]

        # Function signature with CSS styling
        if func_info.signature:
            formatted_sig = self._format_signature_with_wrapping(func_info)

            # Apply CSS classes to signature parts
            styled_sig = formatted_sig
            if func_info.return_type != "Any":
                styled_sig = styled_sig.replace(f"-> {func_info.return_type}", f"-> {func_info.return_type}")
            lines.append("```function\ndef " + styled_sig + ":\n```")

        # Description
        if func_info.docstring_sections.description:
            lines.extend([func_info.docstring_sections.description, ""])

        # Args section
        if func_info.parameters:
            lines.extend(["**Args:**"])
            for param in func_info.parameters:
                param_line = f"- **<span class='parameter'>{param.name}</span>** (**<span class='return-type'>{param.type}</span>**)"
                if param.description:
                    param_line += f": {param.description}"

                lines.append(param_line)
            lines.append("")

        # Returns section
        if func_info.return_type != "Any" or func_info.docstring_sections.returns:
            lines.extend(["**Returns:**"])
            return_desc = func_info.docstring_sections.returns or ""
            lines.extend([f"- **<span class='return-type'>{func_info.return_type}</span>**: {return_desc}", ""])

        # Raises section
        if func_info.docstring_sections.raises:
            lines.extend(["**Raises:**"])
            for exception, description in func_info.docstring_sections.raises.items():
                lines.append(f"- **{exception}**: {description}")
            lines.append("")

        # Examples
        if func_info.docstring_sections.examples:
            lines.extend(["**Example:**", "```function", *func_info.docstring_sections.examples, "```", ""])

        return "\n".join(lines)

    def generate_plugin_docs(self, plugin_name: str, functions: list[FunctionInfo]) -> str:
        """Generate complete plugin documentation."""
        content = [f"# {plugin_name}", "", f"Functions: {len(functions)}", ""]

        for func in functions:
            content.extend(self.generate_markdown(func).split("\n"))
            content.extend(["---", ""])

        return "\n".join(content)

    @staticmethod
    def format_instructions(instructions: Instructions) -> str:
        result = ""
        if instructions.purpose:
            result = "## Purpose\n"
            result += instructions.purpose
        if instructions.interaction_style:
            result += "\n\n## Interaction Style\n"
            for item in instructions.interaction_style:
                result += f"- {item}\n"
        if instructions.examples:
            result += "\n## Examples\n"
            for item in instructions.examples:
                result += f"- {item}\n"
        if instructions.anti_examples:
            result += "\n## Anti-Examples\n"
            for item in instructions.anti_examples:
                result += f"- {item}\n"
        if result == "":
            return "No instructions provided."
        result += "\n\n"
        return result
