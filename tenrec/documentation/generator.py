import shutil
from collections.abc import Callable
from pathlib import Path

from jinja2 import Template

from tenrec.documentation.formatter import Formatter
from tenrec.plugins.models import PluginBase
from tenrec.server import Server


class DocumentationGenerator:
    def __init__(
        self, server: Server, name: str, readme: str | None, directory: str, repo: str, base_path: str
    ) -> None:
        self._directory = Path(directory)
        self.formatter = Formatter()
        self.name = name
        self.readme = readme
        self.server = server
        self.repo = repo
        self.base_path = base_path

    def build_docs(self) -> None:
        self._create_directory()
        tools = self.server.plugin_manager.get_tools()
        self._generate_sidebar(tools)

        for plugin, functions in tools.items():
            content = ["# " + self._title_name(plugin.name)]
            description = plugin.__doc__
            if description:
                content.append(description.strip())
            if hasattr(plugin, "instructions") and plugin.instructions:
                content.append(self.formatter.format_instructions(plugin.instructions))
            else:
                content.append("_No instructions provided by this plugin._")
            content.append("## Tools")
            for function in functions:
                description = self.formatter.describe_callable(function)
                markdown = self.formatter.generate_markdown(description)
                content.append(markdown)
            filename = f"{self._sanitize_plugin_name(plugin.name)}.md"
            filepath = self._directory / "plugins"
            Path.mkdir(filepath, exist_ok=True, parents=True)
            filepath = filepath / filename
            with Path.open(filepath, "w") as f:
                f.write("\n\n".join(content))
        self._copy_static()

    def _copy_static(self) -> None:
        current_file_path = Path(__file__).resolve()
        static_directory = current_file_path.parent / "static"

        static_index = static_directory / "index.html"
        static_readme = static_directory / "README.md"

        output_index = self._directory / "index.html"
        output_readme = self._directory / "README.md"
        output_nojekyll = self._directory / ".nojekyll"

        with static_index.open("r") as f:
            index_template = f.read()
        index = Template(index_template).render(name=self.name, repo=self.repo, base_path=self.base_path)
        with output_index.open("w") as f:
            f.write(index)
        if self.readme:
            readme_path = Path(self.readme)
            if readme_path.exists() and readme_path.is_file():
                shutil.copy(readme_path, output_readme)
        else:
            with static_readme.open("r") as f:
                readme_template = f.read()
            readme = Template(readme_template).render(name=self.name)
            with output_readme.open("w") as f:
                f.write(readme)
        shutil.copytree(static_directory / "_media", self._directory / "_media", dirs_exist_ok=True)
        output_nojekyll.touch(exist_ok=True)

    def _generate_sidebar(self, results: dict[PluginBase, list[Callable]]) -> None:
        sidebar = ["- **Plugins**"]
        for plugin in sorted(results.keys(), key=lambda p: p.name):
            sidebar_name = self._title_name(plugin.name)
            sidebar.append(f"  - [{sidebar_name}](plugins/{self._sanitize_plugin_name(plugin.name)}.md)")
        sidebar_content = "\n".join(sidebar)
        with Path.open(self._directory / "_sidebar.md", "w") as f:
            f.write(sidebar_content)

    def _create_directory(self) -> Path:
        if Path.exists(self._directory):
            for item in self._directory.iterdir():
                if item.is_dir():
                    for subitem in item.iterdir():
                        subitem.unlink()
                    item.rmdir()
                else:
                    item.unlink()
            Path.rmdir(self._directory)
        Path.mkdir(self._directory, parents=True)
        return self._directory

    @staticmethod
    def _title_name(name: str) -> str:
        return name.replace("_", " ").title()

    @staticmethod
    def _sanitize_plugin_name(name: str) -> str:
        return name.lower().replace(" ", "_").replace("-", "_")
