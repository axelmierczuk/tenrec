import re

from tenrec.plugins.models import (
    HexEA,
    ImportData,
    ImportModuleData,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


class ImportsPlugin(PluginBase):
    """Plugin to enumerate and inspect imported functions and modules (DLLs/shared libraries)."""

    name = "imports"
    version = "1.0.0"
    instructions = Instructions(
        purpose=(
            "Enumerate imported symbols (DLL/shared library functions) and their host modules. Use to map "
            "external API usage, identify libraries the binary depends on, and locate import-table entries."
        ),
        interaction_style=[
            "Use module!symbol qualified names (e.g., 'kernel32.dll!CreateFileW') with `imports_get_by_name`",
            "Prefer `imports_get_for_module` over filtering all imports when targeting a single DLL",
            "Imports are read-only metadata; this plugin does not modify the database",
        ],
        examples=[
            "List every imported symbol: `imports_get_all()`",
            "List imported modules (DLLs): `imports_get_modules()`",
            'Find an import by qualified name: `imports_get_by_name("kernel32.dll!CreateFileW")`',
            'List imports from a specific module: `imports_get_for_module("ws2_32.dll")`',
            'Filter imports with regex: `imports_get_all_filtered(".*Crypt.*")`',
        ],
        anti_examples=[
            (
                "DON'T pass an unqualified symbol (e.g., 'CreateFileW') to `imports_get_by_name` - "
                "it requires module!symbol"
            ),
            "DON'T assume an import has a name - ordinal-only imports return name=None",
        ],
    )

    @operation(options=[PaginatedParameter()])
    def get_all(self) -> list[ImportData]:
        """Get every imported symbol across all modules.

        :return: List of ImportData objects with address, name, ordinal, and host module.
        """
        return [ImportData.from_ida(imp) for imp in self.database.imports.get_all_imports()]

    @operation(options=[PaginatedParameter()])
    def get_all_filtered(self, search: str) -> list[ImportData]:
        """Get imports whose qualified name matches a regex pattern.

        Matches against `module!name` (or `module!#ordinal` for ordinal-only imports).

        :param search: Regular expression pattern to match against qualified import names.
        :return: List of ImportData objects whose qualified name matches.
        """
        result = []
        for imp in self.database.imports.get_all_imports():
            qualified = f"{imp.module_name}!{imp.name}" if imp.name else f"{imp.module_name}!#{imp.ordinal}"
            if re.search(search, qualified):
                result.append(ImportData.from_ida(imp))
        return result

    @operation(options=[PaginatedParameter()])
    def get_modules(self) -> list[ImportModuleData]:
        """Get every imported module (DLL / shared library).

        :return: List of ImportModuleData objects with module index and name.
        """
        return [ImportModuleData.from_ida(m) for m in self.database.imports.get_all_modules()]

    @operation()
    def get_at(self, address: HexEA) -> ImportData:
        """Get the import entry at a specific address (typically an IAT slot).

        :param address: Linear address of the import (e.g., an entry in the IAT).
        :return: ImportData for the import at this address.
        :raises OperationException: If no import exists at the address.
        """
        info = self.database.imports.get_import_at(address.ea_t)
        if info is None:
            msg = f"No import found at address: {address}"
            raise OperationError(msg)
        return ImportData.from_ida(info)

    @operation()
    def get_by_name(self, qualified_name: str) -> ImportData:
        """Find an import by its fully-qualified name (case-insensitive).

        :param qualified_name: Name in 'module!symbol' format (e.g., 'kernel32.dll!CreateFileW')
            or 'module!#ordinal' format.
        :return: ImportData for the matching import.
        :raises OperationException: If no import with this qualified name exists.
        """
        info = self.database.imports.get_import_by_name(qualified_name)
        if info is None:
            msg = f"No import found with name: {qualified_name}"
            raise OperationError(msg)
        return ImportData.from_ida(info)

    @operation(options=[PaginatedParameter()])
    def get_for_module(self, module_name: str) -> list[ImportData]:
        """Get every import sourced from a specific module (case-insensitive name match).

        :param module_name: Name of the module (e.g., 'kernel32.dll').
        :return: List of ImportData objects belonging to the named module.
        :raises OperationException: If no module with this name is imported.
        """
        module = self.database.imports.get_module_by_name(module_name)
        if module is None:
            msg = f"No imported module found with name: {module_name}"
            raise OperationError(msg)
        return [ImportData.from_ida(imp) for imp in self.database.imports.get_imports_for_module(module.index)]

    @operation()
    def get_module_count(self) -> int:
        """Get the total number of imported modules.

        :return: Number of distinct modules the binary imports from.
        """
        return self.database.imports.get_module_count()

    @operation()
    def get_count(self) -> int:
        """Get the total number of imported symbols across all modules.

        :return: Total import count.
        """
        return self.database.imports.get_import_count()


plugin = ImportsPlugin()
