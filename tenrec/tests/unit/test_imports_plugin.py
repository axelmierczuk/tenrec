"""Unit tests for the ImportsPlugin class."""

from unittest.mock import Mock

import pytest

from tenrec.plugins.models.exceptions import OperationError
from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.imports import ImportsPlugin


def _mock_import(address: int, name: str | None, ordinal: int, module_name: str, module_index: int = 0) -> Mock:
    info = Mock()
    info.address = address
    info.name = name
    info.ordinal = ordinal
    info.module_index = module_index
    info.module_name = module_name
    return info


def _mock_module(index: int, name: str) -> Mock:
    info = Mock()
    info.index = index
    info.name = name
    return info


class TestImportsPlugin:
    """Test suite for ImportsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database) -> ImportsPlugin:
        plugin = ImportsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.mark.unit
    def test_get_all_transforms_imports(self, plugin):
        plugin.database.imports.get_all_imports.return_value = [
            _mock_import(0x401000, "CreateFileW", 0, "kernel32.dll"),
            _mock_import(0x401008, None, 42, "kernel32.dll"),
        ]

        result = plugin.get_all()

        assert len(result) == 2
        assert result[0].name == "CreateFileW"
        assert result[0].address == HexEA(0x401000)
        assert result[1].name is None
        assert result[1].ordinal == 42

    @pytest.mark.unit
    def test_get_all_filtered_matches_qualified_name(self, plugin):
        plugin.database.imports.get_all_imports.return_value = [
            _mock_import(0x401000, "CreateFileW", 0, "kernel32.dll"),
            _mock_import(0x401008, "RegOpenKeyW", 0, "advapi32.dll"),
            _mock_import(0x401010, None, 13, "kernel32.dll"),
        ]

        result = plugin.get_all_filtered(r"kernel32\.dll!")

        assert len(result) == 2
        names = [r.name for r in result]
        assert "CreateFileW" in names
        assert None in names

    @pytest.mark.unit
    def test_get_modules_transforms_modules(self, plugin):
        plugin.database.imports.get_all_modules.return_value = [
            _mock_module(0, "kernel32.dll"),
            _mock_module(1, "user32.dll"),
        ]

        result = plugin.get_modules()

        assert len(result) == 2
        assert result[0].name == "kernel32.dll"
        assert result[1].index == 1

    @pytest.mark.unit
    def test_get_at_returns_import(self, plugin):
        plugin.database.imports.get_import_at.return_value = _mock_import(
            0x401000, "CreateFileW", 0, "kernel32.dll"
        )

        result = plugin.get_at(HexEA(0x401000))

        assert result.name == "CreateFileW"
        plugin.database.imports.get_import_at.assert_called_once_with(0x401000)

    @pytest.mark.unit
    def test_get_at_raises_when_missing(self, plugin):
        plugin.database.imports.get_import_at.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.get_at(HexEA(0x401000))

        assert "No import found at address: 0x401000" in str(exc.value)

    @pytest.mark.unit
    def test_get_by_name_returns_import(self, plugin):
        plugin.database.imports.get_import_by_name.return_value = _mock_import(
            0x401000, "CreateFileW", 0, "kernel32.dll"
        )

        result = plugin.get_by_name("kernel32.dll!CreateFileW")

        assert result.name == "CreateFileW"
        plugin.database.imports.get_import_by_name.assert_called_once_with("kernel32.dll!CreateFileW")

    @pytest.mark.unit
    def test_get_by_name_raises_when_missing(self, plugin):
        plugin.database.imports.get_import_by_name.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.get_by_name("kernel32.dll!Nope")

        assert "No import found with name: kernel32.dll!Nope" in str(exc.value)

    @pytest.mark.unit
    def test_get_for_module_resolves_module_then_imports(self, plugin):
        plugin.database.imports.get_module_by_name.return_value = _mock_module(2, "kernel32.dll")
        plugin.database.imports.get_imports_for_module.return_value = [
            _mock_import(0x401000, "CreateFileW", 0, "kernel32.dll", module_index=2),
        ]

        result = plugin.get_for_module("kernel32.dll")

        plugin.database.imports.get_module_by_name.assert_called_once_with("kernel32.dll")
        plugin.database.imports.get_imports_for_module.assert_called_once_with(2)
        assert len(result) == 1
        assert result[0].name == "CreateFileW"

    @pytest.mark.unit
    def test_get_for_module_raises_when_module_missing(self, plugin):
        plugin.database.imports.get_module_by_name.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.get_for_module("missing.dll")

        assert "No imported module found with name: missing.dll" in str(exc.value)
        plugin.database.imports.get_imports_for_module.assert_not_called()

    @pytest.mark.unit
    def test_counts_passthrough(self, plugin):
        plugin.database.imports.get_module_count.return_value = 3
        plugin.database.imports.get_import_count.return_value = 42

        assert plugin.get_module_count() == 3
        assert plugin.get_count() == 42
