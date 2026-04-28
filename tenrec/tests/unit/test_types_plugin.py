"""Unit tests for the new type-application operations in TypesPlugin."""

from unittest.mock import Mock

import pytest

from tenrec.plugins.models.exceptions import OperationError
from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.types import TypesPlugin


class TestTypesPluginApply:
    """Test suite for the apply/get operations added in 1.x."""

    @pytest.fixture
    def plugin(self, mock_ida_database) -> TypesPlugin:
        plugin = TypesPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def tif(self) -> Mock:
        t = Mock()
        t._print = Mock(return_value="MyStruct;")
        t.dstr = Mock(return_value="MyStruct")
        return t

    @pytest.mark.unit
    def test_apply_at_resolves_type_then_applies(self, plugin, tif):
        plugin.database.types.get_by_name.return_value = tif
        plugin.database.types.apply_at.return_value = True

        result = plugin.apply_at(HexEA(0x401000), "MyStruct")

        plugin.database.types.get_by_name.assert_called_once_with("MyStruct")
        plugin.database.types.apply_at.assert_called_once_with(tif, 0x401000)
        assert result is True

    @pytest.mark.unit
    def test_apply_at_raises_when_type_missing(self, plugin):
        plugin.database.types.get_by_name.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.apply_at(HexEA(0x401000), "Missing")

        assert "Type 'Missing' not found" in str(exc.value)
        plugin.database.types.apply_at.assert_not_called()

    @pytest.mark.unit
    def test_apply_declaration_at_passes_through(self, plugin):
        plugin.database.types.apply_declaration_at.return_value = True

        result = plugin.apply_declaration_at(HexEA(0x401000), "int __fastcall foo(int)")

        plugin.database.types.apply_declaration_at.assert_called_once_with(0x401000, "int __fastcall foo(int)")
        assert result is True

    @pytest.mark.unit
    def test_get_at_returns_decl_string(self, plugin, tif):
        plugin.database.types.get_at.return_value = tif

        result = plugin.get_at(HexEA(0x401000))

        plugin.database.types.get_at.assert_called_once_with(0x401000)
        assert result == "MyStruct;"

    @pytest.mark.unit
    def test_get_at_raises_when_no_type(self, plugin):
        plugin.database.types.get_at.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.get_at(HexEA(0x401000))

        assert "No type information at address: 0x401000" in str(exc.value)

    @pytest.mark.unit
    def test_get_by_name_returns_decl_string(self, plugin, tif):
        plugin.database.types.get_by_name.return_value = tif

        result = plugin.get_by_name("MyStruct")

        plugin.database.types.get_by_name.assert_called_once_with("MyStruct")
        assert result == "MyStruct;"

    @pytest.mark.unit
    def test_get_by_name_raises_when_missing(self, plugin):
        plugin.database.types.get_by_name.return_value = None

        with pytest.raises(OperationError) as exc:
            plugin.get_by_name("Missing")

        assert "Type 'Missing' not found" in str(exc.value)

    @pytest.mark.unit
    def test_get_at_falls_back_to_dstr_when_print_returns_empty(self, plugin):
        tif = Mock()
        tif._print.return_value = ""
        tif.dstr.return_value = "fallback_repr"
        plugin.database.types.get_at.return_value = tif

        result = plugin.get_at(HexEA(0x401000))

        assert result == "fallback_repr"
