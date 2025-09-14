"""
Unit tests for the FunctionsPlugin class.

These tests verify the plugin's business logic, including:
- HexEA to ea_t conversion
- Exception handling for missing functions
- Filtering logic for regex searches
- FunctionData transformation from func_t objects
- Proper error handling in callees/callers methods
"""

from unittest.mock import Mock, patch

import pytest

from tenrec.plugins.models.exceptions import OperationError
from tenrec.plugins.models.ida import FunctionData, HexEA
from tenrec.plugins.plugins.functions import FunctionsPlugin


class TestFunctionsPlugin:
    """Test suite for FunctionsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates a FunctionsPlugin instance with a mock database."""
        plugin = FunctionsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_func_t(self):
        """Creates a mock func_t object as returned by IDA."""
        func = Mock()
        func.start_ea = 0x401000
        func.end_ea = 0x401050
        func.name = "test_function"
        func.comment = "Test comment"
        func.repeatable_comment = None
        func.is_library = False
        func.is_thunk = False
        func.size = 0x50
        return func

    # ========================================================================
    # Test get_all - Tests plugin's data transformation logic
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_transforms_func_t_to_function_data(self, plugin, mock_func_t):
        """Test that get_all() properly transforms func_t objects to FunctionData."""
        plugin.database.functions.get_all.return_value = [mock_func_t]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_function_data = Mock(spec=FunctionData)
            mock_from_func_t.return_value = mock_function_data

            result = plugin.get_all()

            # Verify transformation was called
            mock_from_func_t.assert_called_once_with(mock_func_t)
            assert result == [mock_function_data]

    @pytest.mark.unit
    def test_get_all_handles_empty_database(self, plugin):
        """Test that get_all() handles empty database correctly."""
        plugin.database.functions.get_all.return_value = []

        result = plugin.get_all()

        assert result == []
        plugin.database.functions.get_all.assert_called_once()

    @pytest.mark.unit
    def test_get_all_processes_multiple_functions(self, plugin):
        """Test that get_all() processes multiple functions correctly."""
        func1 = Mock()
        func1.start_ea = 0x401000
        func2 = Mock()
        func2.start_ea = 0x402000

        plugin.database.functions.get_all.return_value = [func1, func2]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = [
                Mock(spec=FunctionData, name="func1_data"),
                Mock(spec=FunctionData, name="func2_data"),
            ]

            result = plugin.get_all()

            assert len(result) == 2
            assert mock_from_func_t.call_count == 2

    # ========================================================================
    # Test get_all_filtered - Tests plugin's filtering logic
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_filtered_applies_regex_correctly(self, plugin):
        """Test that get_all_filtered() correctly applies regex filtering."""
        func1 = Mock()
        func1.name = "test_function"
        func2 = Mock()
        func2.name = "other_function"
        func3 = Mock()
        func3.name = "test_helper"

        plugin.database.functions.get_all.return_value = [func1, func2, func3]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = lambda f: Mock(spec=FunctionData, name=f.name)

            result = plugin.get_all_filtered("^test_")

            assert len(result) == 2
            assert mock_from_func_t.call_count == 2
            # Verify correct functions were transformed
            calls = mock_from_func_t.call_args_list
            assert calls[0][0][0] == func1
            assert calls[1][0][0] == func3

    @pytest.mark.unit
    def test_get_all_filtered_handles_none_names(self, plugin):
        """Test that get_all_filtered() handles functions with None names."""
        func1 = Mock()
        func1.name = None
        func2 = Mock()
        func2.name = "valid_name"

        plugin.database.functions.get_all.return_value = [func1, func2]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.return_value = Mock(spec=FunctionData)

            result = plugin.get_all_filtered("valid")

            # Only func2 should match
            assert len(result) == 1
            mock_from_func_t.assert_called_once_with(func2)

    @pytest.mark.unit
    def test_get_all_filtered_with_complex_regex(self, plugin):
        """Test get_all_filtered() with complex regex patterns."""
        func1 = Mock()
        func1.name = "sub_401000"
        func2 = Mock()
        func2.name = "sub_402000"
        func3 = Mock()
        func3.name = "main"

        plugin.database.functions.get_all.return_value = [func1, func2, func3]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = lambda f: Mock(spec=FunctionData, name=f.name)

            # Match sub_ followed by hex digits
            result = plugin.get_all_filtered(r"^sub_[0-9a-fA-F]+$")

            assert len(result) == 2

    # ========================================================================
    # Test get_by_name - Tests helper function usage and transformation
    # ========================================================================

    @pytest.mark.unit
    @patch("tenrec.plugins.plugins.functions.get_func_by_name")
    def test_get_by_name_uses_helper_and_transforms(self, mock_get_func, plugin, mock_func_t):
        """Test that get_by_name() uses helper function and transforms result."""
        mock_get_func.return_value = mock_func_t

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_function_data = Mock(spec=FunctionData)
            mock_from_func_t.return_value = mock_function_data

            result = plugin.get_by_name("test_function")

            # Verify helper was called with database and name
            mock_get_func.assert_called_once_with(plugin.database, "test_function")
            # Verify transformation
            mock_from_func_t.assert_called_once_with(mock_func_t)
            assert result == mock_function_data

    @pytest.mark.unit
    @patch("tenrec.plugins.plugins.functions.get_func_by_name")
    def test_get_by_name_propagates_exception(self, mock_get_func, plugin):
        """Test that get_by_name() propagates OperationException from helper."""
        mock_get_func.side_effect = OperationError("Function not found")

        with pytest.raises(OperationError) as exc_info:
            plugin.get_by_name("nonexistent")

        assert "Function not found" in str(exc_info.value)

    # ========================================================================
    # Test get_at - Tests HexEA conversion and exception handling
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_converts_hex_ea_and_transforms(self, plugin, mock_func_t):
        """Test that get_at() converts HexEA to ea_t and transforms result."""
        plugin.database.functions.get_at.return_value = mock_func_t

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_function_data = Mock(spec=FunctionData)
            mock_from_func_t.return_value = mock_function_data

            result = plugin.get_at(HexEA(0x401000))

            # Verify HexEA was converted to ea_t
            plugin.database.functions.get_at.assert_called_once_with(0x401000)
            # Verify transformation
            mock_from_func_t.assert_called_once_with(mock_func_t)
            assert result == mock_function_data

    @pytest.mark.unit
    def test_get_at_raises_exception_when_not_found(self, plugin):
        """Test that get_at() raises OperationException when function not found."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get_at(HexEA(0x401000))

        assert "No function found at address: 0x401000" in str(exc_info.value)

    @pytest.mark.unit
    def test_get_at_with_string_hex_ea(self, plugin, mock_func_t):
        """Test that get_at() handles string HexEA input."""
        plugin.database.functions.get_at.return_value = mock_func_t

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.return_value = Mock(spec=FunctionData)

            plugin.get_at(HexEA("0x401000"))

            plugin.database.functions.get_at.assert_called_once_with(0x401000)

    # ========================================================================
    # Test get_between - Tests address range handling
    # ========================================================================

    @pytest.mark.unit
    def test_get_between_converts_addresses_and_transforms(self, plugin):
        """Test that get_between() converts HexEA addresses and transforms results."""
        func1 = Mock()
        func2 = Mock()
        plugin.database.functions.get_between.return_value = [func1, func2]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = [
                Mock(spec=FunctionData, name="func1"),
                Mock(spec=FunctionData, name="func2"),
            ]

            result = plugin.get_between(HexEA(0x400000), HexEA(0x500000))

            # Verify addresses were converted
            plugin.database.functions.get_between.assert_called_once_with(0x400000, 0x500000)
            # Verify all functions were transformed
            assert len(result) == 2
            assert mock_from_func_t.call_count == 2

    @pytest.mark.unit
    def test_get_between_handles_empty_range(self, plugin):
        """Test that get_between() handles empty range correctly."""
        plugin.database.functions.get_between.return_value = []

        result = plugin.get_between(HexEA(0x600000), HexEA(0x700000))

        assert result == []

    # ========================================================================
    # Test get_callees - Tests exception handling and transformation
    # ========================================================================

    @pytest.mark.unit
    def test_get_callees_checks_function_exists(self, plugin, mock_func_t):
        """Test that get_callees() verifies function exists before getting callees."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get_callees(HexEA(0x401000))

        assert "No function found at address: 0x401000" in str(exc_info.value)
        # Should not try to get callees if function doesn't exist
        plugin.database.functions.get_callees.assert_not_called()

    @pytest.mark.unit
    def test_get_callees_transforms_results(self, plugin, mock_func_t):
        """Test that get_callees() transforms callee functions correctly."""
        callee1 = Mock()
        callee2 = Mock()

        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.get_callees.return_value = [callee1, callee2]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = [
                Mock(spec=FunctionData, name="callee1"),
                Mock(spec=FunctionData, name="callee2"),
            ]

            result = plugin.get_callees(HexEA(0x401000))

            # Verify function was looked up
            plugin.database.functions.get_at.assert_called_once_with(0x401000)
            # Verify callees were retrieved with the resolved function
            plugin.database.functions.get_callees.assert_called_once_with(mock_func_t)
            # Verify transformations
            assert len(result) == 2
            assert mock_from_func_t.call_count == 2

    # ========================================================================
    # Test get_callers - Tests exception handling and transformation
    # ========================================================================

    @pytest.mark.unit
    def test_get_callers_checks_function_exists(self, plugin):
        """Test that get_callers() verifies function exists before getting callers."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get_callers(HexEA(0x401000))

        assert "No function found at address: 0x401000" in str(exc_info.value)
        plugin.database.functions.get_callers.assert_not_called()

    @pytest.mark.unit
    def test_get_callers_transforms_results(self, plugin, mock_func_t):
        """Test that get_callers() transforms caller functions correctly."""
        caller1 = Mock()
        caller2 = Mock()

        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.get_callers.return_value = [caller1, caller2]

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_from_func_t.side_effect = [
                Mock(spec=FunctionData, name="caller1"),
                Mock(spec=FunctionData, name="caller2"),
            ]

            result = plugin.get_callers(HexEA(0x401000))

            assert len(result) == 2
            assert mock_from_func_t.call_count == 2

    # ========================================================================
    # Test get_pseudocode - Tests error handling and data passthrough
    # ========================================================================

    @pytest.mark.unit
    def test_get_pseudocode_checks_function_exists(self, plugin):
        """Test that get_pseudocode() verifies function exists."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get_pseudocode(HexEA(0x401000))

        assert "No function found at address: 0x401000" in str(exc_info.value)

    @pytest.mark.unit
    def test_get_pseudocode_joins_lines(self, plugin, mock_func_t):
        """Test that get_pseudocode() joins lines with newlines."""
        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.get_pseudocode.return_value = ["int test_function() {", "    return 42;", "}"]

        result = plugin.get_pseudocode(HexEA(0x401000))

        assert result == "int test_function() {\n    return 42;\n}"
        plugin.database.functions.get_pseudocode.assert_called_once_with(mock_func_t, True)

    @pytest.mark.unit
    def test_get_pseudocode_passes_remove_tags_parameter(self, plugin, mock_func_t):
        """Test that get_pseudocode() passes remove_tags parameter correctly."""
        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.get_pseudocode.return_value = ["code"]

        plugin.get_pseudocode(HexEA(0x401000), remove_tags=False)

        plugin.database.functions.get_pseudocode.assert_called_once_with(mock_func_t, False)

    # ========================================================================
    # Test get_signature - Tests error handling
    # ========================================================================

    @pytest.mark.unit
    def test_get_signature_checks_function_exists(self, plugin):
        """Test that get_signature() verifies function exists."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get_signature(HexEA(0x401000))

        assert "No function found at address: 0x401000" in str(exc_info.value)

    @pytest.mark.unit
    def test_get_signature_returns_signature(self, plugin, mock_func_t):
        """Test that get_signature() returns the function signature."""
        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.get_signature.return_value = "int test_function(void *arg1, int arg2)"

        result = plugin.get_signature(HexEA(0x401000))

        assert result == "int test_function(void *arg1, int arg2)"
        plugin.database.functions.get_signature.assert_called_once_with(mock_func_t)

    # ========================================================================
    # Test set_name - Tests error handling and parameter passing
    # ========================================================================

    @pytest.mark.unit
    def test_set_name_checks_function_exists(self, plugin):
        """Test that set_name() verifies function exists."""
        plugin.database.functions.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.set_name(HexEA(0x401000), "new_name")

        assert "No function found at address: 0x401000" in str(exc_info.value)

    @pytest.mark.unit
    def test_set_name_passes_parameters_correctly(self, plugin, mock_func_t):
        """Test that set_name() passes all parameters correctly."""
        plugin.database.functions.get_at.return_value = mock_func_t
        plugin.database.functions.set_name.return_value = True

        result = plugin.set_name(HexEA(0x401000), "new_name", auto_correct=False)

        assert result is True
        plugin.database.functions.set_name.assert_called_once_with(mock_func_t, "new_name", False)

    # ========================================================================
    # Test rename_local_variable - Tests error handling and refresh
    # ========================================================================

    @pytest.mark.unit
    @patch("tenrec.plugins.plugins.functions.ida_hexrays.rename_lvar")
    @patch("tenrec.plugins.plugins.functions.refresh_decompiler_ctext")
    def test_rename_local_variable_success(self, mock_refresh, mock_rename_lvar, plugin, mock_func_t):
        """Test successful local variable rename with refresh."""
        plugin.database.functions.get_at.return_value = mock_func_t
        mock_rename_lvar.return_value = True

        result = plugin.rename_local_variable(HexEA(0x401000), "old_var", "new_var")

        # Verify rename was called with start_ea
        mock_rename_lvar.assert_called_once_with(0x401000, "old_var", "new_var")
        # Verify decompiler was refreshed
        mock_refresh.assert_called_once_with(0x401000)
        assert "Renamed variable old_var to new_var" in result

    @pytest.mark.unit
    @patch("tenrec.plugins.plugins.functions.ida_hexrays.rename_lvar")
    def test_rename_local_variable_failure(self, mock_rename_lvar, plugin, mock_func_t):
        """Test that rename_local_variable() raises exception on failure."""
        plugin.database.functions.get_at.return_value = mock_func_t
        mock_rename_lvar.return_value = False

        with pytest.raises(OperationError) as exc_info:
            plugin.rename_local_variable(HexEA(0x401000), "old_var", "new_var")

        assert "Failed to rename local variable: old_var" in str(exc_info.value)
