"""
Unit tests for the NamesPlugin class.
Tests plugin business logic including data transformation, filtering, and error handling.
"""

import pytest
from ida_domain.names import DemangleFlags, SetNameFlags

from tenrec.plugins.models import HexEA, NameData, OperationError
from tenrec.plugins.plugins.names import NamesPlugin


class TestNamesPlugin:
    """Test suite for NamesPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates a NamesPlugin instance with a mock database."""
        plugin = NamesPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_name_data(self):
        """Creates mock name data."""
        return NameData(address=HexEA(0x401000), name="test_function")

    # ========================================================================
    # Test get_all
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_empty(self, plugin):
        """Test get_all when no names exist."""
        plugin.database.names.get_all.return_value = []

        result = plugin.get_all()

        assert result == []
        plugin.database.names.get_all.assert_called_once()

    @pytest.mark.unit
    def test_get_all_multiple(self, plugin):
        """Test get_all with multiple names."""
        name_tuples = [(0x401000, "main"), (0x402000, "sub_402000")]
        plugin.database.names.get_all.return_value = name_tuples

        result = plugin.get_all()

        assert len(result) == 2
        assert all(isinstance(n, NameData) for n in result)
        assert result[0].name == "main"
        assert result[1].name == "sub_402000"

    # ========================================================================
    # Test get_at
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_exists(self, plugin):
        """Test getting a name at a specific address."""
        plugin.database.names.get_at.return_value = "test_function"

        result = plugin.get_at(HexEA(0x401000))

        assert isinstance(result, NameData)
        assert result.name == "test_function"
        plugin.database.names.get_at.assert_called_once_with(0x401000)

    @pytest.mark.unit
    def test_get_at_not_found(self, plugin):
        """Test getting a name when none exists."""
        plugin.database.names.get_at.return_value = None

        with pytest.raises(OperationError, match="No name found"):
            plugin.get_at(HexEA(0x401000))

    # ========================================================================
    # Test get_at_index
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_index(self, plugin):
        """Test getting a name by index."""
        plugin.database.names.get_at_index.return_value = (0x401000, "indexed_name")

        result = plugin.get_at_index(5)

        assert isinstance(result, NameData)
        assert result.name == "indexed_name"
        plugin.database.names.get_at_index.assert_called_once_with(5)

    @pytest.mark.unit
    def test_get_at_index_out_of_bounds(self, plugin):
        """Test getting a name at invalid index."""
        plugin.database.names.get_at_index.return_value = None

        with pytest.raises(OperationError, match="Failed to get name at index"):
            plugin.get_at_index(999)

    # ========================================================================
    # Test set_name
    # ========================================================================

    @pytest.mark.unit
    def test_set_name_success(self, plugin):
        """Test successfully setting a name."""
        plugin.database.names.set_name.return_value = True

        result = plugin.set_name(HexEA(0x401000), "new_function_name")

        assert result is True
        plugin.database.names.set_name.assert_called_once_with(0x401000, "new_function_name", SetNameFlags.NOCHECK)

    @pytest.mark.unit
    def test_set_name_failure(self, plugin):
        """Test failed name setting."""
        plugin.database.names.set_name.return_value = False

        result = plugin.set_name(HexEA(0x401000), "invalid@name")

        assert result is False

    @pytest.mark.unit
    def test_set_name_with_flags(self, plugin):
        """Test setting name with specific flags."""
        plugin.database.names.set_name.return_value = True

        result = plugin.set_name(HexEA(0x401000), "exact_name", SetNameFlags.FORCE)

        assert result is True
        plugin.database.names.set_name.assert_called_once_with(0x401000, "exact_name", SetNameFlags.FORCE)

    # ========================================================================
    # Test delete
    # ========================================================================

    @pytest.mark.unit
    def test_delete_name_success(self, plugin):
        """Test successfully deleting a name."""
        plugin.database.names.delete.return_value = True

        result = plugin.delete(HexEA(0x401000))

        assert result is True
        plugin.database.names.delete.assert_called_once_with(0x401000)

    @pytest.mark.unit
    def test_delete_name_not_found(self, plugin):
        """Test deleting a non-existent name."""
        plugin.database.names.delete.return_value = False

        result = plugin.delete(HexEA(0x401000))

        assert result is False

    # ========================================================================
    # Test get_all_filtered
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_filtered_match(self, plugin):
        """Test getting names by regex pattern."""
        name_tuples = [(0x401000, "test_function_1"), (0x402000, "other_function"), (0x403000, "test_function_2")]
        plugin.database.names.get_all.return_value = name_tuples

        result = plugin.get_all_filtered("^test_")

        assert len(result) == 2
        assert result[0].name == "test_function_1"
        assert result[1].name == "test_function_2"

    @pytest.mark.unit
    def test_get_all_filtered_no_match(self, plugin):
        """Test regex with no matches."""
        plugin.database.names.get_all.return_value = [(0x401000, "function")]

        result = plugin.get_all_filtered("^no_match")

        assert result == []

    # ========================================================================
    # Test get_demangled_name
    # ========================================================================

    @pytest.mark.unit
    def test_get_demangled_name_exists(self, plugin):
        """Test getting a demangled C++ name."""
        plugin.database.names.get_demangled_name.return_value = "std::vector<int>::push_back(int const&)"

        result = plugin.get_demangled_name(HexEA(0x401000), DemangleFlags.NOTYPE)

        assert isinstance(result, NameData)
        assert result.name == "std::vector<int>::push_back(int const&)"
        plugin.database.names.get_demangled_name.assert_called_once_with(0x401000, DemangleFlags.NOTYPE, 0)

    @pytest.mark.unit
    def test_get_demangled_name_not_mangled(self, plugin):
        """Test getting demangled name for non-mangled function."""
        plugin.database.names.get_demangled_name.return_value = None

        with pytest.raises(OperationError, match="No name found at address"):
            plugin.get_demangled_name(HexEA(0x401000), DemangleFlags.NOTYPE)

    # ========================================================================
    # Test get_count
    # ========================================================================

    @pytest.mark.unit
    def test_get_count(self, plugin):
        """Test getting total count of names."""
        plugin.database.names.get_count.return_value = 42

        result = plugin.get_count()

        assert result == 42
        plugin.database.names.get_count.assert_called_once()
