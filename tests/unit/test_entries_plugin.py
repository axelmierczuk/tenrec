"""
Unit tests for the EntriesPlugin class.
Tests plugin business logic including data transformation and error handling.
"""

from unittest.mock import Mock, patch

import pytest
from ida_domain.entries import EntryInfo as IDAEntryInfo

from tenrec.plugins.models import (
    EntryData,
    ForwarderInfo,
    FunctionData,
    HexEA,
    OperationError,
)
from tenrec.plugins.plugins.entries import EntriesPlugin


class TestEntriesPlugin:
    """Test suite for EntriesPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates an EntriesPlugin instance with a mock database."""
        plugin = EntriesPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_ida_entry_info(self):
        """Creates a mock IDA EntryInfo object."""
        entry = Mock(spec=IDAEntryInfo)
        entry.ordinal = 1
        entry.address = 0x401000
        entry.name = "main"
        entry.forwarder_name = None
        return entry

    @pytest.fixture
    def mock_func_t(self):
        """Creates a mock func_t object."""
        func = Mock()
        func.start_ea = 0x401000
        func.end_ea = 0x401100
        func.name = "main"
        func.flags = 0
        return func

    @pytest.fixture
    def mock_function_data(self):
        """Creates a mock FunctionData object."""
        data = Mock(spec=FunctionData)
        data.start_ea = HexEA(0x401000)
        data.end_ea = HexEA(0x401100)
        data.name = "main"
        return data

    @pytest.fixture
    def mock_entry_info(self, mock_function_data):
        """Creates a mock EntryInfo object."""
        entry = Mock(spec=EntryData)
        entry.ordinal = 1
        entry.forwarder_name = None
        entry.function = mock_function_data
        return entry

    # ========================================================================
    # Test add method
    # ========================================================================

    @pytest.mark.unit
    def test_add_converts_hex_ea_and_adds_entry(self, plugin):
        """Test that add() converts HexEA and adds entry point."""
        plugin.database.entries.add.return_value = True

        result = plugin.add(HexEA(0x401000), "custom_entry", ordinal=100, make_code=True)

        plugin.database.entries.add.assert_called_once_with(0x401000, "custom_entry", 100, True)
        assert result is True

    @pytest.mark.unit
    def test_add_with_auto_ordinal(self, plugin):
        """Test add() with automatic ordinal assignment."""
        plugin.database.entries.add.return_value = True

        result = plugin.add(HexEA(0x401000), "entry_point")

        plugin.database.entries.add.assert_called_once_with(0x401000, "entry_point", None, True)
        assert result is True

    # ========================================================================
    # Test exists method
    # ========================================================================

    @pytest.mark.unit
    def test_exists_returns_true_when_entry_exists(self, plugin):
        """Test that exists() returns True when entry exists."""
        plugin.database.entries.exists.return_value = True

        result = plugin.exists(1)

        plugin.database.entries.exists.assert_called_once_with(1)
        assert result is True

    @pytest.mark.unit
    def test_exists_returns_false_when_entry_not_found(self, plugin):
        """Test that exists() returns False when entry doesn't exist."""
        plugin.database.entries.exists.return_value = False

        result = plugin.exists(999)

        assert result is False

    # ========================================================================
    # Test get_addresses method
    # ========================================================================

    @pytest.mark.unit
    def test_get_addresses_returns_entry_addresses(self, plugin):
        """Test that get_addresses() returns list of addresses."""
        plugin.database.entries.get_addresses.return_value = [0x401000, 0x402000, 0x403000]

        result = plugin.get_addresses()

        assert result == [0x401000, 0x402000, 0x403000]
        plugin.database.entries.get_addresses.assert_called_once()

    # ========================================================================
    # Test get_all method
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_transforms_entries_to_entry_info(self, plugin, mock_ida_entry_info, mock_func_t, mock_entry_info):
        """Test that get_all() transforms IDA entries to EntryInfo objects."""
        plugin.database.entries.get_all.return_value = [mock_ida_entry_info]
        plugin.database.functions.get_at.return_value = mock_func_t

        # Mock the create_entry method to return our mock_entry_info
        EntryData.from_ida = Mock(return_value=mock_entry_info)

        result = plugin.get_all()

        EntryData.from_ida.assert_called_once_with(mock_ida_entry_info)
        assert result == [mock_entry_info]

    @pytest.mark.unit
    def test_get_all_skips_failed_transformations(self, plugin):
        """Test that get_all() skips entries that fail transformation."""
        entry1 = Mock(spec=IDAEntryInfo)
        entry2 = Mock(spec=IDAEntryInfo)
        entry3 = Mock(spec=IDAEntryInfo)

        plugin.database.entries.get_all.return_value = [entry1, entry2, entry3]

        # Make the second entry fail
        EntryData.from_ida = Mock(side_effect=[Mock(spec=EntryData), OperationError("Failed"), Mock(spec=EntryData)])

        result = plugin.get_all()

        assert len(result) == 2  # Should skip the failed one

    # ========================================================================
    # Test get_at_index method
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_index_transforms_to_entry_info(self, plugin, mock_ida_entry_info, mock_entry_info):
        """Test that get_at_index() transforms result to EntryInfo."""
        plugin.database.entries.get_at_index.return_value = mock_ida_entry_info
        EntryData.from_ida = Mock(return_value=mock_entry_info)

        result = plugin.get_at_index(0)

        plugin.database.entries.get_at_index.assert_called_once_with(0)
        EntryData.from_ida.assert_called_once_with(mock_ida_entry_info)
        assert result == mock_entry_info

    @pytest.mark.unit
    def test_get_at_index_raises_when_invalid_index(self, plugin):
        """Test that get_at_index() raises when index is invalid."""
        plugin.database.entries.get_at_index.return_value = None
        EntryData.from_ida = Mock(side_effect=OperationError("Entry not found"))

        with pytest.raises(OperationError, match="Entry not found"):
            plugin.get_at_index(999)

    # ========================================================================
    # Test get_by_address method
    # ========================================================================

    @pytest.mark.unit
    def test_get_by_address_converts_hex_ea_and_transforms(self, plugin, mock_ida_entry_info, mock_entry_info):
        """Test that get_by_address() converts HexEA and transforms result."""
        plugin.database.entries.get_at.return_value = mock_ida_entry_info
        EntryData.from_ida = Mock(return_value=mock_entry_info)

        result = plugin.get_at(HexEA(0x401000))

        plugin.database.entries.get_at.assert_called_once_with(0x401000)
        EntryData.from_ida.assert_called_once_with(mock_ida_entry_info)
        assert result == mock_entry_info

    # ========================================================================
    # Test get_by_name method
    # ========================================================================

    @pytest.mark.unit
    def test_get_by_name_transforms_to_entry_info(self, plugin, mock_ida_entry_info, mock_entry_info):
        """Test that get_by_name() transforms result to EntryInfo."""
        plugin.database.entries.get_by_name.return_value = mock_ida_entry_info
        EntryData.from_ida = Mock(return_value=mock_entry_info)

        result = plugin.get_by_name("main")

        plugin.database.entries.get_by_name.assert_called_once_with("main")
        EntryData.from_ida.assert_called_once_with(mock_ida_entry_info)
        assert result == mock_entry_info

    # ========================================================================
    # Test get_by_ordinal method
    # ========================================================================

    @pytest.mark.unit
    def test_get_by_ordinal_transforms_to_entry_info(self, plugin, mock_ida_entry_info, mock_entry_info):
        """Test that get_by_ordinal() transforms result to EntryInfo."""
        plugin.database.entries.get_by_ordinal.return_value = mock_ida_entry_info
        EntryData.from_ida = Mock(return_value=mock_entry_info)

        result = plugin.get_by_ordinal(1)

        plugin.database.entries.get_by_ordinal.assert_called_once_with(1)
        EntryData.from_ida.assert_called_once_with(mock_ida_entry_info)
        assert result == mock_entry_info

    # ========================================================================
    # Test get_count method
    # ========================================================================

    @pytest.mark.unit
    def test_get_count_returns_total_entries(self, plugin):
        """Test that get_count() returns the total number of entries."""
        plugin.database.entries.get_count.return_value = 5

        result = plugin.get_count()

        plugin.database.entries.get_count.assert_called_once()
        assert result == 5

    # ========================================================================
    # Test get_forwarders method
    # ========================================================================

    @pytest.mark.unit
    def test_get_forwarders_transforms_to_forwarder_info(self, plugin):
        """Test that get_forwarders() transforms results to ForwarderInfo."""
        forwarder1 = Mock()
        forwarder1.ordinal = 10
        forwarder1.name = "CreateFileW"
        forwarder2 = Mock()
        forwarder2.ordinal = 11
        forwarder2.name = "ReadFile"

        plugin.database.entries.get_forwarders.return_value = [forwarder1, forwarder2]

        result = plugin.get_forwarders()

        assert len(result) == 2
        assert all(isinstance(f, ForwarderInfo) for f in result)
        assert result[0].ordinal == 10
        assert result[0].name == "CreateFileW"
        assert result[1].ordinal == 11
        assert result[1].name == "ReadFile"

    # ========================================================================
    # Test get_start method
    # ========================================================================

    @pytest.mark.unit
    def test_get_start_gets_main_entry_point(self, plugin, mock_entry_info):
        """Test that get_start() returns the main entry point."""
        plugin.get_at = Mock(return_value=mock_entry_info)

        with patch("ida_kernwin.ida_ida.inf_get_start_ea") as mock_get_start:
            mock_get_start.return_value = 0x401000

            result = plugin.get_start()

            plugin.get_at.assert_called_once_with(HexEA(0x401000))
            assert result == mock_entry_info

    # ========================================================================
    # Test get_ordinals method
    # ========================================================================

    @pytest.mark.unit
    def test_get_ordinals_returns_all_ordinal_numbers(self, plugin):
        """Test that get_ordinals() returns list of ordinal numbers."""
        plugin.database.entries.get_ordinals.return_value = [1, 2, 10, 15, 100]

        result = plugin.get_ordinals()

        assert result == [1, 2, 10, 15, 100]
        plugin.database.entries.get_ordinals.assert_called_once()

    # ========================================================================
    # Test rename method
    # ========================================================================

    @pytest.mark.unit
    def test_rename_changes_entry_name(self, plugin):
        """Test that rename() changes the entry point name."""
        plugin.database.entries.rename.return_value = True

        result = plugin.rename(1, "new_entry_name")

        plugin.database.entries.rename.assert_called_once_with(1, "new_entry_name")
        assert result is True

    @pytest.mark.unit
    def test_rename_returns_false_on_failure(self, plugin):
        """Test that rename() returns False when operation fails."""
        plugin.database.entries.rename.return_value = False

        result = plugin.rename(999, "new_name")

        assert result is False

    # ========================================================================
    # Test set_forwarder method
    # ========================================================================

    @pytest.mark.unit
    def test_set_forwarder_sets_dll_forwarding(self, plugin):
        """Test that set_forwarder() sets DLL forwarding."""
        plugin.database.entries.set_forwarder.return_value = True

        result = plugin.set_forwarder(1, "KERNEL32.CreateFileA")

        plugin.database.entries.set_forwarder.assert_called_once_with(1, "KERNEL32.CreateFileA")
        assert result is True
