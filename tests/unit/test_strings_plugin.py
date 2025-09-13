"""
Unit tests for the StringsPlugin class.
Tests plugin business logic including data transformation, filtering, and error handling.
"""

from unittest.mock import Mock, patch

import pytest
from ida_domain.strings import StringItem, StringType

from tenrec.plugins.models import HexEA, OperationError, StringData
from tenrec.plugins.plugins.strings import StringsPlugin


class TestStringsPlugin:
    """Test suite for StringsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Create a StringsPlugin instance with a mock database."""
        plugin = StringsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_string_item(self):
        """Create a mock StringItem object."""
        item = Mock(spec=StringItem)
        item.address = 0x401000
        item.contents = b"Hello, World!"
        item.length = 13
        item.type = StringType.C
        return item

    @pytest.fixture
    def mock_string_data(self):
        """Create a mock StringData object."""
        data = Mock(spec=StringData)
        data.address = HexEA(0x401000)
        data.contents = b"Hello, World!"
        data.length = 13
        data.type = "C"
        return data

    # ========================================================================
    # Test get_all method
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_transforms_strings_to_string_data(self, plugin, mock_string_item, mock_string_data):
        """Test that get_all() transforms StringItem objects to StringData objects."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()

        # Create two mock string items
        item1 = Mock(spec=StringItem)
        item1.address = 0x401000
        item1.contents = b"Hello"
        item2 = Mock(spec=StringItem)
        item2.address = 0x401100
        item2.contents = b"World"

        plugin.database.strings.get_all.return_value = [item1, item2]

        with patch.object(StringData, "from_ida") as mock_from_ida:
            mock_from_ida.side_effect = [
                Mock(spec=StringData, address=HexEA(0x401000)),
                Mock(spec=StringData, address=HexEA(0x401100)),
            ]

            result = plugin.get_all()

            assert len(result) == 2
            assert all(isinstance(s, StringData) for s in result)
            assert mock_from_ida.call_count == 2
            mock_from_ida.assert_any_call(item1)
            mock_from_ida.assert_any_call(item2)

    @pytest.mark.unit
    def test_get_all_empty_list(self, plugin):
        """Test get_all() with no strings."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()
        plugin.database.strings.get_all.return_value = []

        result = plugin.get_all()

        assert result == []

    # ========================================================================
    # Test get_all_filtered method
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_filtered_applies_regex(self, plugin):
        """Test that get_all_filtered() correctly filters strings by regex."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()

        # Create mock string items
        item1 = Mock(spec=StringItem)
        item1.contents = b"https://example.com"
        item2 = Mock(spec=StringItem)
        item2.contents = b"Just a string"
        item3 = Mock(spec=StringItem)
        item3.contents = b"http://test.org"

        plugin.database.strings.get_all.return_value = [item1, item2, item3]

        # Create mock StringData objects
        data1 = Mock(spec=StringData)
        data1.contents = b"https://example.com"
        data3 = Mock(spec=StringData)
        data3.contents = b"http://test.org"

        with patch.object(StringData, "from_ida") as mock_from_ida:
            # Only return StringData for matching items
            mock_from_ida.side_effect = [data1, data3]

            result = plugin.get_all_filtered(r"https?://")

            assert len(result) == 2
            assert result[0].contents == b"https://example.com"
            assert result[1].contents == b"http://test.org"
            # Should only transform matching items
            assert mock_from_ida.call_count == 2

    @pytest.mark.unit
    def test_get_all_filtered_no_matches(self, plugin):
        """Test get_all_filtered() when no strings match the pattern."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()

        item1 = Mock(spec=StringItem)
        item1.contents = b"test"
        item2 = Mock(spec=StringItem)
        item2.contents = b"string"

        plugin.database.strings.get_all.return_value = [item1, item2]

        result = plugin.get_all_filtered(r"^NO_MATCH$")

        assert result == []

    # ========================================================================
    # Test get_at_address method
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_address_returns_string_data(self, plugin, mock_string_item, mock_string_data):
        """Test that get_at_address() returns StringData for valid address."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()
        plugin.database.strings.get_at.return_value = mock_string_item

        with patch.object(StringData, "from_ida") as mock_from_ida:
            mock_from_ida.return_value = mock_string_data

            result = plugin.get_at_address(HexEA(0x401000))

            plugin.database.strings.get_at.assert_called_once_with(0x401000)
            mock_from_ida.assert_called_once_with(mock_string_item)
            assert result == mock_string_data

    @pytest.mark.unit
    def test_get_at_address_raises_when_not_found(self, plugin):
        """Test that get_at_address() raises exception when no string exists."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()
        plugin.database.strings.get_at.return_value = None

        with pytest.raises(OperationError, match="No string found at address"):
            plugin.get_at_address(HexEA(0x401000))

    # ========================================================================
    # Test get_at_index method
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_index_transforms_to_string_data(self, plugin, mock_string_item, mock_string_data):
        """Test that get_at_index() transforms result to StringData."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()
        plugin.database.strings.get_at_index.return_value = mock_string_item

        with patch.object(StringData, "from_ida") as mock_from_ida:
            mock_from_ida.return_value = mock_string_data

            result = plugin.get_at_index(5)

            plugin.database.strings.get_at_index.assert_called_once_with(5)
            mock_from_ida.assert_called_once_with(mock_string_item)
            assert result == mock_string_data

    @pytest.mark.unit
    def test_get_at_index_raises_when_invalid(self, plugin):
        """Test that get_at_index() raises exception for invalid index."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()
        plugin.database.strings.get_at_index.return_value = None

        with pytest.raises(OperationError, match="Failed to get string at index"):
            plugin.get_at_index(999)

    # ========================================================================
    # Test get_between method
    # ========================================================================

    @pytest.mark.unit
    def test_get_between_filters_by_address_range(self, plugin):
        """Test that get_between() returns strings in address range."""
        plugin.database.is_open.return_value = True
        plugin.database.strings.build_string_list = Mock()

        item1 = Mock(spec=StringItem)
        item2 = Mock(spec=StringItem)
        plugin.database.strings.get_between.return_value = [item1, item2]

        with patch.object(StringData, "from_ida") as mock_from_ida:
            data1 = Mock(spec=StringData)
            data2 = Mock(spec=StringData)
            mock_from_ida.side_effect = [data1, data2]

            result = plugin.get_between(HexEA(0x401000), HexEA(0x402000))

            plugin.database.strings.get_between.assert_called_once_with(0x401000, 0x402000)
            assert len(result) == 2
            assert result == [data1, data2]
