"""
Unit tests for the SegmentsPlugin class.
Tests plugin business logic including data transformation and error handling.
"""

from unittest.mock import Mock, patch

import pytest

from tenrec.plugins.models import HexEA, OperationError, SegmentData
from tenrec.plugins.plugins.segments import SegmentsPlugin


class TestSegmentsPlugin:
    """Test suite for SegmentsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates a SegmentsPlugin instance with a mock database."""
        plugin = SegmentsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_segment(self):
        """Creates a mock segment_t object."""
        segment = Mock()
        segment.start_ea = 0x400000
        segment.end_ea = 0x401000
        segment.type = 2  # SEG_CODE
        segment.flags = 0
        segment.perm = 5  # Read + Execute
        return segment

    @pytest.fixture
    def mock_segment_data(self):
        """Creates a mock SegmentData object."""
        data = Mock(spec=SegmentData)
        data.start_ea = HexEA(0x400000)
        data.end_ea = HexEA(0x401000)
        data.name = ".text"
        data.type = "SEG_CODE"
        data.flags = "regular"
        data.permissions = "SEGPERM_READ | SEGPERM_EXEC"
        return data

    # ========================================================================
    # Test get_all method
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_empty(self, plugin):
        """Test get_all when no segments exist."""
        plugin.database.segments.get_all.return_value = []

        result = plugin.get_all()

        assert result == []
        plugin.database.segments.get_all.assert_called_once()

    @pytest.mark.unit
    def test_get_all_transforms_segments_to_segment_data(self, plugin, mock_segment, mock_segment_data):
        """Test that get_all() properly transforms segment_t objects to SegmentData."""
        plugin.database.segments.get_all.return_value = [mock_segment]
        plugin.database.segments.get_name.return_value = ".text"

        with patch.object(SegmentData, "from_segment_t") as mock_from_segment_t:
            mock_from_segment_t.return_value = mock_segment_data

            result = plugin.get_all()

            mock_from_segment_t.assert_called_once_with(mock_segment, ".text")
            assert result == [mock_segment_data]

    @pytest.mark.unit
    def test_get_all_multiple_segments(self, plugin, mock_segment_data):
        """Test get_all with multiple segments."""
        seg1 = Mock()
        seg1.start_ea = 0x400000
        seg1.end_ea = 0x401000

        seg2 = Mock()
        seg2.start_ea = 0x601000
        seg2.end_ea = 0x602000

        plugin.database.segments.get_all.return_value = [seg1, seg2]
        plugin.database.segments.get_name.side_effect = [".text", ".data"]

        with patch.object(SegmentData, "from_segment_t") as mock_from_segment_t:
            mock_data_1 = Mock(spec=SegmentData)
            mock_data_1.name = ".text"
            mock_data_2 = Mock(spec=SegmentData)
            mock_data_2.name = ".data"
            mock_from_segment_t.side_effect = [mock_data_1, mock_data_2]

            result = plugin.get_all()

            assert len(result) == 2
            assert result[0].name == ".text"
            assert result[1].name == ".data"
            assert mock_from_segment_t.call_count == 2

    # ========================================================================
    # Test get_at method
    # ========================================================================

    @pytest.mark.unit
    def test_get_at_converts_hex_ea_and_transforms_result(self, plugin, mock_segment, mock_segment_data):
        """Test that get_at() converts HexEA and transforms segment to SegmentData."""
        plugin.database.segments.get_at.return_value = mock_segment
        plugin.database.segments.get_name.return_value = ".text"

        with patch.object(SegmentData, "from_segment_t") as mock_from_segment_t:
            mock_from_segment_t.return_value = mock_segment_data

            result = plugin.get_at(HexEA(0x400500))

            plugin.database.segments.get_at.assert_called_once_with(0x400500)
            plugin.database.segments.get_name.assert_called_once_with(mock_segment)
            mock_from_segment_t.assert_called_once_with(mock_segment, ".text")
            assert result == mock_segment_data

    @pytest.mark.unit
    def test_get_at_raises_when_segment_not_found(self, plugin):
        """Test that get_at() raises exception when no segment contains the address."""
        plugin.database.segments.get_at.return_value = None

        with pytest.raises(OperationError, match="No segment found at address"):
            plugin.get_at(HexEA(0x100000))

    # ========================================================================
    # Test set_name method
    # ========================================================================

    @pytest.mark.unit
    def test_set_name_converts_hex_ea_and_calls_database(self, plugin, mock_segment):
        """Test that set_name() converts HexEA and renames the segment."""
        plugin.database.segments.get_at.return_value = mock_segment
        plugin.database.segments.set_name.return_value = True

        result = plugin.set_name(HexEA(0x400500), "new_text_section")

        plugin.database.segments.get_at.assert_called_once_with(0x400500)
        plugin.database.segments.set_name.assert_called_once_with(mock_segment, "new_text_section")
        assert result is True

    @pytest.mark.unit
    def test_set_name_returns_false_when_segment_not_found(self, plugin):
        """Test that set_name() returns False when no segment at address."""
        plugin.database.segments.get_at.return_value = None

        result = plugin.set_name(HexEA(0x100000), "new_name")

        plugin.database.segments.get_at.assert_called_once_with(0x100000)
        plugin.database.segments.set_name.assert_not_called()
        assert result is False

    @pytest.mark.unit
    def test_set_name_returns_false_when_rename_fails(self, plugin, mock_segment):
        """Test that set_name() returns False when rename operation fails."""
        plugin.database.segments.get_at.return_value = mock_segment
        plugin.database.segments.set_name.return_value = False

        result = plugin.set_name(HexEA(0x400500), "invalid@name")

        assert result is False
