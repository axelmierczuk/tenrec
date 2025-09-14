"""
Unit tests for the XrefsPlugin class.
Tests plugin business logic including data transformation and error handling.
"""

from unittest.mock import Mock, patch

import pytest
from ida_domain.xrefs import XrefInfo, XrefsFlags

from tenrec.plugins.models import FunctionData, HexEA, XrefData
from tenrec.plugins.plugins.xrefs import CGFlow, XrefsPlugin


class TestXrefsPlugin:
    """Test suite for XrefsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates an XrefsPlugin instance with a mock database."""
        plugin = XrefsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_xref_info(self):
        """Creates a mock XrefInfo object."""
        xref = Mock(spec=XrefInfo)
        xref.from_ea = 0x401000
        xref.to_ea = 0x402000
        xref.type = Mock()
        xref.type.name = "CALL_NEAR"
        xref.is_code = True
        xref.user = False
        xref.is_flow = False
        return xref

    @pytest.fixture
    def mock_xref_data(self):
        """Creates a mock XrefData object."""
        data = Mock(spec=XrefData)
        data.from_ea = HexEA(0x401000)
        data.to_ea = HexEA(0x402000)
        data.type = "CALL_NEAR"
        data.is_code = True
        data.user_defined = False
        data.is_flow = False
        return data

    # ========================================================================
    # Test get_xrefs_from method
    # ========================================================================

    @pytest.mark.unit
    def test_get_xrefs_from_empty(self, plugin):
        """Test get_xrefs_from when no xrefs exist."""
        plugin.database.xrefs.from_ea.return_value = []

        result = plugin.get_xrefs_from(HexEA(0x401000))

        assert result == []
        plugin.database.xrefs.from_ea.assert_called_once_with(0x401000, XrefsFlags.CODE)

    @pytest.mark.unit
    def test_get_xrefs_from_transforms_xref_info_to_xref_data(self, plugin, mock_xref_info, mock_xref_data):
        """Test that get_xrefs_from() transforms XrefInfo to XrefData."""
        plugin.database.xrefs.from_ea.return_value = [mock_xref_info]

        with patch.object(XrefData, "from_ida") as mock_from_ida:
            mock_from_ida.return_value = mock_xref_data

            result = plugin.get_xrefs_from(HexEA(0x401000))

            mock_from_ida.assert_called_once_with(mock_xref_info)
            assert result == [mock_xref_data]

    @pytest.mark.unit
    def test_get_xrefs_from_with_flags(self, plugin):
        """Test that get_xrefs_from() accepts flags parameter."""
        plugin.database.xrefs.from_ea.return_value = []

        # Test with DATA flags
        plugin.get_xrefs_from(HexEA(0x401000), flags=XrefsFlags.DATA)
        plugin.database.xrefs.from_ea.assert_called_with(0x401000, XrefsFlags.DATA)

        # Test with ALL flags
        plugin.get_xrefs_from(HexEA(0x401000), flags=XrefsFlags.ALL)
        plugin.database.xrefs.from_ea.assert_called_with(0x401000, XrefsFlags.ALL)

    @pytest.mark.unit
    def test_get_xrefs_from_multiple(self, plugin):
        """Test get_xrefs_from with multiple xrefs."""
        xref1 = Mock(spec=XrefInfo)
        xref1.to_ea = 0x402000
        xref2 = Mock(spec=XrefInfo)
        xref2.to_ea = 0x403000

        plugin.database.xrefs.from_ea.return_value = [xref1, xref2]

        with patch.object(XrefData, "from_ida") as mock_from_ida:
            mock_data_1 = Mock(spec=XrefData)
            mock_data_1.to_ea = HexEA(0x402000)
            mock_data_2 = Mock(spec=XrefData)
            mock_data_2.to_ea = HexEA(0x403000)
            mock_from_ida.side_effect = [mock_data_1, mock_data_2]

            result = plugin.get_xrefs_from(HexEA(0x401000))

            assert len(result) == 2
            assert result[0].to_ea == HexEA(0x402000)
            assert result[1].to_ea == HexEA(0x403000)

    # ========================================================================
    # Test get_xrefs_to method
    # ========================================================================

    @pytest.mark.unit
    def test_get_xrefs_to_empty(self, plugin):
        """Test get_xrefs_to when no xrefs exist."""
        plugin.database.xrefs.to_ea.return_value = []

        result = plugin.get_xrefs_to(HexEA(0x402000))

        assert result == []
        plugin.database.xrefs.to_ea.assert_called_once_with(0x402000, XrefsFlags.CODE)

    @pytest.mark.unit
    def test_get_xrefs_to_transforms_xref_info_to_xref_data(self, plugin, mock_xref_info, mock_xref_data):
        """Test that get_xrefs_to() transforms XrefInfo to XrefData."""
        plugin.database.xrefs.to_ea.return_value = [mock_xref_info]

        with patch.object(XrefData, "from_ida") as mock_from_ida:
            mock_from_ida.return_value = mock_xref_data

            result = plugin.get_xrefs_to(HexEA(0x402000))

            mock_from_ida.assert_called_once_with(mock_xref_info)
            assert result == [mock_xref_data]

    @pytest.mark.unit
    def test_get_xrefs_to_with_flags(self, plugin):
        """Test that get_xrefs_to() accepts flags parameter."""
        plugin.database.xrefs.to_ea.return_value = []

        # Test with DATA flags
        plugin.get_xrefs_to(HexEA(0x402000), flags=XrefsFlags.DATA)
        plugin.database.xrefs.to_ea.assert_called_with(0x402000, XrefsFlags.DATA)

        # Test with NOFLOW flags
        plugin.get_xrefs_to(HexEA(0x402000), flags=XrefsFlags.NOFLOW)
        plugin.database.xrefs.to_ea.assert_called_with(0x402000, XrefsFlags.NOFLOW)

    # ========================================================================
    # Test get_xref_graph method
    # ========================================================================

    @pytest.mark.unit
    def test_get_xref_graph_basic(self, plugin):
        """Test get_xref_graph basic functionality."""
        mock_func = Mock()
        mock_func.start_ea = 0x401000
        mock_func.end_ea = 0x401100
        mock_func.name = "test_function"

        plugin.database.functions.get_at.return_value = mock_func
        plugin.database.instructions.get_between.return_value = []

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_func_data = Mock(spec=FunctionData)
            mock_func_data.start_ea = HexEA(0x401000)
            mock_func_data.end_ea = HexEA(0x401100)
            mock_func_data.name = "test_function"
            mock_func_data.model_dump = Mock(
                return_value={"start_ea": "0x401000", "end_ea": "0x401100", "name": "test_function"}
            )
            mock_from_func_t.return_value = mock_func_data

            # Mock the helper to avoid recursion
            plugin.call_graph_helper = Mock(return_value={})

            plugin.get_xref_graph(HexEA(0x401000), depth=1)

            plugin.database.functions.get_at.assert_called_once_with(0x401000)
            mock_from_func_t.assert_called_once_with(mock_func)
            plugin.call_graph_helper.assert_called_once()

    @pytest.mark.unit
    def test_get_xref_graph_with_direction(self, plugin):
        """Test get_xref_graph with different directions."""
        mock_func = Mock()
        mock_func.start_ea = 0x401000

        plugin.database.functions.get_at.return_value = mock_func

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_func_data = Mock(spec=FunctionData)
            mock_func_data.model_dump = Mock(return_value={})
            mock_from_func_t.return_value = mock_func_data

            plugin.call_graph_helper = Mock(return_value={})

            # Test with down direction (default)
            plugin.get_xref_graph(HexEA(0x401000), depth=2, direction=CGFlow.DOWN)
            call_args = plugin.call_graph_helper.call_args
            assert call_args.kwargs["direction"] == CGFlow.DOWN

            # Test with up direction
            plugin.get_xref_graph(HexEA(0x401000), depth=2, direction=CGFlow.UP)
            call_args = plugin.call_graph_helper.call_args
            assert call_args.kwargs["direction"] == CGFlow.UP

    @pytest.mark.unit
    def test_get_xref_graph_with_flags(self, plugin):
        """Test get_xref_graph with different flags."""
        mock_func = Mock()
        plugin.database.functions.get_at.return_value = mock_func

        with patch.object(FunctionData, "from_func_t") as mock_from_func_t:
            mock_func_data = Mock(spec=FunctionData)
            mock_func_data.model_dump = Mock(return_value={})
            mock_from_func_t.return_value = mock_func_data

            plugin.call_graph_helper = Mock(return_value={})

            # Test with DATA flags
            plugin.get_xref_graph(HexEA(0x401000), flags=XrefsFlags.DATA)
            call_args = plugin.call_graph_helper.call_args
            assert call_args.kwargs["flags"] == XrefsFlags.DATA

            # Test with ALL flags
            plugin.get_xref_graph(HexEA(0x401000), flags=XrefsFlags.ALL)
            call_args = plugin.call_graph_helper.call_args
            assert call_args.kwargs["flags"] == XrefsFlags.ALL

    # ========================================================================
    # Test call_graph_helper method
    # ========================================================================

    @pytest.mark.unit
    def test_call_graph_helper_max_depth(self, plugin):
        """Test that call_graph_helper respects max depth."""
        mock_func = Mock(spec=FunctionData)
        mock_func.start_ea = HexEA(0x401000)
        mock_func.end_ea = HexEA(0x401100)
        mock_func.name = "test_func"
        mock_func.model_dump = Mock(return_value={"start_ea": "0x401000", "end_ea": "0x401100", "name": "test_func"})

        # Test at max depth
        result = plugin.call_graph_helper(mock_func, {}, current_depth=3, max_depth=3)
        assert result == {}

        # Should not call database methods when at max depth
        plugin.database.instructions.get_between.assert_not_called()

    @pytest.mark.unit
    def test_call_graph_helper_avoids_duplicates(self, plugin):
        """Test that call_graph_helper avoids duplicate processing."""
        mock_func = Mock(spec=FunctionData)
        mock_func.start_ea = HexEA(0x401000)
        mock_func.end_ea = HexEA(0x401100)
        mock_func.name = "test_func"
        mock_func.model_dump = Mock(return_value={"start_ea": "0x401000", "end_ea": "0x401100", "name": "test_func"})

        # Pre-populate graph with this function
        existing_graph = {HexEA(0x401000): Mock()}

        result = plugin.call_graph_helper(mock_func, existing_graph, current_depth=0, max_depth=3)

        # Should return immediately without processing
        assert result == existing_graph
        plugin.database.instructions.get_between.assert_not_called()

    @pytest.mark.unit
    def test_call_graph_helper_direction_down(self, plugin):
        """Test call_graph_helper with down direction."""
        mock_func = Mock(spec=FunctionData)
        mock_func.start_ea = HexEA(0x401000)
        mock_func.end_ea = HexEA(0x401100)
        mock_func.name = "test_func"
        mock_func.model_dump = Mock(return_value={"start_ea": "0x401000", "end_ea": "0x401100", "name": "test_func"})

        mock_instruction = Mock()
        mock_instruction.ea = 0x401050
        plugin.database.instructions.get_between.return_value = [mock_instruction]
        plugin.database.xrefs.from_ea.return_value = []

        plugin.call_graph_helper(mock_func, {}, current_depth=0, max_depth=1, direction=CGFlow.DOWN)

        # Should call from_ea for down direction
        plugin.database.xrefs.from_ea.assert_called_once_with(0x401050, flags=XrefsFlags.CODE)
        plugin.database.xrefs.to_ea.assert_not_called()

    @pytest.mark.unit
    def test_call_graph_helper_direction_up(self, plugin):
        """Test call_graph_helper with up direction."""
        mock_func = Mock(spec=FunctionData)
        mock_func.start_ea = HexEA(0x401000)
        mock_func.end_ea = HexEA(0x401100)
        mock_func.name = "test_func"
        mock_func.model_dump = Mock(return_value={"start_ea": "0x401000", "end_ea": "0x401100", "name": "test_func"})

        mock_instruction = Mock()
        mock_instruction.ea = 0x401050
        plugin.database.instructions.get_between.return_value = [mock_instruction]
        plugin.database.xrefs.to_ea.return_value = []

        plugin.call_graph_helper(mock_func, {}, current_depth=0, max_depth=1, direction=CGFlow.UP)

        # Should call to_ea for up direction
        plugin.database.xrefs.to_ea.assert_called_once_with(0x401050, flags=XrefsFlags.CODE)
        plugin.database.xrefs.from_ea.assert_not_called()
