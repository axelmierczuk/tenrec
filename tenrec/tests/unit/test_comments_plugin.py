"""
Unit tests for the CommentsPlugin class.

These tests verify the plugin's business logic, including:
- HexEA to ea_t conversion
- Exception handling for missing comments
- Filtering logic for regex searches
- Proper parameter passing to database layer
"""

from unittest.mock import Mock

import pytest
from ida_domain.comments import CommentInfo, CommentKind

from tenrec.plugins.models.exceptions import OperationError
from tenrec.plugins.models.ida import HexEA
from tenrec.plugins.plugins.comments import CommentsPlugin


class TestCommentsPlugin:
    """Test suite for CommentsPlugin operations."""

    @pytest.fixture
    def plugin(self, mock_ida_database):
        """Creates a CommentsPlugin instance with a mock database."""
        plugin = CommentsPlugin()
        plugin.database = mock_ida_database
        return plugin

    @pytest.fixture
    def mock_comment_info(self):
        """Creates a mock CommentInfo object."""
        comment = Mock(spec=CommentInfo)
        comment.ea = 0x401000
        comment.comment = "Test comment"
        comment.repeatable = False
        return comment

    # ========================================================================
    # Test get - Tests plugin logic for retrieving comments
    # ========================================================================

    @pytest.mark.unit
    def test_get_converts_hex_ea_and_returns_comment(self, plugin, mock_comment_info):
        """Test that get() properly converts HexEA to ea_t and returns comment."""
        plugin.database.comments.get_at.return_value = mock_comment_info

        # Test with HexEA input
        result = plugin.get(HexEA(0x401000))

        # Verify HexEA was converted to ea_t (0x401000)
        plugin.database.comments.get_at.assert_called_once_with(0x401000, CommentKind.REGULAR)

    @pytest.mark.unit
    def test_get_raises_exception_when_comment_not_found(self, plugin):
        """Test that get() raises OperationException when no comment exists."""
        plugin.database.comments.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get(HexEA(0x401000))

        assert "No comment found at address: 0x401000" in str(exc_info.value)

    @pytest.mark.unit
    def test_get_passes_comment_kind_parameter(self, plugin, mock_comment_info):
        """Test that get() correctly passes comment_kind to database."""
        plugin.database.comments.get_at.return_value = mock_comment_info

        # Test with different comment kinds
        plugin.get(HexEA(0x401000), CommentKind.REPEATABLE)
        plugin.database.comments.get_at.assert_called_with(0x401000, CommentKind.REPEATABLE)

        plugin.get(HexEA(0x402000), CommentKind.ALL)
        plugin.database.comments.get_at.assert_called_with(0x402000, CommentKind.ALL)

    # ========================================================================
    # Test set - Tests plugin logic for setting comments
    # ========================================================================

    @pytest.mark.unit
    def test_set_converts_hex_ea_and_passes_parameters(self, plugin):
        """Test that set() properly converts HexEA and passes all parameters."""
        plugin.database.comments.set_at.return_value = True

        result = plugin.set(HexEA(0x401000), "New comment", CommentKind.REGULAR)

        plugin.database.comments.set_at.assert_called_once_with(0x401000, "New comment", CommentKind.REGULAR)
        assert result is True

    @pytest.mark.unit
    def test_set_returns_false_on_failure(self, plugin):
        """Test that set() returns False when database operation fails."""
        plugin.database.comments.set_at.return_value = False

        result = plugin.set(HexEA(0x401000), "Comment")

        assert result is False

    # ========================================================================
    # Test delete - Tests plugin logic for deleting comments
    # ========================================================================

    @pytest.mark.unit
    def test_delete_converts_hex_ea_and_passes_comment_kind(self, plugin):
        """Test that delete() properly converts HexEA and passes comment_kind."""
        plugin.database.comments.delete_at = Mock()

        result = plugin.delete(HexEA(0x401000), CommentKind.REPEATABLE)

        plugin.database.comments.delete_at.assert_called_once_with(0x401000, CommentKind.REPEATABLE)
        assert "Successfully deleted comment" in result

    # ========================================================================
    # Test get_all - Tests plugin logic for retrieving all comments
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_converts_to_list(self, plugin):
        """Test that get_all() converts database iterator to list."""
        comment1 = Mock(spec=CommentInfo)
        comment1.ea = 0x401000
        comment1.comment = "Test comment 1"
        comment1.repeatable = False
        comment2 = Mock(spec=CommentInfo)
        comment2.ea = 0x402000
        comment2.comment = "Test comment 2"
        comment2.repeatable = True

        # Mock iterator behavior
        plugin.database.comments.get_all.return_value = iter([comment1, comment2])

        result = plugin.get_all(CommentKind.REGULAR)

        assert isinstance(result, list)
        assert len(result) == 2
        plugin.database.comments.get_all.assert_called_once_with(CommentKind.REGULAR)

    @pytest.mark.unit
    def test_get_all_handles_empty_results(self, plugin):
        """Test that get_all() handles empty results correctly."""
        plugin.database.comments.get_all.return_value = iter([])

        result = plugin.get_all()

        assert result == []

    # ========================================================================
    # Test get_all_filtered - Tests plugin's filtering logic
    # ========================================================================

    @pytest.mark.unit
    def test_get_all_filtered_applies_regex_filter(self, plugin):
        """Test that get_all_filtered() correctly applies regex filtering."""
        comment1 = Mock(spec=CommentInfo)
        comment1.ea = 0x401000
        comment1.comment = "API call to CreateFile"
        comment1.repeatable = False

        comment2 = Mock(spec=CommentInfo)
        comment2.ea = 0x402000
        comment2.comment = "Local variable initialization"
        comment2.repeatable = False

        comment3 = Mock(spec=CommentInfo)
        comment3.ea = 0x403000
        comment3.comment = "API call to ReadFile"
        comment3.repeatable = False

        plugin.database.comments.get_all.return_value = [comment1, comment2, comment3]

        # Test regex filtering
        result = plugin.get_all_filtered("API.*call", CommentKind.REGULAR)

        assert len(result) == 2
        # Check that the results contain the expected comments (transformed to CommentData)
        assert len(result) == 2
        result_comments = [r.comment for r in result]
        assert "API call to CreateFile" in result_comments
        assert "API call to ReadFile" in result_comments
        assert "Local variable initialization" not in result_comments
        plugin.database.comments.get_all.assert_called_once_with(CommentKind.REGULAR)

    @pytest.mark.unit
    def test_get_all_filtered_with_complex_regex(self, plugin):
        """Test get_all_filtered() with more complex regex patterns."""
        comment1 = Mock(spec=CommentInfo)
        comment1.ea = 0x401000
        comment1.comment = "Function: init_system()"
        comment1.repeatable = False

        comment2 = Mock(spec=CommentInfo)
        comment2.ea = 0x402000
        comment2.comment = "Function: cleanup_system()"
        comment2.repeatable = False

        comment3 = Mock(spec=CommentInfo)
        comment3.ea = 0x403000
        comment3.comment = "Variable: system_state"
        comment3.repeatable = False

        plugin.database.comments.get_all.return_value = [comment1, comment2, comment3]

        # Test with regex that matches function definitions
        result = plugin.get_all_filtered(r"Function:.*\(\)$", CommentKind.REGULAR)

        assert len(result) == 2
        # Check that both function comments are in the results
        result_comments = [r.comment for r in result]
        assert "Function: init_system()" in result_comments
        assert "Function: cleanup_system()" in result_comments

    @pytest.mark.unit
    def test_get_all_filtered_returns_empty_on_no_matches(self, plugin):
        """Test that get_all_filtered() returns empty list when no matches."""
        comment = Mock(spec=CommentInfo)
        comment.ea = 0x401000
        comment.comment = "Some comment"
        comment.repeatable = False

        plugin.database.comments.get_all.return_value = [comment]

        result = plugin.get_all_filtered("no_match_pattern", CommentKind.REGULAR)

        assert result == []

    # ========================================================================
    # Test get with ALL flag - Tests plugin logic for getting any comment type
    # ========================================================================

    @pytest.mark.unit
    def test_get_any_converts_hex_ea_and_returns_comment(self, plugin, mock_comment_info):
        """Test that get() with ALL flag converts HexEA and returns any comment found."""
        plugin.database.comments.get_at.return_value = mock_comment_info

        result = plugin.get(HexEA(0x401000), CommentKind.ALL)

        plugin.database.comments.get_at.assert_called_once_with(0x401000, CommentKind.ALL)
        assert result.ea == HexEA(mock_comment_info.ea)
        assert result.comment == mock_comment_info.comment
        assert result.repeatable == mock_comment_info.repeatable

    @pytest.mark.unit
    def test_get_any_raises_exception_when_no_comments(self, plugin):
        """Test that get() with ALL flag raises OperationException when no comments exist."""
        plugin.database.comments.get_at.return_value = None

        with pytest.raises(OperationError) as exc_info:
            plugin.get(HexEA(0x401000), CommentKind.ALL)

        assert "No comment found at address: 0x401000" in str(exc_info.value)

    # ========================================================================
    # Test HexEA conversion edge cases
    # ========================================================================

    @pytest.mark.unit
    def test_hex_ea_string_conversion(self, plugin, mock_comment_info):
        """Test that HexEA properly handles string input."""
        plugin.database.comments.get_at.return_value = mock_comment_info

        # HexEA can be created from string
        result = plugin.get(HexEA("0x401000"))

        plugin.database.comments.get_at.assert_called_with(0x401000, CommentKind.REGULAR)
        assert result.ea == HexEA(mock_comment_info.ea)
        assert result.comment == mock_comment_info.comment
        assert result.repeatable == mock_comment_info.repeatable

    @pytest.mark.unit
    def test_large_address_handling(self, plugin, mock_comment_info):
        """Test handling of large 64-bit addresses."""
        plugin.database.comments.get_at.return_value = mock_comment_info

        # Test with large 64-bit address
        large_addr = 0x7FFFFFFF00000000
        result = plugin.get(HexEA(large_addr))

        plugin.database.comments.get_at.assert_called_with(large_addr, CommentKind.REGULAR)
        assert result.ea == HexEA(mock_comment_info.ea)
        assert result.comment == mock_comment_info.comment
        assert result.repeatable == mock_comment_info.repeatable
