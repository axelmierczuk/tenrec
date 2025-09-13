"""
Unit tests for the DatabaseHandler class.
"""

import threading
from unittest.mock import MagicMock, Mock, PropertyMock, patch

import pytest
from ida_domain.database import IdaCommandOptions

from tenrec.plugins.database_manager import DatabaseHandler, Status


class TestDatabaseHandler:
    """Test suite for DatabaseHandler operations."""

    @pytest.fixture
    def ida_options(self):
        """Create default IDA command options."""
        return IdaCommandOptions(auto_analysis=True, log_file=None)

    @pytest.fixture
    def handler(self, ida_options):
        """Create a DatabaseHandler instance."""
        return DatabaseHandler("/test/path.idb", ida_options)

    # ========================================================================
    # Test initialization
    # ========================================================================

    @pytest.mark.unit
    def test_init(self, handler):
        """Test DatabaseHandler initialization."""
        assert handler._path == "/test/path.idb"
        assert handler._status == Status.CLOSED
        assert isinstance(handler._lock, type(threading.RLock()))
        assert handler._database is not None

    # ========================================================================
    # Test open/close operations
    # ========================================================================

    @pytest.mark.unit
    def test_open_success(self, handler):
        """Test successful database opening."""
        handler._database.is_open = Mock(return_value=False)
        handler._database.open = Mock()

        handler.open(analyze=True)

        assert handler._status == Status.READY
        handler._database.open.assert_called_once()

        # Check that the args were properly passed
        call_args = handler._database.open.call_args
        assert call_args.args[0] == "/test/path.idb"
        assert call_args.kwargs.get("save_on_close", False) is True

    @pytest.mark.unit
    def test_open_already_open(self, handler):
        """Test opening an already open database."""
        handler._database.is_open = Mock(return_value=True)
        handler._database.open = Mock()

        handler.open()

        # Should not call open if already open
        handler._database.open.assert_not_called()
        assert handler._status == Status.CLOSED

    @pytest.mark.unit
    def test_open_without_analysis(self, handler):
        """Test opening database without analysis."""
        handler._database.is_open = Mock(return_value=False)
        handler._database.open = Mock()

        handler.open(analyze=False)

        # The open method should be called with an IdaCommandOptions that has auto_analysis=False
        handler._database.open.assert_called_once()

    @pytest.mark.unit
    @patch("tenrec.plugins.database_manager.IdaCommandOptions")
    def test_open_force_analysis(self, mock_ida_options, ida_options):
        """Test forcing analysis even when disabled in args."""
        # Create a handler with auto_analysis=False
        args_no_analysis = IdaCommandOptions(auto_analysis=False)
        handler = DatabaseHandler("/test/path.idb", args_no_analysis)
        handler._database.is_open = Mock(return_value=False)
        handler._database.open = Mock()

        # Mock the IdaCommandOptions constructor to return a mock object
        mock_options_instance = Mock()
        mock_ida_options.return_value = mock_options_instance

        handler.open(analyze=True, force=True)

        # Verify that IdaCommandOptions was called with auto_analysis=True
        mock_ida_options.assert_called_once()
        call_kwargs = mock_ida_options.call_args.kwargs
        assert call_kwargs["auto_analysis"] is True

    @pytest.mark.unit
    def test_close_success(self, handler):
        """Test successful database closing."""
        handler._database.is_open = Mock(return_value=True)
        handler._database.close = Mock()
        handler._status = Status.READY

        handler.close()

        assert handler._status == Status.CLOSED
        handler._database.close.assert_called_once()

    @pytest.mark.unit
    def test_close_already_closed(self, handler):
        """Test closing an already closed database."""
        handler._database.is_open = Mock(return_value=False)
        handler._database.close = Mock()

        handler.close()

        # Should not call close if already closed
        handler._database.close.assert_not_called()

    # ========================================================================
    # Test status and state methods
    # ========================================================================

    @pytest.mark.unit
    def test_is_open(self, handler):
        """Test is_open method."""
        handler._database.is_open = Mock(return_value=True)
        assert handler.is_open() is True

        handler._database.is_open = Mock(return_value=False)
        assert handler.is_open() is False

    @pytest.mark.unit
    def test_database_property(self, handler):
        """Test database property getter."""
        assert handler.database == handler._database

    @pytest.mark.unit
    def test_status_property(self, handler):
        """Test status property getter."""
        handler._status = Status.READY
        assert handler.status == Status.READY

        handler._status = Status.CLOSING
        assert handler.status == Status.CLOSING

    # ========================================================================
    # Test metadata operation
    # ========================================================================

    @pytest.mark.unit
    def test_metadata(self, handler):
        """Test metadata retrieval."""

        mock_metadata = Mock()
        type(handler._database).metadata = PropertyMock(return_value=mock_metadata)

        result = handler.metadata()

        assert result == mock_metadata

    # ========================================================================
    # Test thread safety
    # ========================================================================

    @pytest.mark.unit
    def test_thread_safety_lock(self, handler):
        """Test that operations use the lock properly."""
        handler._lock = MagicMock()
        handler._database.is_open = Mock(return_value=False)
        handler._database.open = Mock()

        handler.open()

        # Verify lock was acquired and released
        handler._lock.__enter__.assert_called()
        handler._lock.__exit__.assert_called()

    # ========================================================================
    # Test Status enum
    # ========================================================================

    @pytest.mark.unit
    def test_status_enum_values(self):
        """Test Status enum values."""
        assert Status.WAITING == 0
        assert Status.OPENING == 1
        assert Status.READY == 2
        assert Status.CLOSING == 3
        assert Status.CLOSED == 4
