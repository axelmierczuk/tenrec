import re

from ida_domain.comments import CommentKind

from tenrec.plugins.models import (
    CommentData,
    HexEA,
    Instructions,
    OperationError,
    PaginatedParameter,
    PluginBase,
    operation,
)


class CommentsPlugin(PluginBase):
    """Plugin to manage comments in the IDA database."""

    name = "comments"
    version = "1.0.0"
    instructions = Instructions(
        purpose="Manage comments in the IDA database including regular, repeatable, and function comments.",
        interaction_style=[
            "Write comments that add value to understanding the code",
            "Use clear, concise comment text",
            'Choose appropriate comment type: REGULAR ("regular"), REPEATABLE ("repeatable"), or ALL ("all")',
        ],
        examples=[
            'Add a regular comment at an offset: `comments_set(0x401000, "Entry point initialization", "regular")`',
            'Search comments for comments with regex: `comments_get_all_filtered("API.*call", "repeatable")`',
            'Get the comments in function 0x401000: `comments_get(0x401000, "all")`',
        ],
        anti_examples=[
            "DON'T use comments for storing structured data (use appropriate data types instead)",
            "DON'T create excessively long comments that obscure the disassembly",
            "DON'T forget that REPEATABLE comments propagate to all references",
        ],
    )

    @operation()
    def delete(self, address: HexEA, comment_kind: CommentKind = CommentKind.REGULAR) -> str:
        """Delete a comment at the specified address.

        :param address: Address where the comment is located.
        :param comment_kind: Type of comment to delete:
            `REGULAR`: "regular"
            `REPEATABLE`: "repeatable"
            `ALL`: "all"
        :return: True if comment was deleted, False if no comment existed.
        """
        self.database.comments.delete_at(address.ea_t, comment_kind)
        return f"Successfully deleted comment at address: {address}"

    @operation()
    def get(self, address: HexEA, comment_kind: CommentKind = CommentKind.REGULAR) -> CommentData:
        """Get a specific type of comment at an address.

        :param address: Address to retrieve comment from.
        :param comment_kind: Type of comment to delete:
            `REGULAR`: "regular"
            `REPEATABLE`: "repeatable"
            `ALL`: "all"
        :return: CommentInfo object containing comment text and metadata.
        :raises OperationException: If no comment of specified type exists at address.
        """
        result = self.database.comments.get_at(address.ea_t, comment_kind)
        if not result:
            msg = f"No comment found at address: {address}"
            raise OperationError(msg)
        return CommentData.from_ida(result)

    @operation(options=[PaginatedParameter()])
    def get_all(self, comment_kind: CommentKind = CommentKind.REGULAR) -> list[CommentData]:
        """Get all comments of a specific type in the database.

        :param comment_kind: Type of comment to delete:
            `REGULAR`: "regular"
            `REPEATABLE`: "repeatable"
            `ALL`: "all"
        :return: List of CommentInfo objects for all comments of the specified type.
        """
        return list(map(CommentData.from_ida, list(self.database.comments.get_all(comment_kind))))

    @operation(options=[PaginatedParameter()])
    def get_all_filtered(self, search: str, comment_kind: CommentKind = CommentKind.REGULAR) -> list[CommentData]:
        """Search for comments matching a regex pattern.

        :param search: Regular expression pattern to match comment text.
        :param comment_kind: Type of comment to delete:
            `REGULAR`: "regular"
            `REPEATABLE`: "repeatable"
            `ALL`: "all"
        :return: List of CommentInfo objects for comments matching the pattern.
        """
        result = []
        for comment in self.database.comments.get_all(comment_kind):
            if re.search(search, comment.comment):
                result.append(CommentData.from_ida(comment))
        return result

    @operation()
    def set(self, address: HexEA, comment: str, comment_kind: CommentKind = CommentKind.REGULAR) -> bool:
        """Set or update a comment at an address.

        :param address: Address where to place the comment.
        :param comment: Comment text to set (empty string to delete).
        :param comment_kind: Type of comment to delete:
            `REGULAR`: "regular"
            `REPEATABLE`: "repeatable"
            `ALL`: "all"
        :return: True if comment was successfully set, False otherwise.
        """
        return self.database.comments.set_at(address.ea_t, comment, comment_kind)


plugin = CommentsPlugin()
