"""Hypothesis strategies shared across the test suite.

Centralises the input-space generators property tests use. Keeping them
here means a single source of truth for "what is a valid C identifier in
this codebase" or "what range of addresses do we exercise" — and makes
adding new property tests a matter of composing existing strategies.
"""

from __future__ import annotations

from hypothesis import strategies as st


# ---------------------------------------------------------------------------
# Identifiers
# ---------------------------------------------------------------------------

# Characters allowed in any position of a C identifier.
_C_IDENT_INIT_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_"
_C_IDENT_REST_CHARS = _C_IDENT_INIT_CHARS + "0123456789"


@st.composite
def valid_c_identifier(draw, min_size: int = 1, max_size: int = 64) -> str:
    """Generate identifiers IDA's ``names.is_valid_name`` accepts.

    A valid C identifier starts with a letter or underscore and is followed
    by zero or more letters/digits/underscores. The ``min_size`` parameter
    sets the *total* length, including the leading character.
    """
    first = draw(st.sampled_from(_C_IDENT_INIT_CHARS))
    rest = draw(
        st.text(
            alphabet=_C_IDENT_REST_CHARS,
            min_size=max(0, min_size - 1),
            max_size=max(0, max_size - 1),
        )
    )
    return first + rest


# ---------------------------------------------------------------------------
# Numeric / address spaces
# ---------------------------------------------------------------------------

# IDA's ea_t is a 64-bit unsigned integer. We cap at 2**48 because no realistic
# binary lives above that and full 64-bit values trip pydantic's int parsing
# in some edge cases.
hex_ea_value = st.integers(min_value=0, max_value=(1 << 48) - 1)

# Single-byte values for patch tests.
byte_value = st.integers(min_value=0, max_value=0xFF)


# ---------------------------------------------------------------------------
# Free-form text
# ---------------------------------------------------------------------------

# Comment text — IDA accepts anything up to a fairly large limit. We exclude
# control characters because they can corrupt IDA's internal serialisation
# and aren't representative of realistic comments. Newlines are allowed.
_FORBIDDEN_CONTROL = "".join(chr(c) for c in range(32) if c not in (0x09, 0x0A, 0x0D))

comment_text = st.text(
    alphabet=st.characters(blacklist_categories=("Cs",), blacklist_characters=_FORBIDDEN_CONTROL),
    min_size=1,
    max_size=200,
)
