from tenrec.utils import disable_print as _disable_print, diable_warnings as _diable_warnings


# Suppress deprecation warnings from IDA python
# This is not ideal, but IDA generates a lot of these warnings that we can't do much about.
_diable_warnings()
# IDA plugins will often print to stdout, which can clutter the output and cause issues with stdout transport.
_disable_print()
