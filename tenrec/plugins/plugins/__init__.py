from .bytes import plugin as bytes_plugin
from .comments import plugin as comments_plugin
from .entries import plugin as entries_plugin
from .functions import plugin as functions_plugin
from .names import plugin as names_plugin
from .segments import plugin as segments_plugin
from .strings import plugin as strings_plugin
from .types import plugin as types_plugin
from .xrefs import plugin as xrefs_plugin

DEFAULT_PLUGINS = [
    bytes_plugin,
    comments_plugin,
    entries_plugin,
    functions_plugin,
    names_plugin,
    segments_plugin,
    strings_plugin,
    types_plugin,
    xrefs_plugin,
]
