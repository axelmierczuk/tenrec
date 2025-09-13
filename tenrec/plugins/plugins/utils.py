import ida_hexrays
from ida_domain import Database
from ida_funcs import func_t

from tenrec.plugins.models import OperationError


def get_func_by_name(db: Database, name: str) -> func_t:
    """Find a function in the database by its exact name.

    :param db: IDA Pro database instance to search.
    :param name: Exact function name to search for.
    :return: func_t object representing the found function.
    :raises OperationException: If no function with the given name exists in the database.
    """
    for f in db.functions.get_all():
        if f.name == name:
            return f
    msg = f"Function '{name}' not found"
    raise OperationError(msg)


def refresh_decompiler_ctext(function_address: int) -> None:
    error = ida_hexrays.hexrays_failure_t()
    cfunc: ida_hexrays.cfunc_t = ida_hexrays.decompile_func(function_address, error, ida_hexrays.DECOMP_WARNINGS)
    if cfunc:
        cfunc.refresh_func_ctext()
