"""
Incremental Table Synchronization Helper.

Provides a deterministic routine that keeps a table (a ``ttk.Treeview`` or any
object implementing the same small API) in sync with a list of rows without
destroying and recreating every row on every refresh cycle.

The helper is intentionally free of Tkinter imports so that the refresh
behaviour can be verified with lightweight test doubles.
"""

from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple


RowKey = Tuple[Any, ...]


def _default_key(row: Sequence[Any], key_index: int) -> RowKey:
    """Return the identity of a row based on one of its columns."""
    try:
        value = row[key_index]
    except (IndexError, TypeError):
        return ("",)
    return (str(value),)


def sync_tree_rows(
    tree: Any,
    rows: Sequence[Sequence[Any]],
    key_fn: Optional[Callable[[Sequence[Any]], RowKey]] = None,
    key_index: int = 0,
) -> Dict[str, int]:
    """
    Synchronize the rows of a table with the given row data.

    ``tree`` must provide the following subset of the ``ttk.Treeview`` API:

    * ``get_children()``            -> iterable of item identifiers
    * ``item(item_id, option=None)`` -> item values
    * ``item(item_id, values=...)``  -> update item values
    * ``insert(parent, index, values=...)``
    * ``delete(item_ids)``
    * ``selection()`` / ``selection_set(item_ids)`` (optional)

    Rows whose identity is unchanged are updated in place, new rows are
    inserted and stale rows are removed.  The current selection and scroll
    position are preserved whenever the table supports them.

    Returns a dictionary with the number of inserted, updated, unchanged and
    removed rows.
    """
    stats = {"inserted": 0, "updated": 0, "unchanged": 0, "removed": 0}

    row_list = [tuple(row) for row in rows]

    if key_fn is None:
        def _key(row: Sequence[Any]) -> RowKey:
            return _default_key(row, key_index)
    else:
        def _key(row: Sequence[Any]) -> RowKey:
            try:
                return tuple(str(x) for x in key_fn(row))
            except Exception:
                return ("",)

    # Snapshot the current content of the table
    existing: Dict[RowKey, List[str]] = {}
    for item_id in list(tree.get_children()):
        try:
            values = tree.item(item_id, "values")
        except Exception:
            values = None
        key = _key(tuple(values) if values else ())
        existing.setdefault(key, []).append(item_id)

    # Remember the selection so that it survives the refresh
    selected_keys: List[RowKey] = []
    try:
        for item_id in tree.selection():
            values = tree.item(item_id, "values")
            selected_keys.append(_key(tuple(values) if values else ()))
    except Exception:
        selected_keys = []

    # Remember the scroll position
    scroll_position = None
    try:
        scroll_position = tree.yview()
    except Exception:
        scroll_position = None

    for row in row_list:
        key = _key(row)
        bucket = existing.get(key)
        item_id = None
        if bucket:
            item_id = bucket.pop(0)

        if item_id is None:
            tree.insert("", "end", values=row)
            stats["inserted"] += 1
            continue

        try:
            current = tree.item(item_id, "values")
        except Exception:
            current = None

        if tuple(str(x) for x in (current or ())) != tuple(str(x) for x in row):
            tree.item(item_id, values=row)
            stats["updated"] += 1
        else:
            stats["unchanged"] += 1

    # Remove rows that are no longer present
    for bucket in existing.values():
        for item_id in bucket:
            try:
                tree.delete(item_id)
                stats["removed"] += 1
            except Exception:
                continue

    # Restore the selection
    if selected_keys:
        try:
            restore = []
            for item_id in tree.get_children():
                values = tree.item(item_id, "values")
                if _key(tuple(values) if values else ()) in selected_keys:
                    restore.append(item_id)
            tree.selection_set(restore)
        except Exception:
            pass

    # Restore the scroll position
    if scroll_position:
        try:
            tree.yview_moveto(scroll_position[0])
        except Exception:
            pass

    return stats
