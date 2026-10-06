import csv
import sys

# Output formats shared by the commands that print records (search, analyse).
# "list" is each command's own human-readable layout; "table" and "csv" are generic
# renderings of the same rows, built by render_rows().
FORMATS = ("list", "table", "csv")


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return "; ".join(str(v) for v in value)
    return str(value)


# render_rows prints rows (list of dicts) restricted to columns (list of keys), as an
# aligned text table or as CSV on stdout. Lists inside a cell are joined with "; "
# so that a CSV row stays one record per asset/certificate.
def render_rows(rows: list[dict], columns: list[str], fmt: str, out=None) -> None:
    out = out or sys.stdout
    cells = [[_cell(row.get(col)) for col in columns] for row in rows]

    if fmt == "csv":
        writer = csv.writer(out, lineterminator="\n")
        writer.writerow(columns)
        writer.writerows(cells)
        return

    if fmt == "table":
        widths = [max([len(col)] + [len(r[i]) for r in cells]) for i, col in enumerate(columns)]
        header = "  ".join(col.upper().ljust(w) for col, w in zip(columns, widths))
        print(header.rstrip(), file=out)
        for r in cells:
            print("  ".join(v.ljust(w) for v, w in zip(r, widths)).rstrip(), file=out)
        return

    raise ValueError(f"unsupported output format: {fmt}")
