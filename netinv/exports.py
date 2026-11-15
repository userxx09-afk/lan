"""Export report results to CSV, Excel (.xlsx) or XML."""
from __future__ import annotations

import csv
import io
from xml.sax.saxutils import escape


def to_csv(res: dict, name: str):
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=res["columns"], extrasaction="ignore")
    w.writeheader()
    w.writerows(res["rows"])
    return "﻿" + buf.getvalue(), "text/csv; charset=utf-8", "csv"   # BOM so Excel reads UTF-8


def to_xlsx(res: dict, name: str):
    from openpyxl import Workbook
    from openpyxl.utils import get_column_letter
    wb = Workbook()
    ws = wb.active
    ws.title = name.removeprefix("v_")[:31]
    ws.append(res["columns"])
    for r in res["rows"]:
        ws.append([r.get(c) for c in res["columns"]])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for i, c in enumerate(res["columns"], 1):
        width = max([len(str(c))] + [len(str(r.get(c) or "")) for r in res["rows"][:500]])
        ws.column_dimensions[get_column_letter(i)].width = min(60, width + 2)
    for cell in ws[1]:
        cell.font = cell.font.copy(bold=True)
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"


def to_xml(res: dict, name: str):
    tag = name.removeprefix("v_")
    out = ['<?xml version="1.0" encoding="UTF-8"?>', f"<{tag}>"]
    for r in res["rows"]:
        out.append("  <row>" + "".join(f"<{c}>{escape('' if r.get(c) is None else str(r.get(c)))}</{c}>"
                                       for c in res["columns"]) + "</row>")
    out.append(f"</{tag}>")
    return "\n".join(out), "application/xml", "xml"


FORMATS = {"csv": to_csv, "xlsx": to_xlsx, "xml": to_xml}
