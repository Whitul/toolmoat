"""Extract the fillable form fields of a PDF into a JSON file.

Usage: python extract_form_fields.py input.pdf fields.json
"""
import json
import sys

from pypdf import PdfReader


def field_info(name, field):
    info = {"field_id": name, "type": str(field.get("/FT", "")).lstrip("/")}
    if "/V" in field:
        info["value"] = str(field["/V"])
    if "/_States_" in field:
        info["options"] = [str(state) for state in field["/_States_"]]
    return info


def extract(path):
    reader = PdfReader(path)
    fields = reader.get_fields() or {}
    result = []
    for page_number, page in enumerate(reader.pages, start=1):
        for annotation in page.get("/Annots", []) or []:
            widget = annotation.get_object()
            name = widget.get("/T")
            if name is None or name not in fields:
                continue
            info = field_info(name, fields[name])
            info["page"] = page_number
            info["rect"] = [float(v) for v in widget.get("/Rect", [])]
            result.append(info)
    return result


def main():
    if len(sys.argv) != 3:
        print("Usage: extract_form_fields.py input.pdf fields.json", file=sys.stderr)
        sys.exit(1)
    fields = extract(sys.argv[1])
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        json.dump(fields, fh, indent=2)
    print(f"Wrote {len(fields)} fields to {sys.argv[2]}")


if __name__ == "__main__":
    main()
