"""Fill a PDF form with values from a JSON file.

Usage: python fill_pdf_form.py input.pdf values.json output.pdf
"""
import json
import sys

from pypdf import PdfReader, PdfWriter


def fill(input_path, values_path, output_path):
    with open(values_path, encoding="utf-8") as fh:
        values = json.load(fh)
    reader = PdfReader(input_path)
    writer = PdfWriter()
    writer.append(reader)
    known = set((reader.get_fields() or {}).keys())
    unknown = sorted(set(values) - known)
    if unknown:
        raise SystemExit(f"Unknown field ids: {', '.join(unknown)}")
    for page in writer.pages:
        writer.update_page_form_field_values(page, values, auto_regenerate=False)
    writer.set_need_appearances_writer(True)
    with open(output_path, "wb") as out:
        writer.write(out)


def main():
    if len(sys.argv) != 4:
        print("Usage: fill_pdf_form.py input.pdf values.json output.pdf", file=sys.stderr)
        sys.exit(1)
    fill(*sys.argv[1:4])
    print(f"Filled form saved to {sys.argv[3]}")


if __name__ == "__main__":
    main()
