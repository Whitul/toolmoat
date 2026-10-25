# Filling PDF forms

Fillable PDFs store their fields in an AcroForm dictionary. The scripts in
`scripts/` read those fields, and write values back into them.

## Field types

| Type | Value to write |
| --- | --- |
| Text | Any string |
| Checkbox | The field's "on" value, usually `/Yes` |
| Radio group | The export value of the chosen option |
| Choice | One of the listed options |

## Workflow

1. Run `python scripts/extract_form_fields.py input.pdf fields.json`.
2. Read `fields.json` and match every field to the information the user gave you.
3. Ask the user about fields you cannot fill with confidence. Do not guess
   dates, signatures or identification numbers.
4. Save the answers as `values.json`, keyed by field id.
5. Run `python scripts/fill_pdf_form.py input.pdf values.json output.pdf`.
6. Open the result with pdfplumber and check that every value landed in the
   right field before you tell the user it is done.

## Forms without fields

Scanned forms have no fields. Convert the pages to images, find the boxes
visually, and add text annotations at those coordinates instead.
