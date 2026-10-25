"""Report whether a PDF has fillable form fields.

Usage: python check_fillable_fields.py input.pdf
"""
import sys

from pypdf import PdfReader

reader = PdfReader(sys.argv[1])
fields = reader.get_fields()
if fields:
    print(f"This PDF has {len(fields)} fillable form fields.")
else:
    print("This PDF has no fillable form fields; annotate it visually instead.")
