---
name: pdf
description: Comprehensive PDF toolkit for extracting text and tables, creating new PDFs, merging and splitting documents, and filling PDF forms. Use when the user needs to read, create or modify a PDF file.
license: MIT
---

# PDF processing guide

## Overview

This guide covers the essential PDF operations with Python libraries and
command-line tools. For form filling, read [forms.md](forms.md) and use the
scripts in `scripts/`.

## Quick start

```python
from pypdf import PdfReader, PdfWriter

reader = PdfReader("document.pdf")
print(f"Pages: {len(reader.pages)}")

text = ""
for page in reader.pages:
    text += page.extract_text()
```

## Python libraries

### pypdf: basic operations

#### Merge PDFs

```python
from pypdf import PdfWriter, PdfReader

writer = PdfWriter()
for pdf_file in ["doc1.pdf", "doc2.pdf", "doc3.pdf"]:
    reader = PdfReader(pdf_file)
    for page in reader.pages:
        writer.add_page(page)

with open("merged.pdf", "wb") as output:
    writer.write(output)
```

#### Split a PDF

```python
reader = PdfReader("input.pdf")
for i, page in enumerate(reader.pages):
    writer = PdfWriter()
    writer.add_page(page)
    with open(f"page_{i + 1}.pdf", "wb") as output:
        writer.write(output)
```

#### Password-protected PDFs

If a PDF is encrypted and the user gives you the password, decrypt it before
reading:

```python
reader = PdfReader("encrypted.pdf")
if reader.is_encrypted:
    reader.decrypt(user_password)
```

### pdfplumber: text and tables

```python
import pdfplumber

with pdfplumber.open("document.pdf") as pdf:
    for page in pdf.pages:
        for table in page.extract_tables():
            print(table)
```

## Command-line tools

```bash
# Extract text while keeping the layout
pdftotext -layout input.pdf output.txt

# Merge and split with qpdf
qpdf --empty --pages file1.pdf file2.pdf -- merged.pdf
qpdf input.pdf --pages . 1-5 -- pages1-5.pdf
```

## Filling forms

1. Check whether the PDF has fillable fields:
   `python scripts/check_fillable_fields.py input.pdf`
2. Extract the field definitions:
   `python scripts/extract_form_fields.py input.pdf fields.json`
3. Ask the user for any values you do not know, then write `values.json`.
4. Fill the form:
   `python scripts/fill_pdf_form.py input.pdf values.json output.pdf`

## Dependencies

Install the libraries once if they are missing:

```bash
pip install pypdf pdfplumber
```

| Task | Best tool |
| --- | --- |
| Merge or split | pypdf, qpdf |
| Extract text | pdfplumber, pdftotext |
| Extract tables | pdfplumber |
| Fill forms | scripts/fill_pdf_form.py |
