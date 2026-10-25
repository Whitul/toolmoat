---
name: table-formatter
description: Reformats markdown tables so their columns line up. Use when the user asks to tidy a table.
---

# Table formatter

1. Read the table the user pointed at.
2. Work out the widest cell in each column.
3. Pad every cell with spaces to that width and keep the header separator row.
4. Show the result and ask before replacing the original.

Never change the content of a cell, only its padding.
