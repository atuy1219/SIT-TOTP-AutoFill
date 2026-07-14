#!/usr/bin/env python3

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "PhoneFactor"

query = """
SELECT
    _id,
    name,
    username,
    oath_secret_key
FROM accounts
"""

with sqlite3.connect(
    f"file:{DB_PATH.as_posix()}?mode=ro",
    uri=True,
) as connection:
    cursor = connection.execute(query)
    headers = [column[0] for column in cursor.description]
    rows = cursor.fetchall()


def display_value(value: object) -> str:
    return "" if value is None else str(value)


widths = [
    max(
        len(str(header)),
        max(
            (len(display_value(row[index])) for row in rows),
            default=0,
        ),
    )
    for index, header in enumerate(headers)
]

print(
    "  ".join(
        str(header).ljust(widths[index])
        for index, header in enumerate(headers)
    )
)

print("  ".join("-" * width for width in widths))

for row in rows:
    print(
        "  ".join(
            display_value(value).ljust(widths[index])
            for index, value in enumerate(row)
        )
    )
