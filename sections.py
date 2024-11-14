#!/usr/bin/env python3
"""Python script to pretty print exe/dll file section sizes, using pefile module. """

# standard imports first
import sys
import os

# custom module installed via: python3 -m pip install pefile
import pefile


def format_pretty_table(origdata, rjust=()) -> str:
    """Format rows of data in origdata into a pretty printed ASCII table."""
    data = [None if row is None else tuple(map(str, row)) for row in origdata]
    colcount = max(map(len, (row for row in data if row is not None)))
    maxlens = colcount * [0]
    for row in data:
        if row is None:
            continue
        for i, l1 in enumerate(map(len, row)):
            if l1 > maxlens[i]:
                maxlens[i] = l1
    ret = []
    for row in data:
        if row is None:
            ret.append("|".join("-" * width for width in maxlens))
        else:
            parts = []
            for i, (data, width) in enumerate(zip(row, maxlens)):
                if i in rjust:
                    parts.append(data.rjust(width))
                else:
                    parts.append(data.ljust(width))
            ret.append("|".join(parts))
    return "\n".join(ret)


def pretty_filesize(fsize: int, padamount: int = 0) -> str:
    """Return filesize formatted to as B, KiB, MiB or GiB count, optionally padded."""
    padding = padamount * " "
    if fsize < 1024:
        return f"{padding}{fsize} B{padding}"
    if fsize < 1024 * 1024:
        return f"{padding}{fsize / 1024:.1f} KiB{padding}"
    if fsize < 1024 * 1024 * 1024:
        return f"{padding}{fsize / (1024 * 1024):.1f} MiB{padding}"
    return f"{padding}{fsize / (1024 * 1024 * 1024):.1f} GiB{padding}"


def percentage(amount, base) -> str:
    """Return amount/base as a pretty printed percentage."""
    return f"{amount * 100 / base:.1f}%"


def main():
    """Main function, for speed and to not run anything on import as module."""
    files = sys.argv[1:]

    if not files:
        print("Pass in exe or dll or other pefiles files to analyze.")
        print(pefile)

    for fname in files:
        fsize = os.path.getsize(fname)
        pe = pefile.PE(fname)
        rows = [(" Section ", " Size ", "Ratio"), None]
        total = 0
        sections = sorted(pe.sections, key=lambda x: x.SizeOfRawData)
        total = sum(pe.SizeOfRawData for pe in sections)
        for se in sections:
            size = se.SizeOfRawData
            # if size == 0:
            # continue
            name = se.Name.decode("UTF-8").replace("\0", "")
            name = f" {name} "
            rows.append((name, pretty_filesize(size, 1), percentage(size, total)))

        rows.append(None)
        rows.append((" TOTAL ", pretty_filesize(total, 1), percentage(total, total)))
        rows.append((" filesize ", pretty_filesize(fsize, 1), percentage(fsize, total)))

        print(f"Sections in {fname} sorted by size")
        print(format_pretty_table(rows, rjust=(1, 2)))
        print()
        # TODO: try detect upx compression or is it evident from section names?


if __name__ == "__main__":
    main()
