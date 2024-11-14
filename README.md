# sections

Prints sizes of sections inside a pefile (exe, dll, com, etc.), using `pefile` module
from [https://github.com/erocarrera/pefile](https://github.com/erocarrera/pefile).

# Examples

```
$ sections
Pass in exe or dll or other pefiles files to analyze.
<module 'pefile' from 'C:\\Users\\rex\\AppData\\Roaming\\Python\\Python311\\site-packages\\pefile.py'>
```

For most exe files the sum of section sizes will be almost the same as filesize, but for
installers or games made in Love2D like Balatro (where it's normal to append zip to the
exe) the size of file will be huge compared to size of the sections.

```
$ sections Balatro.exe `which sleep.exe`
Sections in Balatro.exe sorted by size
 Section  |      Size |   Ratio
----------|-----------|--------
 .data    |     512 B |    0.1%
 .pdata   |     512 B |    0.1%
 .reloc   |     512 B |    0.1%
 .text    |   6.0 KiB |    1.6%
 .rdata   |   6.0 KiB |    1.6%
 .rsrc    | 371.0 KiB |   96.5%
----------|-----------|--------
 TOTAL    | 384.5 KiB |  100.0%
 filesize |  53.2 MiB |14156.7%

Sections in C:/Program Files/Git/usr/bin/sleep.exe sorted by size
 Section  |     Size | Ratio
----------|----------|------
 .bss     |      0 B |  0.0%
 .data    |    512 B |  1.6%
 .buildid |    512 B |  1.6%
 .reloc   |    512 B |  1.6%
 .pdata   |  1.5 KiB |  4.8%
 .xdata   |  1.5 KiB |  4.8%
 .rsrc    |  1.5 KiB |  4.8%
 .idata   |  2.5 KiB |  7.9%
 .rdata   |  5.5 KiB | 17.5%
 .text    | 17.5 KiB | 55.6%
----------|----------|------
 TOTAL    | 31.5 KiB |100.0%
 filesize | 35.2 KiB |111.6%
```
