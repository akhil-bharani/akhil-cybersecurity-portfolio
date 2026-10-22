# Windows DFIR portfolio update

This is an **overlay package** for the existing `akhil-cybersecurity-portfolio` repository. Copy the *contents* into the repo root. It adds/replaces `projects/windows-dfir.md`, adds `evidence/windows-dfir/`, `scripts/analyze_windows_case.py`, and `tests/test_windows_case.py`.

Update the existing `index.html` Windows project card from `PLANNED LAB` to `PUBLISHED LAB` and its link label to `Read full case study →`. Do not replace your existing index.html with an older version. No real KAPE binaries or employer data are included.

From the repository root:
```
python3 scripts/analyze_windows_case.py
python3 -m unittest discover -s tests -v
```

All evidence is synthetic. This is not a substitute for forensic acquisition or a real incident report.
