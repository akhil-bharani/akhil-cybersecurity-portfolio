# Publish update to existing GitHub Pages site

1. Extract ZIP. Copy **contents** of `akhil-portfolio-complex/` into `~/Downloads/akhil-cybersecurity-portfolio/`, replacing files. Do not copy the enclosing folder or overwrite `.git`.
2. From the repository folder run `python3 -m unittest discover -s tests -v`.
3. Run `git status --short` and verify no private data is included.
4. Run `git add -A && git commit -m "Publish advanced synthetic AWS IR case study" && git push origin main`.
5. GitHub Pages will redeploy; the README and Markdown report render on GitHub, while the website links to the report.
