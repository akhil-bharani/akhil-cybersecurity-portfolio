# AI-Assisted SOC Portfolio Lab — Integration Notes

Copy this package's `scripts/`, `tests/`, `evidence/` and `projects/` files into the corresponding directories of your existing repository using **Merge**, not Replace.

Run:
```bash
python3 scripts/ai_soc_pipeline.py
python3 -m unittest discover -s tests -p 'test_ai_soc_pipeline.py' -v
```

Read `projects/ai-soc.md` for scope and evidence limitations.

This is a deterministic, auditable **agent-style SOC workflow**, not an actual LLM multi-agent system. It intentionally never executes response actions.

Do not replace your existing `README.md`, `index.html`, `styles.css`, or `script.js`. Website integration and links can be done in the final cleanup.
