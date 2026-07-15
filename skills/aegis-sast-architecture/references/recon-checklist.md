# Architecture Recon Checklist

## Current Aegis-SAST Modules

- `aegis_sast/cli.py`: scan entrypoint and report export orchestration
- `aegis_sast/analysis/rule_engine.py`: language-specific rule loading
- `aegis_sast/analysis/vulnerability_detector.py`: core scan coordination
- `aegis_sast/analysis/call_graph.py`: Python function index and import resolution
- `aegis_sast/plugins/*.py`: language-specific extraction and taint tracking
- `aegis_sast/ai/gemini_client.py`: AI verification client
- `aegis_sast/reporting/*.py`: JSON and Markdown report export

## Questions To Answer

- Which modules define the actual scanner capability?
- Which modules are product layers rather than detection logic?
- Which assumptions are language-specific?
- Which parts are ready for benchmarking?
- Which parts are still portfolio-grade and should be reworked before defense?

## Thesis-Oriented Observations To Capture

- Why Tree-sitter was chosen
- Why plugin-based language support matters
- Why AI verification must not replace deterministic evidence
- Why normalized results and benchmarks matter for credibility

