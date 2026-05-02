\# SecAgentBench Simulation Study – Reproducibility Package



This repository contains supplementary materials for the manuscript

“SecAgentBench as a Simulation-Based Study for Adversarial Robustness of

LLM-Based Security Agents”, including simulation outputs, figures,

appendix excerpts, and author-facing templates.



\## Repository layout



\- `paper/`

&#x20; - Final manuscript (Markdown and DOCX).

\- `simulation/`

&#x20; - CSV tables for baseline platforms, isolated attacks, defenses,

&#x20;   adaptive attackers, and attack chains.

&#x20; - PNG figures generated from the CSV outputs.

\- `code/`

&#x20; - `simulation\_core.py`: Monte Carlo simulation engine that produces

&#x20;   the full grid of synthetic robustness results.

\- `docs/`

&#x20; - `appendix\_excerpt.md`: Appendix sections describing the simulation

&#x20;   procedure and parameterization.

\- `templates/`

&#x20; - `cover\_letter\_submission.docx` and `.txt` (journal submission).

&#x20; - `response\_to\_reviewers\_template.docx` (point‑by‑point reply template).



\## Usage



1\. Open the files in `paper/` to view or edit the manuscript.

2\. Inspect the CSV files in `simulation/` to explore the synthetic

&#x20;  results reported in the paper, or regenerate them by running:



&#x20;  ```bash

&#x20;  cd code

&#x20;  python simulation\_core.py

&#x20;  ```



3\. Refer to `docs/appendix\_excerpt.md` for details on the simulation

&#x20;  procedure, platform profiles, and reproducibility notes.

4\. Use the templates in `templates/` when submitting the manuscript and

&#x20;  preparing responses to reviewers.



The full, production-ready simulation code and configuration files can

be released in a dedicated repository upon acceptance.

