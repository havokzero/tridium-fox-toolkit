# tridium-fox-toolkit

**Niagara FOX foothold helper — AX 3.x–friendly enumerator, credential checker, and interactive shell (for _authorized_ testing only).**

> ### Legal & ethical
> This tool is for systems you **own** or have **explicit written permission** to test (e.g., CTFs, lab rigs).  
> Do **not** use it on networks or equipment without authorization.

---

## What it does

- **FOX/FOXS banner enumeration**  
  Sends multiple “hello” strategies (NSE-style + minimal) over **FOX (1911)** and **FOXS/TLS (4911)**, parses key/value blocks, and prints a concise station summary (app/vm/os/station name, timezone, etc.).

- **Credential probe + spray (opt-in)**  
  Tries a single credential or sprays a curated default list (with optional swapped and full matrix modes) across FOX/FOXS, with reason codes: `ok / rejected / digest / timeout / error`.

- **Resilient request layer**  
  Delimiter-aware reads, idle/timeout heuristics, and topic fallbacks:  
  `baja children → nav children → BQL` and `baja ord read → baja resolve → BQL`.

- **Interactive shell**  
  Tiny REPL for navigating and querying a station:  
  `ls`, `cd`, `cat`, `nav`, `read`, `bql`, `points`, `comps`, `auto`, `script`, `debug on|off`, `set wait <ms>`.

---

## Quick start

```bash
# 1) (Recommended) create and activate a virtualenv
python -m venv .venv
source .venv/bin/activate         # Windows: .venv\Scripts\activate

# 2) Install requirements
pip install -r requirements.txt

# 3) Run
python tridium_fox_toolkit.py
