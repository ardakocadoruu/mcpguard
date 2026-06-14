# Contributing to mcpguard

Thank you for helping make the MCP ecosystem safer! This guide covers everything you need to contribute a bug fix, new rule, or feature.

---

## 1. Development Setup

```bash
# Clone the repository
git clone https://github.com/mcpguard/mcpguard.git
cd mcpguard

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install in editable mode with all dev dependencies
pip install -e ".[dev]"

# Verify the installation
mcpguard --version
pytest tests/ -v
```

All dev dependencies (pytest, ruff, mypy, coverage, etc.) are declared under `[project.optional-dependencies] dev` in `pyproject.toml`.

---

## 2. Writing a New Rule

Rules live in `mcpguard/rules/`. Each rule is a Python class that extends `Rule` from `mcpguard/rules/base.py`.

### Rule ID convention

Rule IDs follow the pattern **`MCP00N`** where `N` is the next available integer. Check the existing rules and CHANGELOG to find the next ID before you start.

### Step-by-step

**Step 1 — Create the rule file.**

```bash
touch mcpguard/rules/my_new_rule.py
```

**Step 2 — Implement the `Rule` base class.**

```python
from mcpguard.rules.base import Rule, Finding, Severity

class MyNewRule(Rule):
    rule_id = "MCP007"
    name = "Short human-readable name"
    description = "One-sentence description of what this rule detects."

    def analyze(self, package_path: str) -> list[Finding]:
        findings: list[Finding] = []
        # Walk the package, parse ASTs, pattern-match, etc.
        # Return a Finding for each issue discovered.
        return findings
```

`Finding` fields: `rule_id`, `severity` (`Severity.LOW/MEDIUM/HIGH/CRITICAL`), `message`, `file`, `line` (optional), `evidence` (optional snippet — **redact secrets**).

**Step 3 — Register the rule.**

Add your class to the registry in `mcpguard/rules/__init__.py`:

```python
from mcpguard.rules.my_new_rule import MyNewRule

ALL_RULES = [
    ...,
    MyNewRule(),
]
```

**Step 4 — Write tests.**

Create `tests/rules/test_my_new_rule.py` with at least:

- **Positive cases** — packages/snippets that *should* trigger the rule.
- **Negative cases** — safe code that *should not* trigger the rule.

```python
from mcpguard.rules.my_new_rule import MyNewRule

def test_detects_bad_pattern(tmp_path):
    (tmp_path / "server.py").write_text("# code that should trigger the rule\n")
    findings = MyNewRule().analyze(str(tmp_path))
    assert len(findings) == 1
    assert findings[0].rule_id == "MCP007"

def test_ignores_safe_pattern(tmp_path):
    (tmp_path / "server.py").write_text("# safe code\n")
    findings = MyNewRule().analyze(str(tmp_path))
    assert findings == []
```

**Step 5 — Document it.**

Add an entry to `CHANGELOG.md` under `## [Unreleased]`:

```markdown
### Added
- MCP007: Your rule description
```

---

## 3. Adding to `known_bad.json`

`known_bad.json` is a database of packages with confirmed malicious behavior used by MCP005 (supply chain analysis). Adding a package here causes an immediate `CRITICAL` finding for anyone who scans it.

**Required evidence before adding a package:**

- A public write-up, CVE, security advisory, or blog post describing the malicious behavior.
- The exact package name and version range(s) that are affected.
- A brief description of what the package does (e.g., "exfiltrates env vars to attacker server on install").

In your PR, include direct links to the evidence. Packages must not be added based on suspicion alone.

---

## 4. Running the Test Suite

```bash
# All tests
pytest tests/ -v

# With coverage report
pytest tests/ -v --cov=mcpguard --cov-report=term-missing

# A single file
pytest tests/rules/test_auth.py -v

# A single test
pytest tests/rules/test_auth.py::test_detects_missing_auth -v
```

---

## 5. Code Style

mcpguard uses [ruff](https://docs.astral.sh/ruff/) for both linting and formatting.

- **Line length:** 100 characters
- **Formatter:** `ruff format .` (replaces black)
- **Linter:** `ruff check .`

Run both before committing:

```bash
ruff check .
ruff format .
mypy mcpguard/ --ignore-missing-imports
```

Configuration lives in `pyproject.toml` under `[tool.ruff]`.

---

## 6. Commit Message Format

mcpguard uses [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

```
<type>(<scope>): <short summary>

[optional body]

[optional footer: Closes #N]
```

**Types:** `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `ci`

**Examples:**

```
feat(rules): add MCP007 environment variable exfiltration detection

fix(MCP006): reduce false positives on example/placeholder tokens

docs: add contributing guide

chore(ci): pin codecov-action to v4
```

The summary line must be 72 characters or fewer and written in the imperative mood ("add", "fix", "remove" — not "added" or "adds").

---

## Questions?

Open a [Discussion](https://github.com/mcpguard/mcpguard/discussions) or a [Feature Request issue](.github/ISSUE_TEMPLATE/feature_request.yml) — we're happy to help before you invest time in a large PR.