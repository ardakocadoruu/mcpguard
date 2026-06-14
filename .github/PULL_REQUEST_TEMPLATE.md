# Pull Request

## Summary

<!-- Describe what this PR does and why. Link any related issues with "Closes #N". -->

## Type of change

- [ ] Bug fix
- [ ] New detection rule
- [ ] Improvement to existing rule (reduced false positives/negatives)
- [ ] New output format or CLI feature
- [ ] Refactor / internal improvement
- [ ] Documentation
- [ ] CI / tooling

## Checklist

- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] New detection rule has both **positive** test cases (code that should trigger) and **negative** test cases (safe code that should not)
- [ ] `ruff check .` passes with no errors
- [ ] `ruff format --check .` passes
- [ ] `mypy mcpguard/ --ignore-missing-imports` passes
- [ ] Evidence/snippets in tests are properly **redacted** — no real secrets, tokens, or private keys
- [ ] `CHANGELOG.md` entry added under `## [Unreleased]`
- [ ] If adding a package to `known_bad.json`, sufficient public evidence is cited in this PR description

## Testing

<!-- Describe how to test this change locally. -->

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Security considerations

<!-- If this PR touches secret detection patterns, supply-chain logic, or network analysis, describe any edge cases or potential for false positives/negatives. -->