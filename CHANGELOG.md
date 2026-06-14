# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-14

### Added

- Initial release of mcpguard — a CLI security scanner for MCP (Model Context Protocol) packages
- **MCP001**: Authentication check — detects missing or weak authentication patterns in MCP server implementations
- **MCP002**: Permissions analysis — flags overly broad permission requests and missing scope restrictions
- **MCP003**: Network exfiltration detection — identifies suspicious outbound network calls that may leak data
- **MCP004**: Shell injection detection — detects unsafe subprocess and shell invocation patterns
- **MCP005**: Supply chain analysis — checks lifecycle scripts, detects typosquatting candidates, and cross-references a known-bad package database
- **MCP006**: Secret detection — identifies hardcoded secrets including OpenAI keys, Anthropic keys, AWS credentials, GitHub tokens, and private keys
- Terminal output with [Rich](https://github.com/Textualize/rich) — color-coded severity levels, summary tables, and progress indicators
- JSON output format (`--format json`) for machine-readable results and CI integration
- SARIF output format (`--format sarif`) for GitHub Advanced Security and other SARIF consumers
- PyPI package — install with `pip install mcpguard`

[Unreleased]: https://github.com/mcpguard/mcpguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mcpguard/mcpguard/releases/tag/v0.1.0