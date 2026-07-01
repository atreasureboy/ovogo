# Changelog

All notable changes to Ovogo will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Interactive ask mode** — `PermissionManager.checkToolAsync` now performs readline-based approval prompts when `permissionMode: ask` and a non-read-only tool is requested. New `requiresApproval` flag on `ToolPermissionDecision` lets callers distinguish "needs prompt" from "hard deny". Non-TTY stdin (CI, pipes) safely denies.
- **Persistent permission rules** (`src/config/permissionRules.ts`, `.ovogo/permissions.json`) — declarative allow/deny rules evaluated **before** mode checks. Rule format: `ToolName(glob-pattern)`. Examples: `Bash(nmap*)`, `Bash(**rm -rf**)`, `Read(/shared/docs/**)`. **Deny wins** over allow; matched allow short-circuits all other checks. Project rules merge with `~/.ovogo/permissions.json`. Glob semantics: `*` matches anything except `/`, `**` matches including `/`, `?` matches single char.
- **Tool development guide** (`docs/adding-tools.md`) — walkthrough of creating a new tool, registering it, runtime metadata conventions, where to look for examples.

### Changed
- `PermissionManager` constructor accepts optional `ApprovalPrompt` and `PermissionRules`. `setRules()` allows runtime updates.
- `EngineConfig.permissionRules` flows from `loadPermissionRules(cwd)` in the entry point into the engine.

## [0.2.0] - 2026-07-01

### Added
- **Redaction layer** (`src/core/redaction.ts`) — masks API keys, tokens, passwords, JWT, AWS keys, PEM private keys, cookie headers, and URL-embedded credentials before persisting to event log, episodic memory, dispatch records, task scheduler output, agent results, and compacted context. Detects both sensitive key names and inline secret patterns.
- **PermissionManager** (`src/core/permissionManager.ts`) — three modes (`auto` / `ask` / `deny`) with file-path scoping against `cwd`, `sessionDir`, `readableRoots`, `writableRoots`, plus Bash command classification via `bashPolicy`.
- **ModelClient abstraction** (`src/core/modelClient.ts`) — replaces direct OpenAI SDK usage in engine, orchestrator, and compact with a `ModelClient` interface (`streamChat` + `completeText`). Default implementation: `OpenAICompatibleModelClient`.
- **ArtifactStore** (`src/core/artifactStore.ts`) — per-session artifact persistence with sha256 hashing and redacted manifest. New CLI: `--artifacts <sessionDir>`.
- **BashPolicy** (`src/core/bashPolicy.ts`, 429 lines) — extracted from engine: `classifyBashCommand` (read-only vs mutating), `extractBashReadTargets` / `extractBashWriteTargets`.
- **ToolScheduler** (`src/core/toolScheduler.ts`) — extracted `partitionToolCalls` from engine with configurable `maxParallelBatchSize` (clamped 1..64, prevents unbounded `Promise.all` fan-out).
- **Tool runtime metadata** (`ToolRuntimeMetadata` in `types.ts`) — declarative `readOnly`, `concurrencySafe`, `cacheable`, `cacheTtlMs`, `longRunning` flags drive plan-mode exposure, parallel batching, and caching instead of inline engine sets.
- **Settings schema validation** (`src/config/settings.ts`) — zod-validated `OvogoSettings` with diagnostics; new `runtime` (model, maxIterations, maxConcurrentToolCalls, permissionMode, readable/writableRoots) and `profile` (redteam | generic) sections.
- **New CLI flags**:
  - `--doctor` — local config/environment diagnostics without API key
  - `--events <sessionDir>` — summarize session event log (filterable by type/source/tag/since)
  - `--artifacts <sessionDir>` — summarize artifact manifest
  - `--permission-mode <auto|ask|deny>` — permission preflight mode
  - `--json` — machine-readable diagnostics output
  - `--strict` — non-zero exit when integrity warnings present
- **New event log types**: `run_start`, `run_complete`, `turn_start`, `model_request`, `model_response`, `artifact_write`, `permission_denied`.
- **`npm test` script** — runs `tsc && node --test tests/*.test.mjs`.
- **Test suite** (`tests/`, 22 .mjs files, ~2945 lines) — unit tests for all new abstractions.
- **`OVOGO_MAX_CONCURRENT_TOOL_CALLS` env var** — runtime override for parallel-safe tool batch size.
- **`profile.name` setting** — `redteam` (legacy prompt) or `generic` (domain-neutral coding agent).

### Changed
- `engine.ts`, `orchestrator.ts`, `compact.ts` now depend on `ModelClient` instead of the OpenAI SDK directly.
- `eventLog.readAll` now returns `readWithDiagnostics()` and tolerates corrupt NDJSON lines.
- `DispatchManager` redacts prompts, results, and errors on persist.
- `AsyncTaskScheduler` redacts prompts and outputs before storage.
- `EpisodicMemory`, `SemanticMemory`, `KnowledgeBase` redact records on persist.
- `Renderer`, `TmuxLayout` apply redaction to log writes when enabled.
- `bin/agent-worker.ts` propagates `permissionMode` and `maxConcurrentToolCalls` from worker context.
- `README_SIMPLE.md` updated with new CLI surface and runtime configuration.

### Notes
- `PermissionManager` `ask` mode currently rejects non-read-only operations with a clear reason; interactive approval is not yet implemented.
- Redaction is best-effort regex-based; novel secret formats may not be caught. Add new patterns to `SECRET_VALUE_PATTERNS` in `redaction.ts` as needed.

## [0.1.0] - 2026-04-18

### Added
- Initial release of Ovogo as an autonomous red team coordination engine.
- 22 tools across reconnaissance, scanning, exploitation, post-exploitation, C2, and reporting.
- Think-Act-Observe execution loop with critic, context budget, and auto-compact.
- BattleOrchestrator state machine for multi-phase engagement.
- Sub-agent dispatch (Agent, MultiAgent, DispatchAgent, CheckDispatch, GetDispatchResult).
- Cross-turn memory (semantic + episodic) and growing attack knowledge base.
- C2 (Havoc / Sliver / Metasploit), TmuxSession, ShellSession integrations.
- WeaponRadar semantic search over 22W internal Nuclei PoC database.
- EnvAnalyzer, TechniqueGenerator, MultiScan, DocRead tools.
- MCP tool integration via `@modelcontextprotocol/sdk`.
- `.ovogo/settings.json` for project-level hooks and engagement scope.
- `~/.ovogo/settings.json` for user-level defaults.
- `setup.sh` / `setup.bat` cross-platform install scripts.

[Unreleased]: https://github.com/atreasureboy/ovogo/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/atreasureboy/ovogo/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/atreasureboy/ovogo/releases/tag/v0.1.0