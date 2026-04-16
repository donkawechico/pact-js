# Copilot instructions for pact-js

- Treat `.sync-inputs/pact/` as read-only upstream source of truth.
- Do not edit `.sync-inputs/` or `.sync-metadata/`.
- Only modify `src/`, `dist/`, tests, package metadata, and small repo metadata files if required.
- Preserve the public pact-js API unless upstream fixtures/spec require otherwise.
- Prefer minimal changes that make upstream fixture tests pass once a fixture test harness exists.
- Do not refactor unrelated code.
