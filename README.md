# pact-js

Agnostic JavaScript runtime for the PACT protocol.

## Scope

`pact-js` should not assume anything about Chrome extensions, Discord bots, or any specific host application. It is the shared protocol/runtime layer only.

Its job is to provide reusable PACT primitives such as:

- config parsing
- profile normalization
- payload encryption and decryption
- transport remap handling
- browser-friendly runtime helpers for PACT profiles

## Layout

- `src/pact.js`: canonical source
- `dist/pact.js`: distributable browser artifact

## Usage

Build the distributable artifact:

```sh
npm run build
```

Consumers should decide for themselves how to integrate the built artifact, whether that is copying, bundling, packaging, vendoring, or publishing.

## Design Rule

If code mentions a specific app, extension, bot, storage model, UI flow, or delivery mechanism, it probably belongs outside `pact-js`.
