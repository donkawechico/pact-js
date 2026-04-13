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

Use the protocol/runtime primitives directly:

```js
const Pact = require("@donkawechico/pact-js");

const config = Pact.PactProtocolConfig({
  messagePrefix: "ENC",
  profile: Pact.PactProfile.PACT_PSK2
});
const secret = Pact.PactSecretGenerator.generateSharedSecret(config);
const engine = Pact.PactEngineFactory.create(config, secret);

const payload = await engine.encrypt("hello world");
const plaintext = await engine.decrypt(payload);
```

The browser artifact also exposes `globalThis.Pact`. `globalThis.PactExtension`
is kept as a compatibility alias for older consumers.

## Design Rule

If code mentions a specific app, extension, bot, storage model, UI flow, or delivery mechanism, it probably belongs outside `pact-js`.
