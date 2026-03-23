(function (global) {
  "use strict";

  const DEBUG = false;

  function debugLog(scope, message, details) {
    if (!DEBUG || !global.console || typeof global.console.log !== "function") return;
    if (details === undefined) {
      global.console.log("[PACT][" + scope + "] " + message);
      return;
    }
    global.console.log("[PACT][" + scope + "] " + message, details);
  }

  function preview(value, limit) {
    const text = String(value || "");
    return text.length > limit ? text.slice(0, limit) + "..." : text;
  }

  function textEncoder() {
    return new TextEncoder();
  }

  function textDecoder() {
    return new TextDecoder();
  }

  function utf8Encode(value) {
    return textEncoder().encode(value);
  }

  function utf8Decode(value) {
    return textDecoder().decode(value);
  }

  function padBase64(value) {
    return value + "=".repeat((4 - (value.length % 4)) % 4);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(value) {
    return base64ToBytes(padBase64(value.replace(/-/g, "+").replace(/_/g, "/")));
  }

  function flexibleBase64ToBytes(value) {
    return base64ToBytes(
      padBase64(
        value
          .replace(/\./g, "+")
          .replace(/!/g, "/")
          .replace(/-/g, "+")
          .replace(/_/g, "/")
      )
    );
  }

  function standardBase64ToBytes(value) {
    return base64ToBytes(padBase64(value));
  }

  function concatBytes(parts) {
    const total = parts.reduce((sum, part) => sum + part.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      result.set(part, offset);
      offset += part.length;
    }
    return result;
  }

  function requireSingleChar(value, fieldName) {
    if (typeof value !== "string" || value.length !== 1) {
      throw new Error(fieldName + " must be a single character");
    }
    return value;
  }

  function validateCharRemap(remap) {
    const values = Object.values(remap);
    const unique = new Set(values);
    if (unique.size !== values.length) {
      throw new Error("Character remap values must be unique");
    }
    Object.entries(remap).forEach(([from, to]) => {
      requireSingleChar(from, "transportData.charRemap key");
      requireSingleChar(to, "transportData.charRemap value");
    });
  }

  function applyCharRemap(value, remap) {
    if (!remap || Object.keys(remap).length === 0) return value;
    let result = "";
    for (const char of value) {
      result += remap[char] || char;
    }
    return result;
  }

  function invertCharRemap(value, remap) {
    if (!remap || Object.keys(remap).length === 0) return value;
    const inverse = {};
    Object.entries(remap).forEach(([from, to]) => {
      inverse[to] = from;
    });
    let result = "";
    for (const char of value) {
      result += inverse[char] || char;
    }
    return result;
  }

  function decodeAscii85(value) {
    const normalized = value.replace(/\s+/g, "");
    if (!normalized.length) return new Uint8Array();
    const bytes = [];
    for (let i = 0; i < normalized.length; i += 5) {
      const chunk = normalized.slice(i, i + 5);
      const padded = chunk.padEnd(5, "u");
      let acc = 0n;
      for (const char of padded) {
        const code = char.charCodeAt(0);
        if (code < 33 || code > 117) {
          throw new Error("Invalid ASCII85 payload");
        }
        acc = acc * 85n + BigInt(code - 33);
      }
      const tuple = new Uint8Array(4);
      for (let j = 3; j >= 0; j -= 1) {
        tuple[j] = Number(acc & 0xffn);
        acc >>= 8n;
      }
      const usefulBytes = Math.max(0, chunk.length - 1);
      for (let j = 0; j < usefulBytes; j += 1) {
        bytes.push(tuple[j]);
      }
    }
    return Uint8Array.from(bytes);
  }

  function encodeAscii85(bytes) {
    if (!bytes.length) return "";
    let result = "";
    for (let i = 0; i < bytes.length; i += 4) {
      const chunk = bytes.slice(i, i + 4);
      const padded = new Uint8Array(4);
      padded.set(chunk);
      let acc = 0n;
      for (const byte of padded) {
        acc = (acc << 8n) + BigInt(byte);
      }
      const encoded = new Array(5);
      for (let j = 4; j >= 0; j -= 1) {
        encoded[j] = String.fromCharCode(Number(acc % 85n) + 33);
        acc /= 85n;
      }
      result += encoded.slice(0, chunk.length + 1).join("");
    }
    return result;
  }

  function parseTransportData(value) {
    if (value == null) return { charRemap: {} };
    if (typeof value !== "object" || Array.isArray(value)) {
      throw new Error("transportData must be an object");
    }
    const remapValue = value.charRemap;
    if (remapValue == null) return { charRemap: {} };
    if (typeof remapValue !== "object" || Array.isArray(remapValue)) {
      throw new Error("transportData.charRemap must be an object");
    }
    const charRemap = {};
    for (const key of Object.keys(remapValue).sort()) {
      const from = requireSingleChar(key, "transportData.charRemap key");
      const to = requireSingleChar(remapValue[key], "transportData.charRemap value");
      charRemap[from] = to;
    }
    validateCharRemap(charRemap);
    return { charRemap };
  }

  function parseProfileData(profile, value) {
    if (profile === "pact-psk1" || profile === "pact-psk2") {
      if (value != null && (typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 0)) {
        throw new Error("PACT " + profile.slice(5) + " does not allow non-empty profileData");
      }
      return { recipients: [] };
    }
    if (profile !== "pact-box1") {
      throw new Error("Unknown profile: " + profile);
    }
    if (typeof value !== "object" || value == null || Array.isArray(value)) {
      throw new Error("Missing required profile field: profileData.recipients");
    }
    if (!Array.isArray(value.recipients) || value.recipients.length === 0) {
      throw new Error("Missing required profile field: profileData.recipients");
    }
    return {
      recipients: value.recipients.map((recipient, index) => {
        if (!recipient || typeof recipient !== "object") {
          throw new Error("Missing required profile field: profileData.recipients");
        }
        if (typeof recipient.keyId !== "string" || !recipient.keyId) {
          throw new Error("Missing required profile field: profileData.recipients[" + index + "].keyId");
        }
        if (typeof recipient.publicKey !== "string" || !recipient.publicKey) {
          throw new Error("Missing required profile field: profileData.recipients[" + index + "].publicKey");
        }
        if (base64UrlToBytes(recipient.publicKey).length !== 32) {
          throw new Error("Invalid X25519 public key: profileData.recipients[" + index + "].publicKey");
        }
        return {
          keyId: recipient.keyId,
          publicKey: recipient.publicKey
        };
      })
    };
  }

  function parseConfigString(configString) {
    const trimmed = String(configString || "").trim();
    const prefix = "pact:v1:";
    if (!trimmed.startsWith(prefix)) {
      throw new Error("Config string must start with " + prefix);
    }
    const body = JSON.parse(utf8Decode(base64UrlToBytes(trimmed.slice(prefix.length))));
    const messagePrefix = body.messagePrefix;
    if (typeof messagePrefix !== "string" || !messagePrefix.trim()) {
      throw new Error("Message prefix cannot be blank");
    }
    const profile = body.profile;
    if (!["pact-psk1", "pact-psk2", "pact-box1"].includes(profile)) {
      throw new Error("Unknown profile: " + profile);
    }
    const profileData = parseProfileData(profile, body.profileData);
    const transportData = parseTransportData(body.transportData);
    return {
      messagePrefix,
      profile,
      profileData,
      transportData,
      raw: body
    };
  }

  function normalizeConfig(config) {
    const charRemap = config.transportData.charRemap || {};
    if (config.profile === "pact-psk1") {
      return {
        messagePrefix: config.messagePrefix,
        profile: config.profile,
        packedEncoding: "ASCII85",
        charRemap,
        recipients: []
      };
    }
    if (config.profile === "pact-psk2") {
      return {
        messagePrefix: config.messagePrefix,
        profile: config.profile,
        packedEncoding: "STANDARD_NO_PADDING",
        charRemap,
        recipients: []
      };
    }
    return {
      messagePrefix: config.messagePrefix,
      profile: config.profile,
      packedEncoding: "URL_SAFE_NO_PADDING",
      charRemap,
      recipients: config.profileData.recipients
    };
  }

  function candidateTokens(text) {
    const trimmed = text.trim();
    if (!trimmed) return [];
    const trailing = trimmed.replace(/[.,!?)\]}'"]+$/g, "");
    return Array.from(new Set([trimmed, trailing].filter(Boolean)));
  }

  function splitAroundMatches(text, matches) {
    if (!matches.length) return [{ type: "text", value: text }];
    const sorted = matches
      .slice()
      .sort((a, b) => a.start - b.start || b.end - a.end);
    const parts = [];
    let cursor = 0;
    for (const match of sorted) {
      if (match.start < cursor) continue;
      if (match.start > cursor) {
        parts.push({ type: "text", value: text.slice(cursor, match.start) });
      }
      parts.push({ type: "payload", value: match.value, plaintext: match.plaintext, configId: match.configId });
      cursor = match.end;
    }
    if (cursor < text.length) {
      parts.push({ type: "text", value: text.slice(cursor) });
    }
    return parts;
  }

  async function importAesKey(secret) {
    const raw = flexibleBase64ToBytes(secret);
    if (raw.length !== 16 && raw.length !== 32) {
      throw new Error("Raw AES key must decode to 16 or 32 bytes");
    }
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["decrypt"]);
  }

  async function importAesKeyForEncrypt(secret) {
    const raw = flexibleBase64ToBytes(secret);
    if (raw.length !== 16 && raw.length !== 32) {
      throw new Error("Raw AES key must decode to 16 or 32 bytes");
    }
    return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt"]);
  }

  async function decryptAesGcm(ciphertext, key, iv) {
    const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new Uint8Array(plaintext);
  }

  async function encryptAesGcm(plaintext, key, iv) {
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return new Uint8Array(ciphertext);
  }

  async function decryptDefault(runtimeConfig, payload, secret) {
    if (!payload.startsWith(runtimeConfig.messagePrefix)) {
      throw new Error("Unsupported payload format");
    }
    debugLog("decryptDefault", "Attempting decrypt", {
      profile: runtimeConfig.profile,
      prefix: runtimeConfig.messagePrefix,
      remap: runtimeConfig.charRemap,
      payloadPreview: preview(payload, 120)
    });
    const encoded = invertCharRemap(payload.slice(runtimeConfig.messagePrefix.length), runtimeConfig.charRemap);
    const packedBytes = runtimeConfig.packedEncoding === "ASCII85"
      ? decodeAscii85(encoded)
      : standardBase64ToBytes(encoded);
    if (packedBytes.length <= 12) {
      throw new Error("Packed payload too short");
    }
    const iv = packedBytes.slice(0, 12);
    const ciphertext = packedBytes.slice(12);
    const key = await importAesKey(secret);
    return utf8Decode(await decryptAesGcm(ciphertext, key, iv));
  }

  async function encryptDefault(runtimeConfig, plaintext, secret) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await importAesKeyForEncrypt(secret);
    const ciphertext = await encryptAesGcm(utf8Encode(plaintext), key, iv);
    const packed = concatBytes([iv, ciphertext]);
    const encoded = runtimeConfig.packedEncoding === "ASCII85"
      ? encodeAscii85(packed)
      : bytesToBase64(packed).replace(/=+$/g, "");
    return runtimeConfig.messagePrefix + applyCharRemap(encoded, runtimeConfig.charRemap);
  }

  async function importX25519PrivateKey(secret) {
    const raw = base64UrlToBytes(secret);
    if (raw.length !== 32) {
      throw new Error("X25519 private key must decode to 32 bytes");
    }
    return crypto.subtle.importKey("raw", raw, "X25519", false, ["deriveBits"]);
  }

  async function importX25519PublicKey(value) {
    const raw = base64UrlToBytes(value);
    if (raw.length !== 32) {
      throw new Error("Invalid X25519 public key");
    }
    return crypto.subtle.importKey("raw", raw, "X25519", false, []);
  }

  async function exportX25519PublicKey(key) {
    const raw = await crypto.subtle.exportKey("raw", key);
    return new Uint8Array(raw);
  }

  async function deriveBoxWrap(privateKey, publicKey) {
    const sharedSecret = await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256);
    const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
    const info = utf8Encode("pact-box1-wrap");
    const expanded = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info },
        hkdfKey,
        352
      )
    );
    return {
      wrapKey: expanded.slice(0, 32),
      wrapIv: expanded.slice(32, 44)
    };
  }

  async function decryptBox(runtimeConfig, payload, secret) {
    if (!payload.startsWith(runtimeConfig.messagePrefix)) {
      throw new Error("Unsupported payload format");
    }
    const encoded = invertCharRemap(payload.slice(runtimeConfig.messagePrefix.length), runtimeConfig.charRemap);
    const root = JSON.parse(utf8Decode(base64UrlToBytes(encoded)));
    if (root.profile !== "pact-box1" || !Array.isArray(root.recipients) || root.recipients.length === 0) {
      throw new Error("Unsupported payload format");
    }
    const privateKey = await importX25519PrivateKey(secret);
    const ephemeralPublic = await importX25519PublicKey(root.ephemeralPublicKey);
    let payloadKey = null;
    for (const recipient of root.recipients) {
      try {
        const derived = await deriveBoxWrap(privateKey, ephemeralPublic);
        const wrapKey = await crypto.subtle.importKey("raw", derived.wrapKey, { name: "AES-GCM" }, false, ["decrypt"]);
        payloadKey = await decryptAesGcm(base64UrlToBytes(recipient.wrappedKey), wrapKey, derived.wrapIv);
        break;
      } catch (_error) {
        continue;
      }
    }
    if (!payloadKey) {
      throw new Error("No wrapped payload key could be decrypted with the provided private key");
    }
    const contentKey = await crypto.subtle.importKey("raw", payloadKey, { name: "AES-GCM" }, false, ["decrypt"]);
    const plaintext = await decryptAesGcm(
      base64UrlToBytes(root.ciphertext),
      contentKey,
      base64UrlToBytes(root.payloadIv)
    );
    return utf8Decode(plaintext);
  }

  async function encryptBox(runtimeConfig, plaintext) {
    if (!runtimeConfig.recipients || runtimeConfig.recipients.length === 0) {
      throw new Error("PACT box1 requires at least one recipient");
    }
    const ephemeral = await crypto.subtle.generateKey("X25519", true, ["deriveBits"]);
    const ephemeralPublicBytes = await exportX25519PublicKey(ephemeral.publicKey);
    const payloadKey = crypto.getRandomValues(new Uint8Array(32));
    const payloadIv = crypto.getRandomValues(new Uint8Array(12));
    const contentKey = await crypto.subtle.importKey("raw", payloadKey, { name: "AES-GCM" }, false, ["encrypt"]);
    const payloadCiphertext = await encryptAesGcm(utf8Encode(plaintext), contentKey, payloadIv);

    const recipients = [];
    for (const recipient of runtimeConfig.recipients) {
      const recipientPublic = await importX25519PublicKey(recipient.publicKey);
      const derived = await deriveBoxWrap(ephemeral.privateKey, recipientPublic);
      const wrapKey = await crypto.subtle.importKey("raw", derived.wrapKey, { name: "AES-GCM" }, false, ["encrypt"]);
      const wrappedKey = await encryptAesGcm(payloadKey, wrapKey, derived.wrapIv);
      recipients.push({
        keyId: recipient.keyId,
        wrappedKey: bytesToBase64Url(wrappedKey)
      });
    }

    const payloadJson = {
      profile: "pact-box1",
      ephemeralPublicKey: bytesToBase64Url(ephemeralPublicBytes),
      payloadIv: bytesToBase64Url(payloadIv),
      recipients,
      ciphertext: bytesToBase64Url(payloadCiphertext)
    };
    const encoded = bytesToBase64Url(utf8Encode(JSON.stringify(payloadJson)));
    return runtimeConfig.messagePrefix + applyCharRemap(encoded, runtimeConfig.charRemap);
  }

  async function decryptPayload(savedConfig, payload) {
    const parsed = parseConfigString(savedConfig.configString);
    const runtime = normalizeConfig(parsed);
    const secret = String(savedConfig.secret || "").trim();
    debugLog("decryptPayload", "Using saved config", {
      name: savedConfig.name || "",
      profile: parsed.profile,
      remap: parsed.transportData.charRemap || {},
      payloadPreview: preview(payload, 120)
    });
    if (!secret) {
      throw new Error("Missing secret");
    }
    if (runtime.profile === "pact-box1") {
      return decryptBox(runtime, payload, secret);
    }
    return decryptDefault(runtime, payload, secret);
  }

  async function encryptPayload(savedConfig, plaintext) {
    const parsed = parseConfigString(savedConfig.configString);
    const runtime = normalizeConfig(parsed);
    const secret = String(savedConfig.secret || "").trim();
    if (runtime.profile === "pact-box1") {
      return encryptBox(runtime, plaintext);
    }
    if (!secret) {
      throw new Error("Missing secret");
    }
    return encryptDefault(runtime, plaintext, secret);
  }

  async function findDecryptableMatches(savedConfig, text) {
    const parsed = parseConfigString(savedConfig.configString);
    const runtime = normalizeConfig(parsed);
    const prefix = runtime.messagePrefix;
    debugLog("findMatches", "Scanning text node", {
      name: savedConfig.name || "",
      profile: parsed.profile,
      prefix,
      remap: parsed.transportData.charRemap || {},
      textPreview: preview(text, 160)
    });
    const matches = [];
    const seen = new Set();
    const regex = new RegExp(escapeRegex(prefix) + "\\S+", "g");
    let match;
    while ((match = regex.exec(text)) !== null) {
      for (const candidate of candidateTokens(match[0])) {
        const start = match.index;
        const end = start + candidate.length;
        const key = start + ":" + candidate;
        if (seen.has(key)) continue;
        seen.add(key);
        try {
          const plaintext = await decryptPayload(savedConfig, candidate);
          matches.push({
            start,
            end,
            value: candidate,
            plaintext,
            configId: savedConfig.id || ""
          });
          break;
        } catch (_error) {
          debugLog("findMatches", "Candidate failed", {
            candidate: preview(candidate, 120),
            error: _error && _error.message ? _error.message : String(_error)
          });
        }
      }
    }
    return matches;
  }

  function escapeRegex(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  global.PactExtension = {
    parseConfigString,
    normalizeConfig,
    splitAroundMatches,
    findDecryptableMatches,
    decryptPayload,
    encryptPayload,
    bytesToBase64Url
  };
})(globalThis);
