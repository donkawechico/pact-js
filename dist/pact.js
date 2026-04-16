(function (global) {
  "use strict";

  const PROFILE = Object.freeze({
    PACT_PSK1: "PACT_PSK1",
    PACT_PSK2: "PACT_PSK2",
    PACT_BOX1: "PACT_BOX1"
  });
  const KEY_HANDLING = Object.freeze({
    PASSPHRASE_PBKDF2: "PASSPHRASE_PBKDF2",
    RAW_BASE64_KEY: "RAW_BASE64_KEY"
  });
  const PAYLOAD_LAYOUT = Object.freeze({
    MULTIPART: "MULTIPART",
    PACKED: "PACKED"
  });
  const PACKED_ENCODING = Object.freeze({
    URL_SAFE_NO_PADDING: "URL_SAFE_NO_PADDING",
    STANDARD_NO_PADDING: "STANDARD_NO_PADDING",
    ASCII85: "ASCII85"
  });
  const SELF_DESCRIBING_PREFIX = "[pact]:v1:";
  const SYNTHETIC_MESSAGE_PREFIX = "pact-auto";

  function getCrypto() {
    if (global.crypto && global.crypto.subtle) return global.crypto;
    if (typeof require === "function") return require("node:crypto").webcrypto;
    throw new Error("Web Crypto is required");
  }

  function getNodeCryptoModule() {
    if (typeof require !== "function") return null;
    try {
      return require("node:crypto");
    } catch (_error) {
      return null;
    }
  }

  function utf8Encode(value) {
    return new TextEncoder().encode(String(value));
  }

  function utf8Decode(value) {
    return new TextDecoder().decode(value);
  }

  function padBase64(value) {
    return value + "=".repeat((4 - (value.length % 4)) % 4);
  }

  function bytesToBase64(bytes) {
    if (typeof btoa === "function") {
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      return btoa(binary);
    }
    return Buffer.from(bytes).toString("base64");
  }

  function base64ToBytes(value) {
    if (typeof atob === "function") {
      const binary = atob(value);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes;
    }
    return new Uint8Array(Buffer.from(value, "base64"));
  }

  function bytesToBase64Url(bytes) {
    return bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function base64UrlToBytes(value) {
    return base64ToBytes(padBase64(String(value).replace(/-/g, "+").replace(/_/g, "/")));
  }

  function flexibleBase64ToBytes(value) {
    return base64ToBytes(
      padBase64(String(value).replace(/\./g, "+").replace(/!/g, "/").replace(/-/g, "+").replace(/_/g, "/"))
    );
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

  function compactJson(value) {
    return JSON.stringify(value);
  }

  function sortedObject(value) {
    const result = {};
    for (const key of Object.keys(value || {}).sort()) result[key] = value[key];
    return result;
  }

  function requireSingleChar(value, fieldName) {
    if (typeof value !== "string" || value.length !== 1) throw new Error(fieldName + " must be a single character");
    return value;
  }

  function cloneRemap(remap) {
    const result = {};
    for (const key of Object.keys(remap || {}).sort()) {
      result[requireSingleChar(key, "transportData.charRemap key")] = requireSingleChar(
        remap[key],
        "transportData.charRemap value"
      );
    }
    validateCharRemap(result);
    return result;
  }

  function validateCharRemap(remap) {
    const values = Object.values(remap || {});
    if (new Set(values).size !== values.length) throw new Error("Character remap values must be unique");
  }

  function applyCharRemap(value, remap) {
    let result = "";
    for (const char of value) result += remap && remap[char] ? remap[char] : char;
    return result;
  }

  function invertCharRemap(value, remap) {
    const inverse = {};
    for (const [from, to] of Object.entries(remap || {})) inverse[to] = from;
    let result = "";
    for (const char of value) result += inverse[char] || char;
    return result;
  }

  function profileFromWireName(value) {
    const normalized = String(value || "").toLowerCase();
    if (value === PROFILE.PACT_PSK1 || normalized === "pact-psk1") return PROFILE.PACT_PSK1;
    if (value === PROFILE.PACT_PSK2 || normalized === "pact-psk2") return PROFILE.PACT_PSK2;
    if (value === PROFILE.PACT_BOX1 || normalized === "pact-box1") return PROFILE.PACT_BOX1;
    throw new Error("Unknown profile: " + value);
  }

  function profileWireName(profile) {
    const normalized = profileFromWireName(profile);
    if (normalized === PROFILE.PACT_PSK1) return "pact-psk1";
    if (normalized === PROFILE.PACT_PSK2) return "pact-psk2";
    return "pact-box1";
  }

  function defaultCryptoFor(keyHandling) {
    return {
      algorithm: "aes-256-gcm",
      ivBytes: 12,
      tagBits: 128,
      kdf:
        keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2
          ? { type: "pbkdf2-hmac-sha256", iterations: 120000, saltBytes: 16 }
          : null
    };
  }

  function sameJson(left, right) {
    return JSON.stringify(left) === JSON.stringify(right);
  }

  function attachRuntimeConfig(input) {
    const keyHandling = input.keyHandling || KEY_HANDLING.PASSPHRASE_PBKDF2;
    const config = {
      messagePrefix: input.messagePrefix == null ? "pact1" : input.messagePrefix,
      profile: input.profile == null ? null : profileFromWireName(input.profile),
      recipients: (input.recipients || []).map((recipient) => ({ keyId: recipient.keyId, publicKey: recipient.publicKey })),
      keyHandling,
      payloadLayout: input.payloadLayout || PAYLOAD_LAYOUT.MULTIPART,
      multipartSeparator: input.multipartSeparator || ":",
      packedEncoding: input.packedEncoding || PACKED_ENCODING.URL_SAFE_NO_PADDING,
      charRemap: cloneRemap(input.charRemap || {}),
      crypto: input.crypto === undefined ? defaultCryptoFor(keyHandling) : input.crypto
    };
    config.toProtocolConfig = function () {
      return runtimeToProtocolConfig(config);
    };
    return config;
  }

  function PactRuntimeConfig(input) {
    return attachRuntimeConfig(input || {});
  }

  function runtimeToProtocolConfig(runtimeConfig) {
    if (runtimeConfig.profile === PROFILE.PACT_BOX1) {
      if (!runtimeConfig.recipients.length) throw new Error("PACT box1 runtime configs require at least one recipient");
      return attachProtocolConfig({
        messagePrefix: runtimeConfig.messagePrefix,
        profile: PROFILE.PACT_BOX1,
        profileData: { recipients: runtimeConfig.recipients },
        transportData: { charRemap: runtimeConfig.charRemap }
      });
    }
    if (runtimeConfig.keyHandling !== KEY_HANDLING.RAW_BASE64_KEY) {
      throw new Error("Only raw-key runtime configs can be expressed as PACT shared-secret profiles");
    }
    if (runtimeConfig.payloadLayout !== PAYLOAD_LAYOUT.PACKED) {
      throw new Error("Only packed runtime configs can be expressed as PACT shared-secret profiles");
    }
    if (!sameJson(runtimeConfig.crypto, defaultCryptoFor(KEY_HANDLING.RAW_BASE64_KEY))) {
      throw new Error("Only default AES-256-GCM raw-key crypto can be expressed as PACT shared-secret profiles");
    }
    if (runtimeConfig.packedEncoding === PACKED_ENCODING.ASCII85) {
      return attachProtocolConfig({
        messagePrefix: runtimeConfig.messagePrefix,
        profile: PROFILE.PACT_PSK1,
        transportData: { charRemap: runtimeConfig.charRemap }
      });
    }
    if (runtimeConfig.packedEncoding === PACKED_ENCODING.STANDARD_NO_PADDING) {
      return attachProtocolConfig({
        messagePrefix: runtimeConfig.messagePrefix,
        profile: PROFILE.PACT_PSK2,
        transportData: { charRemap: runtimeConfig.charRemap }
      });
    }
    throw new Error("Runtime config does not match a standard PACT shared-secret profile");
  }

  function parseTransportData(value) {
    if (value == null) return { charRemap: {} };
    if (typeof value !== "object" || Array.isArray(value)) throw new Error("transportData must be an object");
    if (value.charRemap == null) return { charRemap: {} };
    if (typeof value.charRemap !== "object" || Array.isArray(value.charRemap)) {
      throw new Error("transportData.charRemap must be an object");
    }
    return { charRemap: cloneRemap(value.charRemap) };
  }

  function parseProfileData(profile, value) {
    if (profile === PROFILE.PACT_PSK1 || profile === PROFILE.PACT_PSK2) {
      if (value != null && (typeof value !== "object" || Array.isArray(value) || Object.keys(value).length > 0)) {
        throw new Error("PACT " + profileWireName(profile).slice(5) + " does not allow non-empty profileData");
      }
      return {};
    }
    if (typeof value !== "object" || value == null || Array.isArray(value)) {
      throw new Error("Missing required profile field: profileData.recipients");
    }
    if (!Array.isArray(value.recipients) || value.recipients.length === 0) {
      throw new Error("Missing required profile field: profileData.recipients");
    }
    return {
      recipients: value.recipients.map((recipient, index) => {
        if (!recipient || typeof recipient !== "object") throw new Error("Missing required profile field: profileData.recipients");
        if (typeof recipient.keyId !== "string" || !recipient.keyId) {
          throw new Error("Missing required profile field: profileData.recipients[" + index + "].keyId");
        }
        if (typeof recipient.publicKey !== "string" || !recipient.publicKey) {
          throw new Error("Missing required profile field: profileData.recipients[" + index + "].publicKey");
        }
        if (base64UrlToBytes(recipient.publicKey).length !== 32) {
          throw new Error("Invalid X25519 public key: profileData.recipients[" + index + "].publicKey");
        }
        return { keyId: recipient.keyId, publicKey: recipient.publicKey };
      })
    };
  }

  function attachProtocolConfig(input) {
    const profile = profileFromWireName(input.profile);
    const config = {
      messagePrefix: input.messagePrefix,
      profile,
      profileData: input.profileData || {},
      transportData: input.transportData || { charRemap: {} },
      extraFields: sortedObject(input.extraFields || {})
    };
    config.profileData = parseProfileData(profile, config.profileData);
    config.transportData = parseTransportData(config.transportData);
    config.normalize = function () {
      return normalizeProtocolConfig(config);
    };
    config.withTransport = function (options) {
      const update = options || {};
      return attachProtocolConfig({
        messagePrefix: update.messagePrefix == null ? config.messagePrefix : update.messagePrefix,
        profile: config.profile,
        profileData: config.profileData,
        transportData: { charRemap: update.charRemap == null ? config.transportData.charRemap : update.charRemap },
        extraFields: config.extraFields
      });
    };
    config.withProfile = function (profileValue, options) {
      const updatedProfile = profileFromWireName(profileValue);
      const update = options || {};
      return attachProtocolConfig({
        messagePrefix: config.messagePrefix,
        profile: updatedProfile,
        profileData:
          updatedProfile === PROFILE.PACT_PSK1 || updatedProfile === PROFILE.PACT_PSK2
            ? {}
            : config.profileData,
        transportData: { charRemap: update.charRemap == null ? config.transportData.charRemap : update.charRemap },
        extraFields: config.extraFields
      });
    };
    config.normalize();
    return config;
  }

  function PactProtocolConfig(input) {
    return attachProtocolConfig(input || {});
  }

  function normalizeProtocolConfig(config) {
    if (typeof config.messagePrefix !== "string" || config.messagePrefix === "") throw new Error("messagePrefix must not be empty");
    if (config.messagePrefix === "pact") throw new Error("messagePrefix must not be pact");
    if (config.messagePrefix.includes("[") || config.messagePrefix.includes("]")) {
      throw new Error("messagePrefix must not contain brackets");
    }
    validateCharRemap(config.transportData.charRemap);
    if (config.profile === PROFILE.PACT_PSK1) {
      return attachRuntimeConfig({
        messagePrefix: config.messagePrefix,
        profile: PROFILE.PACT_PSK1,
        keyHandling: KEY_HANDLING.RAW_BASE64_KEY,
        payloadLayout: PAYLOAD_LAYOUT.PACKED,
        packedEncoding: PACKED_ENCODING.ASCII85,
        charRemap: config.transportData.charRemap,
        crypto: defaultCryptoFor(KEY_HANDLING.RAW_BASE64_KEY)
      });
    }
    if (config.profile === PROFILE.PACT_PSK2) {
      return attachRuntimeConfig({
        messagePrefix: config.messagePrefix,
        profile: PROFILE.PACT_PSK2,
        keyHandling: KEY_HANDLING.RAW_BASE64_KEY,
        payloadLayout: PAYLOAD_LAYOUT.PACKED,
        packedEncoding: PACKED_ENCODING.STANDARD_NO_PADDING,
        charRemap: config.transportData.charRemap,
        crypto: defaultCryptoFor(KEY_HANDLING.RAW_BASE64_KEY)
      });
    }
    return attachRuntimeConfig({
      messagePrefix: config.messagePrefix,
      profile: PROFILE.PACT_BOX1,
      recipients: config.profileData.recipients,
      charRemap: config.transportData.charRemap
    });
  }

  const PactConfigString = {
    parse(value) {
      const trimmed = String(value || "").trim();
      const prefix = "pact:v1:";
      if (!trimmed.startsWith(prefix)) throw new Error("Config string must start with " + prefix);
      const root = JSON.parse(utf8Decode(base64UrlToBytes(trimmed.slice(prefix.length))));
      if (typeof root.messagePrefix !== "string") throw new Error("Missing required field: messagePrefix");
      if (root.messagePrefix === "") throw new Error("messagePrefix must not be empty");
      if (root.messagePrefix === "pact") throw new Error("messagePrefix must not be pact");
      if (root.messagePrefix.includes("[") || root.messagePrefix.includes("]")) {
        throw new Error("messagePrefix must not contain brackets");
      }
      if (typeof root.profile !== "string") throw new Error("Missing required field: profile");
      const known = new Set(["messagePrefix", "profile", "profileData", "transportData", "protocolVersion"]);
      const extraFields = {};
      for (const key of Object.keys(root).sort()) {
        if (!known.has(key)) extraFields[key] = root[key];
      }
      const profile = profileFromWireName(root.profile);
      return attachProtocolConfig({
        messagePrefix: root.messagePrefix,
        profile,
        profileData: parseProfileData(profile, root.profileData),
        transportData: parseTransportData(root.transportData),
        extraFields
      });
    },
    serialize(config) {
      const protocolConfig = attachProtocolConfig(config);
      const root = {
        messagePrefix: protocolConfig.messagePrefix,
        profile: profileWireName(protocolConfig.profile)
      };
      if (protocolConfig.profile === PROFILE.PACT_BOX1) root.profileData = protocolConfig.profileData;
      if (Object.keys(protocolConfig.transportData.charRemap).length) {
        root.transportData = { charRemap: sortedObject(protocolConfig.transportData.charRemap) };
      }
      for (const key of Object.keys(protocolConfig.extraFields).sort()) {
        if (!(key in root)) root[key] = protocolConfig.extraFields[key];
      }
      return "pact:v1:" + bytesToBase64Url(utf8Encode(compactJson(root)));
    }
  };

  function wirePrefix(messagePrefix) {
    return "[" + messagePrefix + "]";
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
        if (code < 33 || code > 117) throw new Error("Invalid ASCII85 payload");
        acc = acc * 85n + BigInt(code - 33);
      }
      const tuple = new Uint8Array(4);
      for (let j = 3; j >= 0; j -= 1) {
        tuple[j] = Number(acc & 0xffn);
        acc >>= 8n;
      }
      for (let j = 0; j < Math.max(0, chunk.length - 1); j += 1) bytes.push(tuple[j]);
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
      for (const byte of padded) acc = (acc << 8n) + BigInt(byte);
      const encoded = new Array(5);
      for (let j = 4; j >= 0; j -= 1) {
        encoded[j] = String.fromCharCode(Number(acc % 85n) + 33);
        acc /= 85n;
      }
      result += encoded.slice(0, chunk.length + 1).join("");
    }
    return result;
  }

  function encodeSegment(value, encoding, remap) {
    const encoded =
      encoding === PACKED_ENCODING.ASCII85
        ? encodeAscii85(value)
        : encoding === PACKED_ENCODING.STANDARD_NO_PADDING
          ? bytesToBase64(value).replace(/=+$/g, "")
          : bytesToBase64Url(value);
    return applyCharRemap(encoded, remap);
  }

  function decodeSegment(value, encoding, remap) {
    const normalized = invertCharRemap(value, remap);
    if (encoding === PACKED_ENCODING.ASCII85) return decodeAscii85(normalized);
    if (encoding === PACKED_ENCODING.STANDARD_NO_PADDING) return flexibleBase64ToBytes(normalized);
    return base64UrlToBytes(normalized);
  }

  async function importAesKey(raw, usages) {
    return getCrypto().subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usages);
  }

  function decodeRawAesKey(secret) {
    const raw = flexibleBase64ToBytes(secret);
    if (raw.length !== 16 && raw.length !== 32) throw new Error("Raw AES key must decode to 16 or 32 bytes");
    return raw;
  }

  async function derivePassphraseKey(secret, salt, iterations) {
    const crypto = getCrypto();
    const baseKey = await crypto.subtle.importKey("raw", utf8Encode(secret), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function decryptAesGcm(ciphertext, key, iv) {
    return new Uint8Array(await getCrypto().subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext));
  }

  async function encryptAesGcm(plaintext, key, iv) {
    return new Uint8Array(await getCrypto().subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  }

  function randomBytes(length) {
    return getCrypto().getRandomValues(new Uint8Array(length));
  }

  async function defaultEncryptDeterministic(runtimeConfig, plaintext, secret, options) {
    const iv = options.iv;
    if (!iv) throw new Error("Deterministic encrypt requires iv");
    if (runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2) {
      const salt = options.salt;
      if (!salt) throw new Error("Passphrase mode requires a salt");
      const key = await derivePassphraseKey(secret, salt, runtimeConfig.crypto.kdf.iterations);
      const ciphertext = await encryptAesGcm(utf8Encode(plaintext), key, iv);
      if (runtimeConfig.payloadLayout === PAYLOAD_LAYOUT.MULTIPART) {
        return [
          wirePrefix(runtimeConfig.messagePrefix),
          encodeSegment(salt, runtimeConfig.packedEncoding, runtimeConfig.charRemap),
          encodeSegment(iv, runtimeConfig.packedEncoding, runtimeConfig.charRemap),
          encodeSegment(ciphertext, runtimeConfig.packedEncoding, runtimeConfig.charRemap)
        ].join(runtimeConfig.multipartSeparator);
      }
      return wirePrefix(runtimeConfig.messagePrefix) + encodeSegment(concatBytes([salt, iv, ciphertext]), runtimeConfig.packedEncoding, runtimeConfig.charRemap);
    }
    const key = await importAesKey(decodeRawAesKey(secret), ["encrypt"]);
    const ciphertext = await encryptAesGcm(utf8Encode(plaintext), key, iv);
    if (runtimeConfig.payloadLayout === PAYLOAD_LAYOUT.MULTIPART) {
      return [
        wirePrefix(runtimeConfig.messagePrefix),
        encodeSegment(iv, runtimeConfig.packedEncoding, runtimeConfig.charRemap),
        encodeSegment(ciphertext, runtimeConfig.packedEncoding, runtimeConfig.charRemap)
      ].join(runtimeConfig.multipartSeparator);
    }
    return wirePrefix(runtimeConfig.messagePrefix) + encodeSegment(concatBytes([iv, ciphertext]), runtimeConfig.packedEncoding, runtimeConfig.charRemap);
  }

  async function decryptDefault(runtimeConfig, payload, secret) {
    if (payload.startsWith(SELF_DESCRIBING_PREFIX)) return decryptSelfDescribing(payload, secret);
    if (runtimeConfig.payloadLayout === PAYLOAD_LAYOUT.MULTIPART) {
      const parts = payload.split(runtimeConfig.multipartSeparator);
      if (parts[0] !== wirePrefix(runtimeConfig.messagePrefix)) throw new Error("Unsupported payload format");
      if (runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2) {
        if (parts.length !== 4) throw new Error("Unsupported payload format");
        const salt = decodeSegment(parts[1], runtimeConfig.packedEncoding, runtimeConfig.charRemap);
        const iv = decodeSegment(parts[2], runtimeConfig.packedEncoding, runtimeConfig.charRemap);
        const ciphertext = decodeSegment(parts[3], runtimeConfig.packedEncoding, runtimeConfig.charRemap);
        const key = await derivePassphraseKey(secret, salt, runtimeConfig.crypto.kdf.iterations);
        return utf8Decode(await decryptAesGcm(ciphertext, key, iv));
      }
      if (parts.length !== 3) throw new Error("Unsupported payload format");
      const iv = decodeSegment(parts[1], runtimeConfig.packedEncoding, runtimeConfig.charRemap);
      const ciphertext = decodeSegment(parts[2], runtimeConfig.packedEncoding, runtimeConfig.charRemap);
      const key = await importAesKey(decodeRawAesKey(secret), ["decrypt"]);
      return utf8Decode(await decryptAesGcm(ciphertext, key, iv));
    }
    const prefix = wirePrefix(runtimeConfig.messagePrefix);
    if (!payload.startsWith(prefix)) throw new Error("Unsupported payload format");
    const packedBytes = decodeSegment(payload.slice(prefix.length), runtimeConfig.packedEncoding, runtimeConfig.charRemap);
    if (runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2) {
      const saltBytes = runtimeConfig.crypto.kdf.saltBytes;
      const ivBytes = runtimeConfig.crypto.ivBytes;
      if (packedBytes.length <= saltBytes + ivBytes) throw new Error("Packed payload too short");
      const salt = packedBytes.slice(0, saltBytes);
      const iv = packedBytes.slice(saltBytes, saltBytes + ivBytes);
      const ciphertext = packedBytes.slice(saltBytes + ivBytes);
      const key = await derivePassphraseKey(secret, salt, runtimeConfig.crypto.kdf.iterations);
      return utf8Decode(await decryptAesGcm(ciphertext, key, iv));
    }
    if (packedBytes.length <= runtimeConfig.crypto.ivBytes) throw new Error("Packed payload too short");
    const iv = packedBytes.slice(0, runtimeConfig.crypto.ivBytes);
    const ciphertext = packedBytes.slice(runtimeConfig.crypto.ivBytes);
    const key = await importAesKey(decodeRawAesKey(secret), ["decrypt"]);
    return utf8Decode(await decryptAesGcm(ciphertext, key, iv));
  }

  async function importX25519PrivateKey(secret) {
    const raw = base64UrlToBytes(secret);
    if (raw.length !== 32) throw new Error("X25519 private key must decode to 32 bytes");
    const nodeCrypto = getNodeCryptoModule();
    if (nodeCrypto) {
      return {
        nodeKey: nodeCrypto.createPrivateKey({
          key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(raw)]),
          format: "der",
          type: "pkcs8"
        })
      };
    }
    return getCrypto().subtle.importKey("raw", raw, "X25519", false, ["deriveBits"]);
  }

  async function importX25519PublicKey(value) {
    const raw = base64UrlToBytes(value);
    if (raw.length !== 32) throw new Error("Invalid X25519 public key");
    const nodeCrypto = getNodeCryptoModule();
    if (nodeCrypto) {
      return {
        nodeKey: nodeCrypto.createPublicKey({
          key: Buffer.concat([Buffer.from("302a300506032b656e032100", "hex"), Buffer.from(raw)]),
          format: "der",
          type: "spki"
        })
      };
    }
    return getCrypto().subtle.importKey("raw", raw, "X25519", false, []);
  }

  async function exportRawKey(key) {
    return new Uint8Array(await getCrypto().subtle.exportKey("raw", key));
  }

  async function deriveBoxWrap(privateKey, publicKey) {
    const nodeCrypto = getNodeCryptoModule();
    if (nodeCrypto && privateKey.nodeKey && publicKey.nodeKey) {
      const sharedSecret = nodeCrypto.diffieHellman({ privateKey: privateKey.nodeKey, publicKey: publicKey.nodeKey });
      const expanded = new Uint8Array(nodeCrypto.hkdfSync("sha256", sharedSecret, Buffer.alloc(0), Buffer.from("pact-box1-wrap"), 44));
      return { wrapKey: expanded.slice(0, 32), wrapIv: expanded.slice(32, 44) };
    }
    const crypto = getCrypto();
    const sharedSecret = await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256);
    const hkdfKey = await crypto.subtle.importKey("raw", sharedSecret, "HKDF", false, ["deriveBits"]);
    const expanded = new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info: utf8Encode("pact-box1-wrap") },
        hkdfKey,
        352
      )
    );
    return { wrapKey: expanded.slice(0, 32), wrapIv: expanded.slice(32, 44) };
  }

  function parseBoxPayload(payload, messagePrefix, remap) {
    if (!payload.startsWith(messagePrefix)) throw new Error("Unsupported payload format");
    const root = JSON.parse(utf8Decode(base64UrlToBytes(invertCharRemap(payload.slice(messagePrefix.length), remap))));
    if (root.profile !== "pact-box1" || !Array.isArray(root.recipients) || root.recipients.length === 0) {
      throw new Error("Unsupported payload format");
    }
    if (typeof root.ephemeralPublicKey !== "string" || typeof root.payloadIv !== "string" || typeof root.ciphertext !== "string") {
      throw new Error("Unsupported payload format");
    }
    for (const recipient of root.recipients) {
      if (!recipient || typeof recipient.keyId !== "string" || typeof recipient.wrappedKey !== "string") {
        throw new Error("Unsupported payload format");
      }
    }
    return root;
  }

  async function decryptBox(runtimeConfig, payload, secret) {
    if (!secret) throw new Error("PACT box1 decryption requires an X25519 private key");
    if (payload.startsWith(SELF_DESCRIBING_PREFIX)) return decryptSelfDescribing(payload, secret);
    const root = parseBoxPayload(payload, wirePrefix(runtimeConfig.messagePrefix), runtimeConfig.charRemap);
    const privateKey = await importX25519PrivateKey(secret);
    const ephemeralPublic = await importX25519PublicKey(root.ephemeralPublicKey);
    let payloadKey = null;
    for (const recipient of root.recipients) {
      try {
        const derived = await deriveBoxWrap(privateKey, ephemeralPublic);
        const wrapKey = await importAesKey(derived.wrapKey, ["decrypt"]);
        payloadKey = await decryptAesGcm(base64UrlToBytes(recipient.wrappedKey), wrapKey, derived.wrapIv);
        break;
      } catch (_error) {
        continue;
      }
    }
    if (!payloadKey) throw new Error("No wrapped payload key could be decrypted with the provided private key");
    const contentKey = await importAesKey(payloadKey, ["decrypt"]);
    const plaintext = await decryptAesGcm(base64UrlToBytes(root.ciphertext), contentKey, base64UrlToBytes(root.payloadIv));
    return utf8Decode(plaintext);
  }

  async function encryptBoxDeterministic(runtimeConfig, plaintext, options) {
    const payloadKey = options.payloadKey;
    const payloadIv = options.iv || options.payloadIv;
    const ephemeralPrivateKey = options.ephemeralPrivateKey;
    if (!payloadKey || payloadKey.length !== 32) throw new Error("PACT box1 payload key must be 32 bytes");
    if (!payloadIv || payloadIv.length !== 12) throw new Error("PACT box1 payload IV must be 12 bytes");
    if (!ephemeralPrivateKey || ephemeralPrivateKey.length !== 32) throw new Error("PACT box1 ephemeral private key must be 32 bytes");
    if (!runtimeConfig.recipients.length) throw new Error("PACT box1 requires at least one recipient");
    const crypto = getCrypto();
    const nodeCrypto = getNodeCryptoModule();
    let ephemeralPrivate;
    let ephemeralPublicBytes;
    if (nodeCrypto) {
      ephemeralPrivate = {
        nodeKey: nodeCrypto.createPrivateKey({
          key: Buffer.concat([Buffer.from("302e020100300506032b656e04220420", "hex"), Buffer.from(ephemeralPrivateKey)]),
          format: "der",
          type: "pkcs8"
        })
      };
      ephemeralPublicBytes = new Uint8Array(
        nodeCrypto.createPublicKey(ephemeralPrivate.nodeKey).export({ format: "der", type: "spki" }).slice(-32)
      );
    } else {
      ephemeralPrivate = await crypto.subtle.importKey("raw", ephemeralPrivateKey, "X25519", true, ["deriveBits"]);
      const jwk = await crypto.subtle.exportKey("jwk", ephemeralPrivate);
      const ephemeralPublic = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: jwk.x, ext: true }, "X25519", true, []);
      ephemeralPublicBytes = await exportRawKey(ephemeralPublic);
    }
    const payloadCiphertext = await encryptAesGcm(utf8Encode(plaintext), await importAesKey(payloadKey, ["encrypt"]), payloadIv);
    const recipients = [];
    for (const recipient of runtimeConfig.recipients) {
      const derived = await deriveBoxWrap(ephemeralPrivate, await importX25519PublicKey(recipient.publicKey));
      const wrappedKey = await encryptAesGcm(payloadKey, await importAesKey(derived.wrapKey, ["encrypt"]), derived.wrapIv);
      recipients.push({ keyId: recipient.keyId, wrappedKey: bytesToBase64Url(wrappedKey) });
    }
    const payloadJson = {
      profile: "pact-box1",
      ephemeralPublicKey: bytesToBase64Url(ephemeralPublicBytes),
      payloadIv: bytesToBase64Url(payloadIv),
      recipients,
      ciphertext: bytesToBase64Url(payloadCiphertext)
    };
    return wirePrefix(runtimeConfig.messagePrefix) + applyCharRemap(bytesToBase64Url(utf8Encode(compactJson(payloadJson))), runtimeConfig.charRemap);
  }

  async function encryptBox(runtimeConfig, plaintext) {
    const crypto = getCrypto();
    const nodeCrypto = getNodeCryptoModule();
    let ephemeralPrivate;
    let ephemeralPublicBytes;
    if (nodeCrypto) {
      const pair = nodeCrypto.generateKeyPairSync("x25519");
      ephemeralPrivate = { nodeKey: pair.privateKey };
      ephemeralPublicBytes = new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }).slice(-32));
    } else {
      const ephemeral = await crypto.subtle.generateKey("X25519", true, ["deriveBits"]);
      ephemeralPrivate = ephemeral.privateKey;
      ephemeralPublicBytes = await exportRawKey(ephemeral.publicKey);
    }
    const payloadKey = randomBytes(32);
    const payloadIv = randomBytes(12);
    const payloadCiphertext = await encryptAesGcm(utf8Encode(plaintext), await importAesKey(payloadKey, ["encrypt"]), payloadIv);
    const recipients = [];
    for (const recipient of runtimeConfig.recipients) {
      const derived = await deriveBoxWrap(ephemeralPrivate, await importX25519PublicKey(recipient.publicKey));
      const wrappedKey = await encryptAesGcm(payloadKey, await importAesKey(derived.wrapKey, ["encrypt"]), derived.wrapIv);
      recipients.push({ keyId: recipient.keyId, wrappedKey: bytesToBase64Url(wrappedKey) });
    }
    const payloadJson = {
      profile: "pact-box1",
      ephemeralPublicKey: bytesToBase64Url(ephemeralPublicBytes),
      payloadIv: bytesToBase64Url(payloadIv),
      recipients,
      ciphertext: bytesToBase64Url(payloadCiphertext)
    };
    return wirePrefix(runtimeConfig.messagePrefix) + applyCharRemap(bytesToBase64Url(utf8Encode(compactJson(payloadJson))), runtimeConfig.charRemap);
  }

  function candidateTokens(text) {
    const trimmed = String(text || "").trim();
    if (!trimmed) return [];
    return Array.from(new Set([trimmed, trimmed.replace(/[.,!?)\]}'"]+$/g, "")].filter(Boolean)));
  }

  function profileId(profile) {
    if (profile === PROFILE.PACT_PSK1) return "1";
    if (profile === PROFILE.PACT_PSK2) return "2";
    if (profile === PROFILE.PACT_BOX1) return "3";
    throw new Error("Self-describing messages require a standard profile");
  }

  function profileFromId(value) {
    if (value === "1") return PROFILE.PACT_PSK1;
    if (value === "2") return PROFILE.PACT_PSK2;
    if (value === "3") return PROFILE.PACT_BOX1;
    throw new Error("Unknown profile ID: " + value);
  }

  function profilePayloadAlphabet(profile) {
    if (profile === PROFILE.PACT_PSK1) return new Set(Array.from({ length: 85 }, (_, index) => String.fromCharCode(index + 33)));
    if (profile === PROFILE.PACT_PSK2) return new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".split(""));
    return new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".split(""));
  }

  function parseRemapSpec(value, profile) {
    if (value.length % 3 !== 0) throw new Error("Compact remap spec length must be a multiple of 3");
    const remap = {};
    const destinations = new Set();
    const alphabet = profilePayloadAlphabet(profile);
    for (let index = 0; index < value.length; index += 3) {
      const sourceHex = value.slice(index, index + 2);
      const destination = value[index + 2];
      if (!/^[0-9A-F]{2}$/.test(sourceHex)) throw new Error("Malformed remap source hex");
      const source = String.fromCharCode(parseInt(sourceHex, 16));
      if (Object.prototype.hasOwnProperty.call(remap, source)) throw new Error("Duplicate remap source");
      if (destinations.has(destination)) throw new Error("Duplicate remap destination");
      if (destination === ":") throw new Error("Compact remap destination must not be ':'");
      if (!alphabet.has(source)) throw new Error("Remap source outside profile alphabet");
      remap[source] = destination;
      destinations.add(destination);
    }
    return remap;
  }

  function remapSpec(remap, profile) {
    const spec = Object.keys(remap || {})
      .sort()
      .map((source) => source.charCodeAt(0).toString(16).toUpperCase().padStart(2, "0") + remap[source])
      .join("");
    parseRemapSpec(spec, profile);
    return spec;
  }

  function parseSelfDescribing(value) {
    const parts = String(value).split(":");
    if (parts.length < 5) throw new Error("Self-describing message must contain four preamble delimiters");
    const tag = parts[0];
    const version = parts[1];
    const profilePart = parts[2];
    const remapPart = parts[3];
    const encodedPayload = parts.slice(4).join(":");
    if (tag !== "[pact]" || version !== "v1") throw new Error("Unsupported self-describing message format");
    const profile = profileFromId(profilePart);
    return {
      runtimeConfig: selfDescribingRuntimeConfig(profile, parseRemapSpec(remapPart, profile)),
      encodedPayload,
      profile,
      remap: parseRemapSpec(remapPart, profile)
    };
  }

  function selfDescribingRuntimeConfig(profile, remap) {
    if (profile === PROFILE.PACT_BOX1) {
      return attachRuntimeConfig({ messagePrefix: SYNTHETIC_MESSAGE_PREFIX, profile, charRemap: remap });
    }
    return attachRuntimeConfig({
      messagePrefix: SYNTHETIC_MESSAGE_PREFIX,
      profile,
      keyHandling: KEY_HANDLING.RAW_BASE64_KEY,
      payloadLayout: PAYLOAD_LAYOUT.PACKED,
      packedEncoding: profile === PROFILE.PACT_PSK1 ? PACKED_ENCODING.ASCII85 : PACKED_ENCODING.STANDARD_NO_PADDING,
      charRemap: remap,
      crypto: defaultCryptoFor(KEY_HANDLING.RAW_BASE64_KEY)
    });
  }

  function toSelfDescribing(ciphertext, runtimeConfig) {
    const prefix = wirePrefix(runtimeConfig.messagePrefix);
    if (!ciphertext.startsWith(prefix)) throw new Error("Unsupported payload format");
    return (
      SELF_DESCRIBING_PREFIX +
      profileId(runtimeConfig.profile) +
      ":" +
      remapSpec(runtimeConfig.charRemap, runtimeConfig.profile) +
      ":" +
      ciphertext.slice(prefix.length)
    );
  }

  async function decryptSelfDescribing(payload, secret) {
    const parsed = parseSelfDescribing(payload);
    return PactEngineFactory.create(parsed.runtimeConfig, secret).decrypt(wirePrefix(SYNTHETIC_MESSAGE_PREFIX) + parsed.encodedPayload);
  }

  const PactSelfDescribing = {
    PREFIX: SELF_DESCRIBING_PREFIX,
    isSelfDescribingMessage(value) {
      return String(value || "").trim().startsWith(SELF_DESCRIBING_PREFIX);
    },
    parse(value) {
      try {
        return parseSelfDescribing(value);
      } catch (_error) {
        return null;
      }
    },
    findMessages(text) {
      if (!String(text || "").trim()) return [];
      const results = [];
      const seen = new Set();
      for (const token of String(text).split(/\s+/)) {
        for (const candidate of candidateTokens(token)) {
          if (!seen.has(candidate) && PactSelfDescribing.parse(candidate)) {
            seen.add(candidate);
            results.push(candidate);
          }
        }
      }
      return results;
    },
    async decryptFirst(value, secrets) {
      const parsed = PactSelfDescribing.parse(String(value).trim());
      if (!parsed) return null;
      const payload = wirePrefix(SYNTHETIC_MESSAGE_PREFIX) + parsed.encodedPayload;
      const seen = new Set();
      for (const candidate of secrets || []) {
        const secret = String(candidate.secret || "").trim();
        if (!secret || seen.has(secret)) continue;
        seen.add(secret);
        try {
          return {
            plaintext: await PactEngineFactory.create(parsed.runtimeConfig, secret).decrypt(payload),
            secretId: candidate.id,
            parsed
          };
        } catch (_error) {
          continue;
        }
      }
      return null;
    },
    buildMessage(runtimeConfig, encodedPayload) {
      return SELF_DESCRIBING_PREFIX + profileId(runtimeConfig.profile) + ":" + remapSpec(runtimeConfig.charRemap, runtimeConfig.profile) + ":" + encodedPayload;
    },
    preamblePreview(runtimeConfig) {
      return PactSelfDescribing.buildMessage(runtimeConfig, "<encrypted message>");
    }
  };

  const PactSecretValidator = {
    validate(config, secret) {
      const runtimeConfig = config.normalize ? config.normalize() : attachRuntimeConfig(config);
      if (runtimeConfig.profile === PROFILE.PACT_BOX1) {
        if (!secret || !String(secret).trim()) return { isValid: true, message: null };
        try {
          if (base64UrlToBytes(secret).length !== 32) throw new Error("bad key");
          return { isValid: true, message: null };
        } catch (_error) {
          return { isValid: false, message: "X25519 private key must decode to 32 bytes" };
        }
      }
      if (!secret || !String(secret).trim()) return { isValid: false, message: "Secret cannot be blank" };
      if (runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2) return { isValid: true, message: null };
      try {
        decodeRawAesKey(secret);
        return { isValid: true, message: null };
      } catch (_error) {
        return { isValid: false, message: "Raw AES key must decode to 16 or 32 bytes" };
      }
    }
  };

  const PactSecretGenerator = {
    generateSharedSecret(config) {
      const runtimeConfig = config.normalize ? config.normalize() : attachRuntimeConfig(config);
      if (runtimeConfig.keyHandling !== KEY_HANDLING.RAW_BASE64_KEY) {
        throw new Error("Shared secret generation is only supported for raw-key profiles");
      }
      return bytesToBase64Url(randomBytes(32));
    },
    async generateKeyPair() {
      const nodeCrypto = getNodeCryptoModule();
      if (nodeCrypto) {
        const pair = nodeCrypto.generateKeyPairSync("x25519");
        return {
          publicKey: bytesToBase64Url(new Uint8Array(pair.publicKey.export({ format: "der", type: "spki" }).slice(-32))),
          privateKey: bytesToBase64Url(new Uint8Array(pair.privateKey.export({ format: "der", type: "pkcs8" }).slice(-32)))
        };
      }
      const pair = await getCrypto().subtle.generateKey("X25519", true, ["deriveBits"]);
      return {
        publicKey: bytesToBase64Url(await exportRawKey(pair.publicKey)),
        privateKey: bytesToBase64Url(await exportRawKey(pair.privateKey))
      };
    }
  };

  function createEngine(config, secret) {
    const runtimeConfig = config.normalize ? config.normalize() : attachRuntimeConfig(config);
    const validation = PactSecretValidator.validate(runtimeConfig, secret);
    if (!validation.isValid) throw new Error(validation.message || "Invalid secret");
    return {
      config: runtimeConfig,
      async encrypt(plaintext) {
        if (runtimeConfig.profile === PROFILE.PACT_BOX1) return encryptBox(runtimeConfig, plaintext);
        const iv = randomBytes(runtimeConfig.crypto.ivBytes);
        const options = { iv };
        if (runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2) options.salt = randomBytes(runtimeConfig.crypto.kdf.saltBytes);
        return defaultEncryptDeterministic(runtimeConfig, plaintext, secret || "", options);
      },
      async encryptSelfDescribing(plaintext) {
        return toSelfDescribing(await this.encrypt(plaintext), runtimeConfig);
      },
      async decrypt(payload) {
        if (runtimeConfig.profile === PROFILE.PACT_BOX1) return decryptBox(runtimeConfig, payload, secret);
        return decryptDefault(runtimeConfig, payload, secret || "");
      },
      async matchesEncryptedPayload(value) {
        try {
          if (String(value).startsWith(SELF_DESCRIBING_PREFIX)) {
            await decryptSelfDescribing(value, secret || "");
            return true;
          }
          if (runtimeConfig.profile === PROFILE.PACT_BOX1) {
            parseBoxPayload(value, wirePrefix(runtimeConfig.messagePrefix), runtimeConfig.charRemap);
            return true;
          }
          if (runtimeConfig.payloadLayout === PAYLOAD_LAYOUT.MULTIPART) {
            const parts = String(value).split(runtimeConfig.multipartSeparator);
            const expectedParts = runtimeConfig.keyHandling === KEY_HANDLING.PASSPHRASE_PBKDF2 ? 4 : 3;
            if (parts.length !== expectedParts || parts[0] !== wirePrefix(runtimeConfig.messagePrefix)) return false;
            parts.slice(1).forEach((part) => decodeSegment(part, runtimeConfig.packedEncoding, runtimeConfig.charRemap));
            return true;
          }
          const prefix = wirePrefix(runtimeConfig.messagePrefix);
          if (!String(value).startsWith(prefix) || String(value).slice(prefix.length) === "") return false;
          decodeSegment(String(value).slice(prefix.length), runtimeConfig.packedEncoding, runtimeConfig.charRemap);
          return true;
        } catch (_error) {
          return false;
        }
      },
      async findEncryptedPayloads(text) {
        if (!String(text || "").trim()) return [];
        const results = [];
        const seen = new Set();
        for (const token of String(text).split(/\s+/)) {
          for (const candidate of candidateTokens(token)) {
            if (!seen.has(candidate) && (await this.matchesEncryptedPayload(candidate))) {
              seen.add(candidate);
              results.push(candidate);
            }
          }
        }
        return results;
      }
    };
  }

  const PactEngineFactory = {
    create: createEngine,
    async encryptSelfDescribing(config, plaintext, secret) {
      return createEngine(config, secret).encryptSelfDescribing(plaintext);
    },
    async encryptDeterministic(runtimeConfig, plaintext, secret, options) {
      const runtime = attachRuntimeConfig(runtimeConfig);
      const validation = PactSecretValidator.validate(runtime, secret);
      if (!validation.isValid) throw new Error(validation.message || "Invalid secret");
      const ciphertext =
        runtime.profile === PROFILE.PACT_BOX1
          ? await encryptBoxDeterministic(runtime, plaintext, options || {})
          : await defaultEncryptDeterministic(runtime, plaintext, secret || "", options || {});
      return options && options.selfDescribing ? toSelfDescribing(ciphertext, runtime) : ciphertext;
    }
  };

  function splitAroundMatches(text, matches) {
    if (!matches.length) return [{ type: "text", value: text }];
    const sorted = matches.slice().sort((a, b) => a.start - b.start || b.end - a.end);
    const parts = [];
    let cursor = 0;
    for (const match of sorted) {
      if (match.start < cursor) continue;
      if (match.start > cursor) parts.push({ type: "text", value: text.slice(cursor, match.start) });
      parts.push({ type: "payload", value: match.value, plaintext: match.plaintext, configId: match.configId });
      cursor = match.end;
    }
    if (cursor < text.length) parts.push({ type: "text", value: text.slice(cursor) });
    return parts;
  }

  async function decryptPayload(savedConfig, payload) {
    const engine = PactEngineFactory.create(PactConfigString.parse(savedConfig.configString), String(savedConfig.secret || "").trim());
    return engine.decrypt(payload);
  }

  async function encryptPayload(savedConfig, plaintext) {
    const engine = PactEngineFactory.create(PactConfigString.parse(savedConfig.configString), String(savedConfig.secret || "").trim() || null);
    return engine.encrypt(plaintext);
  }

  async function findDecryptableMatches(savedConfig, text) {
    const parsed = PactConfigString.parse(savedConfig.configString);
    const engine = PactEngineFactory.create(parsed, String(savedConfig.secret || "").trim() || null);
    const prefix = wirePrefix(parsed.messagePrefix);
    const matches = [];
    const seen = new Set();
    const regex = new RegExp(prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\S+", "g");
    let match;
    while ((match = regex.exec(text)) !== null) {
      for (const candidate of candidateTokens(match[0])) {
        const key = match.index + ":" + candidate;
        if (seen.has(key)) continue;
        seen.add(key);
        try {
          matches.push({
            start: match.index,
            end: match.index + candidate.length,
            value: candidate,
            plaintext: await engine.decrypt(candidate),
            configId: savedConfig.id || ""
          });
          break;
        } catch (_error) {
          continue;
        }
      }
    }
    return matches;
  }

  const PactProfile = Object.freeze(Object.assign({}, PROFILE, { fromWireName: profileFromWireName, wireName: profileWireName }));
  const Pact = {
    PactConfigString,
    PactEngineFactory,
    PactKeyHandling: KEY_HANDLING,
    PactPackedEncoding: PACKED_ENCODING,
    PactPayloadLayout: PAYLOAD_LAYOUT,
    PactProfile,
    PactProtocolConfig,
    PactRuntimeConfig,
    PactSecretGenerator,
    PactSecretValidator,
    PactSelfDescribing,
    bytesToBase64Url,
    base64UrlToBytes
  };

  global.Pact = Pact;
  global.PactExtension = Object.assign(
    {
      parseConfigString: PactConfigString.parse,
      normalizeConfig: normalizeProtocolConfig,
      splitAroundMatches,
      findDecryptableMatches,
      decryptPayload,
      encryptPayload,
      bytesToBase64Url
    },
    Pact
  );
  if (typeof module !== "undefined" && module.exports) module.exports = Pact;
})(globalThis);
