# `.vault` File Format Specification

This document specifies the on-disk/exported file format produced and consumed
by this app (`docs/index.html`), so an independent implementation — in any
language — can decrypt (and produce) files that are interoperable with it,
given the same master password.

Everything here is derived directly from the app's source (`deriveKey`,
`buildAAD`, `tryDecrypt`, `encryptVaultBlob` in `docs/index.html`) and
verified against a generated test vector (see [Test Vector](#test-vector)).

## 1. Overview

A `.vault` file is a single binary blob:

```
[ magic (4 bytes, optional) ][ salt (16 bytes) ][ iv (12 bytes) ][ ciphertext + GCM tag ]
```

- The plaintext is UTF-8 JSON (see [§5](#5-plaintext-json-schema)).
- Encryption is **AES-256-GCM**.
- The key is derived from the user's password via **PBKDF2-HMAC-SHA256**,
  using the blob's own salt, with **600,000 iterations**.
- There is no separate integrity/MAC field — GCM's built-in authentication
  tag (the last 16 bytes of the ciphertext region) serves that purpose.
  Decryption fails (throws) if the password is wrong or the data was
  tampered with.

A new implementation only needs to support **Format C** (current). Formats A
and B are documented for completeness/backward-compatibility, in case you
need to read files exported by older versions of this app.

## 2. Container Formats

The app detects which format a file is in by reading its first 4 bytes and
falling back if they don't match a known magic number. **Always write Format
C**; only read A/B if you need to import old files.

### 2.1 Format C — current (write this)

| Offset | Length | Field       |
|-------:|-------:|-------------|
| 0      | 4      | Magic: `56 4C 54 02` (ASCII `"VLT"` + `0x02`) |
| 4      | 16     | PBKDF2 salt |
| 20     | 12     | AES-GCM IV (nonce) |
| 32     | rest   | AES-GCM ciphertext, **including** the 16-byte GCM tag appended at the end |

AES-GCM **Additional Authenticated Data (AAD)** = `magic (4 bytes) || salt (16 bytes)`
(20 bytes total, bytes 0–19 of the file, concatenated). This binds the
magic+salt into the authentication tag so they can't be swapped onto a
different ciphertext undetected.

Minimum valid file size: 4 (magic) + 16 (salt) + 12 (iv) + 16 (GCM tag, empty
plaintext) = **48 bytes**.

### 2.2 Format B — legacy (read-only)

Same layout as Format C, except:
- Magic is `56 4C 54 01` instead of `...02`.
- **No AAD** is used (`crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, cipher)` — no `additionalData`).

Byte offsets are otherwise identical to Format C (salt at 4–20, iv at 20–32, cipher at 32+).

### 2.3 Format A — legacy, no magic (read-only)

No magic prefix at all. Detected only when the first 4 bytes don't match
Format C or B's magic.

| Offset | Length | Field |
|-------:|-------:|-------|
| 0      | 16     | PBKDF2 salt |
| 16     | 12     | AES-GCM IV |
| 28     | rest   | AES-GCM ciphertext (+ tag) |

No AAD (same as Format B).

### 2.4 Format detection algorithm

```
header = bytes[0:4]
if header == [0x56,0x4C,0x54,0x02]:  use Format C (salt@4, iv@20, cipher@32, AAD = magic+salt)
elif header == [0x56,0x4C,0x54,0x01]: use Format B (salt@4, iv@20, cipher@32, no AAD)
else:                                  use Format A (salt@0, iv@16, cipher@28, no AAD)
```

## 3. Key Derivation

```
key = PBKDF2-HMAC-SHA256(
    password = UTF-8 bytes of the user's password string,
    salt     = the 16-byte salt from the file,
    iterations = 600000,
    derived key length = 256 bits
)
```

The derived key is used directly as an AES-256 key (no further HKDF or
truncation). In Web Crypto terms:

```js
const raw = await crypto.subtle.importKey('raw', utf8(password), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
);
```

Equivalent in most languages: `PBKDF2(password_utf8, salt, 600000, 32, sha256)`.

## 4. Encryption / Decryption

- **Algorithm**: AES-256-GCM.
- **IV/nonce**: 12 bytes (96 bits), **must be freshly random for every
  encryption** — never reuse an IV with the same key. This app generates a
  new random salt (and therefore effectively a new key) on every export, and
  a new random IV on every save under the same key during local auto-save;
  either is sufficient, but a fresh random IV every time is the hard
  requirement for GCM safety.
- **AAD**: see [§2](#2-container-formats) per-format — Format C only.
- **Tag length**: 16 bytes (128 bits), the Web Crypto / most AES-GCM library
  default. The tag is the trailing 16 bytes of the "ciphertext" produced by
  `crypto.subtle.encrypt` (Web Crypto concatenates ciphertext + tag); most
  other libraries' AES-GCM encrypt functions do the same, or return them
  separately — concatenate tag after ciphertext if yours does.

Decryption: run AES-256-GCM decrypt with the derived key, the file's IV, the
ciphertext-with-trailing-tag, and (Format C only) the AAD. A wrong password
or corrupted/tampered data causes the GCM tag check to fail — treat any
decryption error as "wrong password or corrupted file," since there's no way
to distinguish the two.

## 5. Plaintext JSON Schema

Once decrypted, the plaintext is a UTF-8 JSON document:

```jsonc
{
  "metadata": {
    "title":     "string — vault display name",
    "version":   "string — app version that wrote the file, e.g. \"1.4.2\"",
    "timestamp": "string — ISO-8601, when this export/save was made"
  },
  "files": [
    {
      "id":        "string — UUID (random, stable per file)",
      "name":      "string — filename as shown to the user",
      "path":      "string — folder path, segments joined by '/', e.g. \"Work/2026\" (never empty — \"Root\" is the top-level default)",
      "tags":      ["string", "..."],
      "content":   "string — a `data:` URL; see §6",
      "modified":  "string — ISO-8601 timestamp",
      "size":      "number — byte size of the original file (informational; not re-validated against `content`)",
      "favorite":  "boolean — starred/favorited",
      "trashed":   "boolean — soft-deleted (in the Recycle Bin)",
      "trashedAt": "string (ISO-8601) or null — when it was trashed"
    }
  ]
}
```

### Field notes for a compatible reader/writer

These mirror `sanitiseEntry()`/`isValidFileEntry()` in the app, which is
deliberately forgiving on **import** so older/foreign files still load. A new
implementation reading vaults produced by this app can rely on all fields
being present and well-typed as described above. If *your* app will also
import files this app might read, consider applying the same defaults:

| Field | If missing/invalid on import, default to |
|---|---|
| `id` | a freshly generated UUID |
| `path` | normalise (trim, drop empty segments, join with `/`); empty → `"Root"` |
| `tags` | `[]`; non-string entries are dropped |
| `modified` | current timestamp |
| `size` | `0` |
| `favorite` | `false` |
| `trashed` | `false` |
| `trashedAt` | `null` |

An entry is considered invalid (and skipped entirely) if `name` is missing/
blank, `content` isn't a string, or `content` doesn't start with `"data:"`.

### `metadata.title`

Free text; treat as untrusted display data (don't interpret as HTML/code).

## 6. File Content Encoding

Each file's bytes are stored as a [data URL](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/data) string:

```
data:<mime-type>;base64,<base64-encoded-file-bytes>
```

e.g. `data:text/plain;base64,SGVsbG8sIHZhdWx0IQ==`

To recover the original file bytes: take the substring after the first `,`,
base64-decode it. The MIME type before `;base64` is informational (derived
from the browser's `FileReader.readAsDataURL()` at import time) — don't rely
on it for anything security-sensitive.

## 7. Size Limits (app-specific, not a protocol requirement)

These are UI-level guardrails this app enforces when *adding* files, not
something a decoder must replicate:

- Per-file: 50 MB (`MAX_FILE_BYTES`)
- Total vault: 100 MB (`MAX_VAULT_BYTES`, sum of all `files[].size`, trashed
  files included since they still count against local storage until
  permanently deleted)

## 8. Test Vector

Generated and round-tripped with Node's `crypto.webcrypto` (not this app's
own code — an independent implementation of the spec above), confirming the
spec is self-consistent and implementable from scratch.

**Inputs:**
- Password: `correct horse battery staple`
- Salt (hex, 16 bytes): `000102030405060708090a0b0c0d0e0f`
- IV (hex, 12 bytes): `101112131415161718191a1b`
- Plaintext JSON:
  ```json
  {"metadata":{"title":"Spec Test Vault","version":"1.4.2","timestamp":"2026-01-01T00:00:00.000Z"},"files":[{"id":"11111111-1111-4111-8111-111111111111","name":"hello.txt","path":"Docs","tags":["example"],"content":"data:text/plain;base64,SGVsbG8sIHZhdWx0IQ==","modified":"2026-01-01T00:00:00.000Z","size":13,"favorite":false,"trashed":false,"trashedAt":null}]}
  ```

**Output — full file (Format C), base64:**

```
VkxUAgABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGht3MBCgZJ7MFr/bu/K30QCTZVT/xrxFhdumUzu+rco0z8ii+oWAw9oOunLRJc+VYmZ7Oghw+nRTSD2090qW6hqrScRdjx/lRscpMSHPfs6Mr6yyb1ZTjVFNK88IpsUf5R+co4gfYxjJb9wNYUI9abYC8bXqsfQ+Rsi+juJDKwlZ87pla7b/iwaYpMdWZ/IUzibx5ECMqyl2f1t5BwLnUOd2KvFIr+HrXMKufcjxNhu7ZZXZXFoQbo6tX9/r100Vo5kOEM03oBZ56XH/HJ7u/yOZ1aI3SMAEi0qCtIz2oo7O//M5WbNfo8A+I3cN68SzyAVrI9vvSyp+Lsh2c/8iqRvAiygJyNSoYUPpgPESvo4BR2+S6mmFm4g/K41SJ0lhq2GCycoGd8ifTGyVpRiQf4xHsJlYpn891xYxlFEyxgV0QmRhRo1s7eoSuWL5PdHZKcUnCUIr28u0wVgXpDaVJj8POlxjdBBiDr1TaR4oEVXRfp5yLAtMvZo=
```

(407 bytes total: 4 magic + 16 salt + 12 iv + 375 ciphertext-with-tag.)

To self-check an implementation: base64-decode the above, split per §2.1,
derive the key per §3 with the given password and salt, AES-GCM-decrypt with
the given IV and AAD = `564c5402` ++ salt, and confirm the plaintext JSON
matches exactly.

## 9. Writing a Compatible `.vault` File (for your new app)

1. Generate a random 16-byte salt and a random 12-byte IV (use a CSPRNG).
2. Derive the key per §3 from the user's password and that salt.
3. Build the plaintext JSON per §5 (at minimum, `metadata.title` /
   `.version` / `.timestamp` and a `files` array — this app does not
   require any particular `version` string to open a file).
4. AES-256-GCM encrypt the plaintext with AAD = `56 4C 54 02` ++ salt.
5. Write: magic (`56 4C 54 02`) ++ salt ++ iv ++ ciphertext-with-tag.
6. Give the file a `.vault` extension (filename itself isn't parsed/relied
   on by the format — this app names exports
   `<app>-<version>-<UTC timestamp, YYYYMMDDTHHMMZ>.vault`, but any name
   works for import).

## 10. Security Notes

- **Never reuse an IV with the same key.** This app always pairs a fresh
  random salt with a fresh random IV on export, and a fresh random IV (same
  salt/key) on each local auto-save — either approach keeps (key, IV) pairs
  unique, which is the actual GCM requirement.
- 600,000 PBKDF2-SHA256 iterations is deliberately slow (by design, to resist
  offline brute-force) — expect ~100–500ms per derivation depending on
  hardware. Cache the derived key per (password, salt) pair within a session
  rather than re-deriving on every operation.
- There is no password-strength enforcement baked into the format — any
  non-empty password string works. The app's own UI nudges users toward
  stronger passwords but doesn't encode that choice into the file.
- Treat every string field decoded from a vault (`metadata.title`, file
  `name`, `path`, `tags`) as untrusted display text, not code/markup.
