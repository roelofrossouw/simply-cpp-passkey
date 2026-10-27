# simply-cpp-passkey

`sc-passkey` is the relying party's side of passkeys
([WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/)): the options a browser's
`navigator.credentials.create()` and `get()` take, and every check of what they answer.
The caller keeps the challenge and the credentials; this does the COSE keys and signatures
(OpenSSL) and the checks, reading the CBOR with
[sc-cbor](https://github.com/roelofrossouw/simply-cpp-cbor) in strict mode.
`js/sc-passkey.js` is the browser's side.

**Documentation:** the [simply-cpp wiki](https://github.com/roelofrossouw/simply-cpp/wiki) has the [sc-passkey reference](https://github.com/roelofrossouw/simply-cpp/wiki/Reference-sc-passkey).

```cpp
#include <sc_passkey.h>

const sc::passkey::verifier rp{"1web.co.za", "1Web", {"https://*.1web.co.za"}};

// Registration: options to the browser, its challenge kept; the answer checked.
const auto options = rp.registration_options({user_id, "roelof", "Roelof"}, already_registered);
const auto made = rp.verify_registration(answer_json, kept_challenge);
made.id, made.public_key, made.sign_count;      // to keep (base64url), with made.aaguid, ...

// Authentication: the credentials it may use, then the answer against the kept key.
const auto asked = rp.authentication_options({{made.id, made.transports}});
const auto used = rp.verify_authentication(answer_json, kept_challenge, made.public_key, made.sign_count);
used.sign_count;                                // keep it for the next one

// Every failed check: sc::passkey::error, reason() "origin", "challenge", "signature", ...
```

| Type | | |
|---|---|---|
| `sc::passkey::verifier` | `registration_options()`, `authentication_options()`, `verify_registration()`, `verify_authentication()`, `origin_allowed()`, `rp_id()` | one relying party |
| `sc::passkey::credential` | `id`, `public_key`, `algorithm`, `sign_count`, `aaguid`, `transports`, `attachment`, `attestation_format`, `user_verified`, `backup_eligible`, `backed_up`; `to_json()` | a registration taken |
| `sc::passkey::assertion` | `id`, `user_handle`, `sign_count`, `user_verified`, `backup_eligible`, `backed_up`; `to_json()` | an authentication taken |
| `sc::passkey::user`, `descriptor` | `id`, `name`, `display_name`; `id`, `transports` | |
| `sc::passkey::error` | `reason()`, `what()` | a check that failed |
| `credential_id(json)` | | a response's credential id, to look its key up |

- **Origins** are exact (`https://www.1web.co.za`) or a wildcard (`https://*.1web.co.za`:
  https, any subdomain depth, not the bare domain), each the RP ID or under it; no ports.
- **Algorithms:** ES256 (-7), EdDSA with Ed25519 (-8) and RS256 (-257, 2048 bits at
  least), offered in that order.
- **Attestation** is "none": any format is taken and its statement isn't checked; the
  AAGUID is returned as a UUID.
- **The checks:** the response's shape and type, id and rawId the same, clientDataJSON's
  type, the challenge (constant time), the origin, no `crossOrigin` or `topOrigin`, the RP ID
  hash, user presence, user verification when asked for, BE/BS consistency, attested
  credential data at registration (the credential id the same as rawId), the authenticator
  data's exact length, the COSE key (a valid point or key), the signature, and the sign
  count: both non-zero and not above the kept one is `"counter"` (0 and 0 is what synced
  passkeys send).
- Reasons: `format`, `type`, `credential`, `challenge`, `origin`, `cross_origin`, `rp_id`,
  `user_presence`, `user_verification`, `flags`, `algorithm`, `key`, `signature`, `counter`.
  A kept challenge or key that isn't base64url is the caller's mistake:
  `std::invalid_argument`.

The tests run WebAuthn Level 3's own test vectors (ES256, RS256 and Ed25519 with each
attestation format; those for ES384, ES512, Ed448 and cross-origin frames refused), round
trips with a software authenticator for each algorithm, every check failing on its own, and
a fuzz run of mutated responses.

## Building

OpenSSL 3 comes from the system (`libssl-dev` on Ubuntu, `openssl` in Homebrew).
`scripts/install.sh` builds, tests and installs the module; `sc-passkey-demo` prints
registration options, or checks a saved response.

## License

Apache License 2.0 (see `LICENSE` and `NOTICE`). OpenSSL is Apache-2.0, linked
dynamically from the system.
