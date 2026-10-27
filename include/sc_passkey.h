#pragma once

// Passkeys (WebAuthn Level 3) for a relying party: the options a browser's navigator.credentials
// create() and get() take, and the checks of what they answer, registration and authentication.
// The caller keeps the challenge (say, in its session) and the credentials (id, COSE public key,
// sign count); this does the COSE keys, signatures (OpenSSL) and every WebAuthn check, reading the
// CBOR with sc-cbor in strict mode. Ids, keys and challenges are base64url (sc::base64::encode_url).
//
//     sc::passkey::verifier rp{"1web.co.za", "1Web", {"https://*.1web.co.za"}};
//     const auto options = rp.registration_options({user_id, "roelof", "Roelof"}, {});
//     // ... options to the browser, options["challenge"] kept, the browser's answer back ...
//     const auto made = rp.verify_registration(answer_json, kept_challenge);
//
// Attestation is "none": any format is taken and its statement isn't checked. The algorithms are
// ES256 (-7), EdDSA with Ed25519 (-8) and RS256 (-257). Every failed check throws sc::passkey::error,
// whose reason() says which check.

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace sc::passkey {
    // Why a response wasn't taken: reason() is one word for code ("origin", "challenge", ...),
    // what() says it in a sentence.
    class error : public std::runtime_error {
    public:
        error(std::string reason, const std::string &message) : std::runtime_error(message), reason_(std::move(reason)) {}

        [[nodiscard]] const std::string &reason() const { return reason_; }

    private:
        std::string reason_;
    };

    // The algorithms taken, as COSE numbers, in the order the options offer them.
    enum class algorithm : int { es256 = -7, eddsa = -8, rs256 = -257 };

    // A user, as registration options name them: id is opaque bytes (at most 64), the names text.
    struct user {
        std::string id;
        std::string name;
        std::string display_name;
    };

    // A credential the browser may use or must not make again: its id (base64url), and the
    // transports it was registered with, when known ("usb", "nfc", "ble", "internal", "hybrid").
    struct descriptor {
        std::string id;
        std::vector<std::string> transports;
    };

    // A registration that was taken: what to keep.
    struct credential {
        std::string id;                      // base64url
        std::string public_key;              // the COSE key, base64url, as given back to verify_authentication
        int algorithm = 0;                   // COSE: -7, -8 or -257
        std::uint32_t sign_count = 0;
        std::string aaguid;                  // 00000000-0000-0000-0000-000000000000 when none
        std::vector<std::string> transports; // what the browser said
        std::string attachment;              // "platform", "cross-platform" or ""
        std::string attestation_format;      // "none", "packed", ... (not checked)
        bool user_verified = false;
        bool backup_eligible = false;
        bool backed_up = false;

        [[nodiscard]] nlohmann::ordered_json to_json() const;
    };

    // An authentication that was taken.
    struct assertion {
        std::string id;                         // base64url
        std::optional<std::string> user_handle; // base64url, when the authenticator gave one
        std::uint32_t sign_count = 0;           // to keep for the next one
        bool user_verified = false;
        bool backup_eligible = false;
        bool backed_up = false;

        [[nodiscard]] nlohmann::ordered_json to_json() const;
    };

    class verifier {
    public:
        // rp_id: a domain ("1web.co.za"). origins: exact ("https://www.1web.co.za") or a wildcard
        // ("https://*.1web.co.za": https only, any subdomain depth, not the bare domain); each must
        // be https (or http://localhost) with no port or path, and its host the RP ID or under it.
        // std::invalid_argument for one that isn't.
        verifier(std::string rp_id, std::string rp_name, std::vector<std::string> origins);

        // PublicKeyCredentialCreationOptionsJSON for navigator.credentials.create() (or
        // PublicKeyCredential.parseCreationOptionsFromJSON()), with a fresh 32-byte challenge
        // ("challenge", base64url) to keep for verify_registration. Resident key and user
        // verification "preferred", attestation "none".
        [[nodiscard]] nlohmann::ordered_json registration_options(const user &for_user, const std::vector<descriptor> &exclude,
                                                                  std::chrono::milliseconds timeout = std::chrono::minutes{5},
                                                                  std::string_view user_verification = "preferred") const;

        // PublicKeyCredentialRequestOptionsJSON for navigator.credentials.get(): the credentials it
        // may use (none: a discoverable one), user verification "preferred".
        [[nodiscard]] nlohmann::ordered_json authentication_options(const std::vector<descriptor> &allow,
                                                                    std::chrono::milliseconds timeout = std::chrono::minutes{5},
                                                                    std::string_view user_verification = "preferred") const;

        // The browser's RegistrationResponseJSON (PublicKeyCredential.toJSON()), checked against the
        // kept challenge (base64url). error when any check fails.
        [[nodiscard]] credential verify_registration(std::string_view response_json, std::string_view challenge,
                                                     bool require_user_verification = false) const;

        // The browser's AuthenticationResponseJSON, checked against the kept challenge and the
        // credential's kept public key (base64url COSE) and sign count. A sign count that went back
        // (both non-zero, the new one not above the kept one) is an error ("counter"): the
        // authenticator may have been cloned.
        [[nodiscard]] assertion verify_authentication(std::string_view response_json, std::string_view challenge, std::string_view public_key,
                                                      std::uint32_t sign_count, bool require_user_verification = false) const;

        // Whether an origin is one of the configured ones.
        [[nodiscard]] bool origin_allowed(std::string_view origin) const;

        [[nodiscard]] const std::string &rp_id() const { return rp_id_; }

    private:
        std::string rp_id_;
        std::string rp_name_;
        std::vector<std::string> exact_;    // full origins
        std::vector<std::string> suffixes_; // a wildcard's ".1web.co.za"
    };

    // The credential id (base64url) a response is for, to look its key up before verifying; error
    // ("format") when the JSON isn't a response.
    [[nodiscard]] std::string credential_id(std::string_view response_json);
}
