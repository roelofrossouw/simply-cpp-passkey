#include "sc_passkey.h"

#include <base64.h>
#include <sc_cbor.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <memory>

namespace sc::passkey {
    namespace {
        // What a response may be at most, before anything is parsed.
        constexpr std::size_t response_limit = 256 * 1024;
        constexpr std::size_t challenge_size = 32;
        constexpr std::size_t credential_id_limit = 1023;

        // Authenticator data's flags.
        constexpr std::uint8_t flag_up = 0x01, flag_uv = 0x04, flag_be = 0x08, flag_bs = 0x10, flag_at = 0x40, flag_ed = 0x80;

        [[noreturn]] void fail(const char *reason, const std::string &message) { throw error(reason, message); }

        std::string encode_url(const std::string_view bytes) { return base64::encode_url(bytes); }

        // Base64url from a response: error ("format") when it isn't.
        std::string decode_url(const std::string_view text, const std::string &what) {
            try {
                return base64::decode_url(text);
            } catch (const std::runtime_error &) {
                throw error("format", what + " isn't base64url");
            }
        }

        // --- OpenSSL

        struct pkey_free {
            void operator()(EVP_PKEY *key) const { EVP_PKEY_free(key); }
        };
        using pkey = std::unique_ptr<EVP_PKEY, pkey_free>;

        std::string sha256(const std::string_view data) {
            std::string out(32, '\0');
            unsigned int length = 0;
            if (EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char *>(out.data()), &length, EVP_sha256(), nullptr) != 1 || length != 32)
                throw std::runtime_error("passkey: SHA-256 failed");
            return out;
        }

        bool same_bytes(const std::string_view a, const std::string_view b) {
            return a.size() == b.size() && CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
        }

        std::string random_bytes(const std::size_t size) {
            std::string out(size, '\0');
            if (RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(size)) != 1) throw std::runtime_error("passkey: no random bytes");
            return out;
        }

        // A key from parameters (EC, RSA), checked to be a valid public key.
        pkey from_parameters(const char *type, OSSL_PARAM_BLD *build) {
            std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)> parameters{OSSL_PARAM_BLD_to_param(build), &OSSL_PARAM_free};
            OSSL_PARAM_BLD_free(build);
            if (!parameters) fail("key", "the credential's public key couldn't be read");
            std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> context{EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr), &EVP_PKEY_CTX_free};
            EVP_PKEY *made = nullptr;
            if (!context || EVP_PKEY_fromdata_init(context.get()) != 1 || EVP_PKEY_fromdata(context.get(), &made, EVP_PKEY_PUBLIC_KEY, parameters.get()) != 1)
                fail("key", "the credential's public key isn't a valid key");
            pkey out{made};
            std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> check{EVP_PKEY_CTX_new_from_pkey(nullptr, out.get(), nullptr), &EVP_PKEY_CTX_free};
            if (!check || EVP_PKEY_public_check(check.get()) != 1) fail("key", "the credential's public key isn't a valid key");
            return out;
        }

        const std::string &key_bytes(const cbor::value &key, const std::int64_t label, const char *what) {
            const auto *found = key.find(cbor::value{label});
            if (!found || !found->is_bytes()) fail("key", std::string{"the credential's public key has no "} + what);
            return found->byte_string();
        }

        std::int64_t key_integer(const cbor::value &key, const std::int64_t label, const char *what) {
            const auto *found = key.find(cbor::value{label});
            if (!found || !found->is_integer() || found->argument() > 0x7fffffff) fail("key", std::string{"the credential's public key has no "} + what);
            return found->integer();
        }

        // A COSE key (RFC 9053) as OpenSSL's, with its algorithm: EC2 P-256 with ES256, OKP Ed25519
        // with EdDSA, RSA (2048 bits at least) with RS256.
        pkey key_of(const cbor::value &key, int &alg) {
            if (!key.is_map()) fail("key", "the credential's public key isn't a COSE key");
            const auto kty = key_integer(key, 1, "key type");
            alg = static_cast<int>(key_integer(key, 3, "algorithm"));
            if (alg != static_cast<int>(algorithm::es256) && alg != static_cast<int>(algorithm::eddsa) && alg != static_cast<int>(algorithm::rs256))
                fail("algorithm", "the credential's algorithm " + std::to_string(alg) + " isn't taken (ES256, EdDSA and RS256 are)");
            if (alg == static_cast<int>(algorithm::es256)) {
                if (kty != 2 || key_integer(key, -1, "curve") != 1) fail("key", "an ES256 key that isn't an EC2 P-256 key");
                const auto &x = key_bytes(key, -2, "x"), &y = key_bytes(key, -3, "y");
                if (x.size() != 32 || y.size() != 32) fail("key", "a P-256 key whose coordinates aren't 32 bytes");
                const auto point = std::string{"\x04"} + x + y;
                auto *build = OSSL_PARAM_BLD_new();
                if (!build || OSSL_PARAM_BLD_push_utf8_string(build, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) != 1 ||
                    OSSL_PARAM_BLD_push_octet_string(build, OSSL_PKEY_PARAM_PUB_KEY, point.data(), point.size()) != 1) {
                    OSSL_PARAM_BLD_free(build);
                    fail("key", "the credential's public key couldn't be read");
                }
                return from_parameters("EC", build);
            }
            if (alg == static_cast<int>(algorithm::eddsa)) {
                if (kty != 1 || key_integer(key, -1, "curve") != 6) fail("key", "an EdDSA key that isn't an OKP Ed25519 key");
                const auto &x = key_bytes(key, -2, "x");
                if (x.size() != 32) fail("key", "an Ed25519 key that isn't 32 bytes");
                pkey out{EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, reinterpret_cast<const unsigned char *>(x.data()), x.size())};
                if (!out) fail("key", "the credential's public key isn't a valid key");
                return out;
            }
            if (kty != 3) fail("key", "an RS256 key that isn't an RSA key");
            const auto &n = key_bytes(key, -1, "modulus"), &e = key_bytes(key, -2, "exponent");
            if (n.size() < 256 || n.size() > 1024 || static_cast<unsigned char>(n.front()) == 0) fail("key", "an RSA modulus that isn't 2048 to 8192 bits");
            if (e.empty() || e.size() > 8) fail("key", "an RSA exponent that isn't 1 to 8 bytes");
            std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_n{BN_bin2bn(reinterpret_cast<const unsigned char *>(n.data()), static_cast<int>(n.size()), nullptr), &BN_free};
            std::unique_ptr<BIGNUM, decltype(&BN_free)> bn_e{BN_bin2bn(reinterpret_cast<const unsigned char *>(e.data()), static_cast<int>(e.size()), nullptr), &BN_free};
            auto *build = OSSL_PARAM_BLD_new();
            if (!bn_n || !bn_e || !build || OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_N, bn_n.get()) != 1 ||
                OSSL_PARAM_BLD_push_BN(build, OSSL_PKEY_PARAM_RSA_E, bn_e.get()) != 1) {
                OSSL_PARAM_BLD_free(build);
                fail("key", "the credential's public key couldn't be read");
            }
            return from_parameters("RSA", build);
        }

        bool signature_holds(EVP_PKEY *key, const int alg, const std::string_view data, const std::string_view signature) {
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
            if (!context) throw std::runtime_error("passkey: no digest context");
            const EVP_MD *digest = alg == static_cast<int>(algorithm::eddsa) ? nullptr : EVP_sha256();
            if (EVP_DigestVerifyInit(context.get(), nullptr, digest, nullptr, key) != 1) return false;
            return EVP_DigestVerify(context.get(), reinterpret_cast<const unsigned char *>(signature.data()), signature.size(),
                                    reinterpret_cast<const unsigned char *>(data.data()), data.size()) == 1;
        }

        // --- JSON

        nlohmann::json parse_json(const std::string_view text, const char *what) {
            if (text.size() > response_limit) fail("format", std::string{what} + " is larger than " + std::to_string(response_limit) + " bytes");
            auto out = nlohmann::json::parse(text, nullptr, false);
            if (out.is_discarded() || !out.is_object()) fail("format", std::string{what} + " isn't a JSON object");
            return out;
        }

        const nlohmann::json *member(const nlohmann::json &object, const char *key) {
            const auto found = object.find(key);
            return found == object.end() || found->is_null() ? nullptr : &*found;
        }

        std::string text_of(const nlohmann::json &object, const char *key, const char *what) {
            const auto *found = member(object, key);
            if (!found || !found->is_string()) fail("format", std::string{what} + " has no " + key);
            return found->get<std::string>();
        }

        std::string bytes_of(const nlohmann::json &object, const char *key, const char *what) {
            const auto text = text_of(object, key, what);
            return decode_url(text, std::string{what} + "'s " + key);
        }

        // The parts every response has: its id (checked against rawId), and response.
        struct response_parts {
            std::string id;     // base64url, as given
            std::string raw_id; // bytes
            nlohmann::json body;
            nlohmann::json response;
        };

        response_parts parts_of(const std::string_view json) {
            response_parts out;
            out.body = parse_json(json, "the response");
            out.id = text_of(out.body, "id", "the response");
            out.raw_id = bytes_of(out.body, "rawId", "the response");
            if (out.raw_id.empty() || out.raw_id.size() > credential_id_limit) fail("credential", "a credential id that isn't 1 to 1023 bytes");
            if (decode_url(out.id, "the response's id") != out.raw_id) fail("credential", "the response's id and rawId differ");
            if (text_of(out.body, "type", "the response") != "public-key") fail("type", "the response isn't a public-key credential");
            const auto *response = member(out.body, "response");
            if (!response || !response->is_object()) fail("format", "the response has no response object");
            out.response = *response;
            return out;
        }

        // --- authenticator data

        struct authenticator_data {
            std::string rp_id_hash;
            std::uint8_t flags = 0;
            std::uint32_t sign_count = 0;
            std::string aaguid;            // 16 bytes, with attested credential data
            std::string credential_id;     // bytes
            std::string public_key;        // the COSE key's own bytes
            std::optional<cbor::value> key;
        };

        authenticator_data read_authenticator_data(const std::string_view data) {
            if (data.size() < 37) fail("format", "authenticator data shorter than 37 bytes");
            authenticator_data out;
            out.rp_id_hash = std::string{data.substr(0, 32)};
            out.flags = static_cast<std::uint8_t>(data[32]);
            for (int i = 0; i < 4; ++i) out.sign_count = out.sign_count << 8 | static_cast<std::uint8_t>(data[33 + i]);
            std::size_t at = 37;
            auto limit = cbor::decode_options::strict();
            limit.max_depth = 8;
            limit.max_items = 256;
            limit.max_length = 4096;
            try {
                if (out.flags & flag_at) {
                    if (data.size() < at + 18) fail("format", "attested credential data cut short");
                    out.aaguid = std::string{data.substr(at, 16)};
                    const auto length = static_cast<std::size_t>(static_cast<std::uint8_t>(data[at + 16]) << 8 | static_cast<std::uint8_t>(data[at + 17]));
                    at += 18;
                    if (length == 0 || length > credential_id_limit) fail("credential", "a credential id that isn't 1 to 1023 bytes");
                    if (data.size() - at < length) fail("format", "attested credential data cut short");
                    out.credential_id = std::string{data.substr(at, length)};
                    at += length;
                    std::size_t used = 0;
                    out.key = cbor::decode_prefix(data.substr(at), used, limit);
                    out.public_key = std::string{data.substr(at, used)};
                    at += used;
                }
                if (out.flags & flag_ed) {
                    std::size_t used = 0;
                    const auto extensions = cbor::decode_prefix(data.substr(at), used, limit);
                    if (!extensions.is_map()) fail("format", "authenticator extensions that aren't a map");
                    at += used;
                }
            } catch (const cbor::error &problem) {
                fail("format", std::string{"authenticator data: "} + problem.what());
            }
            if (at != data.size()) fail("format", "authenticator data has " + std::to_string(data.size() - at) + " bytes after its end");
            return out;
        }

        // --- origins

        bool host_text(const std::string_view host) {
            if (host.empty() || host.front() == '.' || host.back() == '.' || host.find("..") != std::string_view::npos) return false;
            return std::ranges::all_of(host, [](const char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.'; });
        }

        bool under(const std::string_view host, const std::string_view rp_id) {
            return host == rp_id || (host.size() > rp_id.size() && host.ends_with(rp_id) && host[host.size() - rp_id.size() - 1] == '.');
        }

        nlohmann::ordered_json descriptors(const std::vector<descriptor> &list) {
            auto out = nlohmann::ordered_json::array();
            for (const auto &each: list) {
                nlohmann::ordered_json item{{"type", "public-key"}, {"id", each.id}};
                if (!each.transports.empty()) item["transports"] = each.transports;
                out.push_back(std::move(item));
            }
            return out;
        }

        std::string uuid_of(const std::string_view bytes) {
            static constexpr char hex[] = "0123456789abcdef";
            std::string out;
            for (std::size_t i = 0; i < bytes.size(); ++i) {
                if (i == 4 || i == 6 || i == 8 || i == 10) out += '-';
                out += hex[static_cast<std::uint8_t>(bytes[i]) >> 4];
                out += hex[static_cast<std::uint8_t>(bytes[i]) & 0xf];
            }
            return out;
        }
    }

    nlohmann::ordered_json credential::to_json() const {
        return {{"id", id},
                {"publicKey", public_key},
                {"algorithm", algorithm},
                {"signCount", sign_count},
                {"aaguid", aaguid},
                {"transports", transports},
                {"attachment", attachment},
                {"attestationFormat", attestation_format},
                {"userVerified", user_verified},
                {"backupEligible", backup_eligible},
                {"backedUp", backed_up}};
    }

    nlohmann::ordered_json assertion::to_json() const {
        return {{"id", id},
                {"userHandle", user_handle ? nlohmann::ordered_json(*user_handle) : nlohmann::ordered_json(nullptr)},
                {"signCount", sign_count},
                {"userVerified", user_verified},
                {"backupEligible", backup_eligible},
                {"backedUp", backed_up}};
    }

    verifier::verifier(std::string rp_id, std::string rp_name, std::vector<std::string> origins) : rp_id_(std::move(rp_id)), rp_name_(std::move(rp_name)) {
        if (!host_text(rp_id_)) throw std::invalid_argument("passkey: the RP ID \"" + rp_id_ + "\" isn't a domain (lower case, no scheme or port)");
        if (origins.empty()) throw std::invalid_argument("passkey: no origins given");
        for (const auto &origin: origins) {
            const bool local = rp_id_ == "localhost" && origin == "http://localhost";
            if (!origin.starts_with("https://") && !local) throw std::invalid_argument("passkey: the origin \"" + origin + "\" isn't https");
            if (local) {
                exact_.push_back(origin);
                continue;
            }
            const auto host = std::string_view{origin}.substr(8);
            if (host.starts_with("*.")) {
                const auto suffix = host.substr(2);
                if (!host_text(suffix) || !under(suffix, rp_id_))
                    throw std::invalid_argument("passkey: the origin \"" + origin + "\" isn't a wildcard under the RP ID " + rp_id_);
                suffixes_.push_back("." + std::string{suffix});
                continue;
            }
            if (!host_text(host) || !under(host, rp_id_))
                throw std::invalid_argument("passkey: the origin \"" + origin + "\" isn't https://<host> with the host the RP ID " + rp_id_ + " or under it");
            exact_.push_back(origin);
        }
    }

    bool verifier::origin_allowed(const std::string_view origin) const {
        if (std::ranges::find(exact_, origin) != exact_.end()) return true;
        if (!origin.starts_with("https://")) return false;
        const auto host = origin.substr(8);
        if (!host_text(host)) return false;
        return std::ranges::any_of(suffixes_, [&](const std::string &suffix) { return host.size() > suffix.size() && host.ends_with(suffix); });
    }

    nlohmann::ordered_json verifier::registration_options(const user &for_user, const std::vector<descriptor> &exclude, const std::chrono::milliseconds timeout,
                                                          const std::string_view user_verification) const {
        if (for_user.id.empty() || for_user.id.size() > 64) throw std::invalid_argument("passkey: a user id must be 1 to 64 bytes");
        if (for_user.name.empty()) throw std::invalid_argument("passkey: a user needs a name");
        auto params = nlohmann::ordered_json::array();
        for (const auto alg: {algorithm::es256, algorithm::eddsa, algorithm::rs256}) params.push_back({{"type", "public-key"}, {"alg", static_cast<int>(alg)}});
        return {{"rp", {{"id", rp_id_}, {"name", rp_name_}}},
                {"user", {{"id", encode_url(for_user.id)}, {"name", for_user.name}, {"displayName", for_user.display_name.empty() ? for_user.name : for_user.display_name}}},
                {"challenge", encode_url(random_bytes(challenge_size))},
                {"pubKeyCredParams", params},
                {"timeout", timeout.count()},
                {"excludeCredentials", descriptors(exclude)},
                {"authenticatorSelection", {{"residentKey", "preferred"}, {"requireResidentKey", false}, {"userVerification", user_verification}}},
                {"attestation", "none"}};
    }

    nlohmann::ordered_json verifier::authentication_options(const std::vector<descriptor> &allow, const std::chrono::milliseconds timeout,
                                                            const std::string_view user_verification) const {
        return {{"challenge", encode_url(random_bytes(challenge_size))},
                {"timeout", timeout.count()},
                {"rpId", rp_id_},
                {"allowCredentials", descriptors(allow)},
                {"userVerification", user_verification}};
    }

    namespace {
        // clientDataJSON's checks: its type, the challenge (constant time), the origin, not
        // cross-origin. The bytes as they came, for the hash.
        std::string check_client_data(const verifier &rp, const nlohmann::json &response, const char *type, const std::string_view challenge) {
            const auto bytes = bytes_of(response, "clientDataJSON", "the response");
            const auto client = parse_json(bytes, "clientDataJSON");
            if (text_of(client, "type", "clientDataJSON") != type) fail("type", std::string{"clientDataJSON's type isn't "} + type);
            std::string kept, given;
            try {
                kept = base64::decode_url(challenge);
            } catch (const std::runtime_error &) {
                throw std::invalid_argument("passkey: the kept challenge isn't base64url");
            }
            try {
                given = base64::decode_url(text_of(client, "challenge", "clientDataJSON"));
            } catch (const std::runtime_error &) {
                fail("challenge", "clientDataJSON's challenge isn't base64url");
            }
            if (kept.empty() || !same_bytes(kept, given)) fail("challenge", "the challenge isn't the one given");
            const auto origin = text_of(client, "origin", "clientDataJSON");
            if (!rp.origin_allowed(origin)) fail("origin", "the origin " + origin + " isn't one of the relying party's");
            if (const auto *cross = member(client, "crossOrigin"); cross && cross->is_boolean() && cross->get<bool>())
                fail("cross_origin", "the credential was used from a cross-origin frame");
            if (member(client, "topOrigin")) fail("cross_origin", "the credential was used from another site's frame");
            return bytes;
        }

        void check_flags(const verifier &rp, const authenticator_data &data, const bool require_user_verification) {
            if (!same_bytes(data.rp_id_hash, sha256(rp.rp_id()))) fail("rp_id", "the authenticator data isn't for the RP ID " + rp.rp_id());
            if (!(data.flags & flag_up)) fail("user_presence", "the user wasn't present (UP not set)");
            if (require_user_verification && !(data.flags & flag_uv)) fail("user_verification", "the user wasn't verified (UV not set)");
            if ((data.flags & flag_bs) && !(data.flags & flag_be)) fail("flags", "backed up (BS) without being eligible for it (BE)");
        }
    }

    credential verifier::verify_registration(const std::string_view response_json, const std::string_view challenge, const bool require_user_verification) const {
        const auto parts = parts_of(response_json);
        (void) check_client_data(*this, parts.response, "webauthn.create", challenge);

        cbor::value attestation;
        try {
            // The attestation statement may hold certificates (x5c): larger strings than the strict default.
            auto limit = cbor::decode_options::strict();
            limit.max_length = 32768;
            attestation = cbor::decode(bytes_of(parts.response, "attestationObject", "the response"), limit);
        } catch (const cbor::error &problem) {
            fail("format", std::string{"the attestation object: "} + problem.what());
        }
        const auto *format = attestation.find("fmt");
        const auto *statement = attestation.find("attStmt");
        const auto *auth_data = attestation.find("authData");
        if (!attestation.is_map() || !format || !format->is_text() || !statement || !statement->is_map() || !auth_data || !auth_data->is_bytes())
            fail("format", "the attestation object isn't {fmt, attStmt, authData}");

        const auto data = read_authenticator_data(auth_data->byte_string());
        check_flags(*this, data, require_user_verification);
        if (!(data.flags & flag_at) || !data.key) fail("format", "the authenticator data has no attested credential data");
        if (data.credential_id != parts.raw_id) fail("credential", "the authenticator data is for another credential id");
        int alg = 0;
        (void) key_of(*data.key, alg);

        credential out;
        out.id = encode_url(parts.raw_id);
        out.public_key = encode_url(data.public_key);
        out.algorithm = alg;
        out.sign_count = data.sign_count;
        out.aaguid = uuid_of(data.aaguid);
        out.attestation_format = format->text();
        out.user_verified = data.flags & flag_uv;
        out.backup_eligible = data.flags & flag_be;
        out.backed_up = data.flags & flag_bs;
        if (const auto *transports = member(parts.response, "transports"); transports && transports->is_array())
            for (const auto &each: *transports)
                if (each.is_string() && each.get<std::string>().size() <= 32 && out.transports.size() < 8) out.transports.push_back(each.get<std::string>());
        if (const auto *attachment = member(parts.body, "authenticatorAttachment"); attachment && attachment->is_string()) {
            const auto text = attachment->get<std::string>();
            if (text == "platform" || text == "cross-platform") out.attachment = text;
        }
        return out;
    }

    assertion verifier::verify_authentication(const std::string_view response_json, const std::string_view challenge, const std::string_view public_key,
                                              const std::uint32_t sign_count, const bool require_user_verification) const {
        const auto parts = parts_of(response_json);
        const auto client_data = check_client_data(*this, parts.response, "webauthn.get", challenge);
        const auto data_bytes = bytes_of(parts.response, "authenticatorData", "the response");
        const auto signature = bytes_of(parts.response, "signature", "the response");
        if (signature.empty() || signature.size() > 1024) fail("signature", "a signature that isn't 1 to 1024 bytes");

        const auto data = read_authenticator_data(data_bytes);
        check_flags(*this, data, require_user_verification);
        if (data.flags & flag_at) fail("format", "attested credential data in an assertion");

        cbor::value key;
        try {
            auto limit = cbor::decode_options::strict();
            limit.max_depth = 4;
            limit.max_items = 32;
            limit.max_length = 2048;
            key = cbor::decode(base64::decode_url(public_key), limit);
        } catch (const cbor::error &problem) {
            throw std::invalid_argument(std::string{"passkey: the kept public key isn't a COSE key: "} + problem.what());
        } catch (const std::runtime_error &) {
            throw std::invalid_argument("passkey: the kept public key isn't base64url");
        }
        int alg = 0;
        const auto checked = key_of(key, alg);
        if (!signature_holds(checked.get(), alg, data_bytes + sha256(client_data), signature)) fail("signature", "the signature doesn't hold");

        if (data.sign_count != 0 && sign_count != 0 && data.sign_count <= sign_count)
            fail("counter", "the sign count went from " + std::to_string(sign_count) + " to " + std::to_string(data.sign_count) +
                                ": the authenticator may have been cloned");

        assertion out;
        out.id = encode_url(parts.raw_id);
        if (const auto *handle = member(parts.response, "userHandle"); handle && handle->is_string() && !handle->get<std::string>().empty()) {
            out.user_handle = encode_url(decode_url(handle->get<std::string>(), "the response's userHandle"));
        }
        out.sign_count = data.sign_count;
        out.user_verified = data.flags & flag_uv;
        out.backup_eligible = data.flags & flag_be;
        out.backed_up = data.flags & flag_bs;
        return out;
    }

    std::string credential_id(const std::string_view response_json) {
        const auto body = parse_json(response_json, "the response");
        const auto raw = bytes_of(body, "rawId", "the response");
        if (raw.empty() || raw.size() > credential_id_limit) fail("credential", "a credential id that isn't 1 to 1023 bytes");
        return encode_url(raw);
    }
}
