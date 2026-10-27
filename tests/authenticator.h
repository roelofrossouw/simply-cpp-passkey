#pragma once

// A software authenticator for the tests: a key pair of each algorithm (OpenSSL), and the responses
// a browser would give for it, as RegistrationResponseJSON and AuthenticationResponseJSON. Each
// part can be changed before it's put together, for the cases that must fail.

#include <base64.h>
#include <sc_cbor.h>
#include <sc_passkey.h>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>
#include <stdexcept>
#include <string>

namespace test {
    using sc::cbor::value;

    inline std::string base64url_encode(const std::string_view bytes) { return sc::base64::encode_url(bytes); }

    inline std::string sha256(const std::string &data) {
        std::string out(32, '\0');
        unsigned int length = 0;
        EVP_Digest(data.data(), data.size(), reinterpret_cast<unsigned char *>(out.data()), &length, EVP_sha256(), nullptr);
        return out;
    }

    inline std::string bignum_bytes(const EVP_PKEY *key, const char *name, const std::size_t size = 0) {
        BIGNUM *number = nullptr;
        if (EVP_PKEY_get_bn_param(key, name, &number) != 1) throw std::runtime_error("no key parameter");
        std::string out(size ? size : static_cast<std::size_t>(BN_num_bytes(number)), '\0');
        if (size) BN_bn2binpad(number, reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(size));
        else BN_bn2bin(number, reinterpret_cast<unsigned char *>(out.data()));
        BN_free(number);
        return out;
    }

    struct key_pair {
        std::shared_ptr<EVP_PKEY> key;
        int alg = 0;

        explicit key_pair(const int algorithm) : alg(algorithm) {
            EVP_PKEY *made = algorithm == -7    ? EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")
                             : algorithm == -8  ? EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")
                                                : EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", static_cast<size_t>(2048));
            if (!made) throw std::runtime_error("no key made");
            key.reset(made, EVP_PKEY_free);
        }

        // Its COSE public key.
        [[nodiscard]] value cose() const {
            if (alg == -7)
                return value::map_of({{1, 2}, {3, -7}, {-1, 1}, {-2, value::bytes(bignum_bytes(key.get(), OSSL_PKEY_PARAM_EC_PUB_X, 32))},
                                      {-3, value::bytes(bignum_bytes(key.get(), OSSL_PKEY_PARAM_EC_PUB_Y, 32))}});
            if (alg == -8) {
                std::string raw(32, '\0');
                size_t length = raw.size();
                EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char *>(raw.data()), &length);
                return value::map_of({{1, 1}, {3, -8}, {-1, 6}, {-2, value::bytes(raw)}});
            }
            return value::map_of({{1, 3}, {3, -257}, {-1, value::bytes(bignum_bytes(key.get(), OSSL_PKEY_PARAM_RSA_N))},
                                  {-2, value::bytes(bignum_bytes(key.get(), OSSL_PKEY_PARAM_RSA_E))}});
        }

        [[nodiscard]] std::string sign(const std::string &data) const {
            std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context{EVP_MD_CTX_new(), &EVP_MD_CTX_free};
            EVP_DigestSignInit(context.get(), nullptr, alg == -8 ? nullptr : EVP_sha256(), nullptr, key.get());
            size_t length = 0;
            EVP_DigestSign(context.get(), nullptr, &length, reinterpret_cast<const unsigned char *>(data.data()), data.size());
            std::string out(length, '\0');
            EVP_DigestSign(context.get(), reinterpret_cast<unsigned char *>(out.data()), &length, reinterpret_cast<const unsigned char *>(data.data()), data.size());
            out.resize(length);
            return out;
        }
    };

    inline std::string random_id(const std::size_t size = 32) {
        std::string out(size, '\0');
        RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), static_cast<int>(size));
        return out;
    }

    // The parts of a response, each changeable.
    struct parts {
        std::string type = "webauthn.create";
        std::string challenge;          // base64url
        std::string origin = "https://roelof.1web.co.za";
        std::string client_extra;       // more clientDataJSON members, ",\"crossOrigin\":true"
        std::string rp_id = "1web.co.za";
        unsigned char flags = 0x45;     // UP, UV, AT
        std::uint32_t sign_count = 0;
        std::string aaguid = std::string(16, '\x11');
        std::string credential_id = random_id();
        std::string fmt = "none";
        std::string extra_auth_data;    // bytes after the authenticator data's end
        std::string user_handle;        // bytes
    };

    inline std::string client_data(const parts &p) {
        return R"({"type":")" + p.type + R"(","challenge":")" + p.challenge + R"(","origin":")" + p.origin + "\"" + p.client_extra + "}";
    }

    inline std::string authenticator_data(const parts &p, const key_pair *with_key) {
        std::string out = sha256(p.rp_id);
        out += static_cast<char>(p.flags);
        for (int i = 3; i >= 0; --i) out += static_cast<char>(p.sign_count >> (8 * i) & 0xff);
        if (with_key) {
            out += p.aaguid;
            out += static_cast<char>(p.credential_id.size() >> 8);
            out += static_cast<char>(p.credential_id.size() & 0xff);
            out += p.credential_id;
            out += sc::cbor::encode(with_key->cose());
        }
        return out + p.extra_auth_data;
    }

    inline std::string registration(const parts &p, const key_pair &key) {
        const auto attestation = value::map_of({{"fmt", p.fmt}, {"attStmt", value{sc::cbor::map{}}}, {"authData", value::bytes(authenticator_data(p, &key))}});
        const auto id = base64url_encode(p.credential_id);
        return R"({"id":")" + id + R"(","rawId":")" + id + R"(","type":"public-key","authenticatorAttachment":"platform","response":{"clientDataJSON":")" +
               base64url_encode(client_data(p)) + R"(","attestationObject":")" + base64url_encode(sc::cbor::encode(attestation)) +
               R"(","transports":["internal","hybrid"]},"clientExtensionResults":{}})";
    }

    // An assertion, signed by key (or the given signature, when one is).
    inline std::string authentication(const parts &p, const key_pair &key, const std::string *signature = nullptr) {
        const auto client = client_data(p);
        const auto data = authenticator_data(p, nullptr);
        const auto signed_by = signature ? *signature : key.sign(data + sha256(client));
        const auto id = base64url_encode(p.credential_id);
        return R"({"id":")" + id + R"(","rawId":")" + id + R"(","type":"public-key","response":{"clientDataJSON":")" + base64url_encode(client) +
               R"(","authenticatorData":")" + base64url_encode(data) + R"(","signature":")" + base64url_encode(signed_by) + R"(","userHandle":")" +
               base64url_encode(p.user_handle) + R"("},"clientExtensionResults":{}})";
    }
}
