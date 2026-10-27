// WebAuthn Level 3's own test vectors (vectors.h): each registers and then signs in with the
// credential it made, as the specification's relying party would; those for what isn't taken (a
// cross-origin frame, ES384, ES512, Ed448) fail with their reason. Any attestation format is
// taken, its statement not checked ("none" asked for).
#include "vectors.h"

#include <base64.h>
#include <sc_passkey.h>

#include "sc_test.h"

namespace {
    std::string bytes(const std::string_view hex) {
        std::string out;
        for (std::size_t i = 0; i + 1 < hex.size(); i += 2) out += static_cast<char>(std::stoi(std::string{hex.substr(i, 2)}, nullptr, 16));
        return out;
    }

    std::string url(const std::string_view hex) { return sc::base64::encode_url(bytes(hex)); }

    std::string registration(const vectors::vector &v) {
        const auto id = url(v.credential_id);
        return R"({"id":")" + id + R"(","rawId":")" + id + R"(","type":"public-key","response":{"clientDataJSON":")" + url(v.registration_client_data) +
               R"(","attestationObject":")" + url(v.attestation_object) + R"("},"clientExtensionResults":{}})";
    }

    std::string authentication(const vectors::vector &v, std::string signature) {
        const auto id = url(v.credential_id);
        return R"({"id":")" + id + R"(","rawId":")" + id + R"(","type":"public-key","response":{"clientDataJSON":")" + url(v.authentication_client_data) +
               R"(","authenticatorData":")" + url(v.authenticator_data) + R"(","signature":")" + sc::base64::encode_url(signature) +
               R"("},"clientExtensionResults":{}})";
    }
}

int main() {
    const sc::passkey::verifier rp{"example.org", "Example", {"https://example.org"}};
    for (const auto &v: vectors::all) {
        SECTION(std::string{v.name}.c_str());
        std::string reason;
        sc::passkey::credential made;
        try {
            made = rp.verify_registration(registration(v), url(v.registration_challenge));
        } catch (const sc::passkey::error &problem) {
            reason = problem.reason();
            if (reason != v.refused) std::cerr << "    registration: " << problem.what() << '\n';
        }
        CHECK_EQ(reason, std::string{v.refused});
        if (!v.refused.empty()) continue;
        CHECK_EQ(made.id, url(v.credential_id));

        const auto signature = bytes(v.signature);
        try {
            const auto used = rp.verify_authentication(authentication(v, signature), url(v.authentication_challenge), made.public_key, made.sign_count);
            CHECK_EQ(used.id, made.id);
        } catch (const sc::passkey::error &problem) {
            CHECK_MSG(false, std::string{"authentication: "} + problem.what());
        }
        // The same with one bit of the signature changed.
        auto changed = signature;
        changed[changed.size() / 2] = static_cast<char>(changed[changed.size() / 2] ^ 1);
        try {
            (void) rp.verify_authentication(authentication(v, changed), url(v.authentication_challenge), made.public_key, made.sign_count);
            CHECK_MSG(false, "a changed signature was taken");
        } catch (const sc::passkey::error &problem) {
            CHECK_EQ(problem.reason(), std::string{"signature"});
        }
        // And with another origin's relying party.
        const sc::passkey::verifier other{"example.org", "Example", {"https://www.example.org"}};
        try {
            (void) other.verify_authentication(authentication(v, signature), url(v.authentication_challenge), made.public_key, made.sign_count);
            CHECK_MSG(false, "another origin was taken");
        } catch (const sc::passkey::error &problem) {
            CHECK_EQ(problem.reason(), std::string{"origin"});
        }
    }
    TEST_SUMMARY();
}
