// Registration and authentication against a software authenticator, with each algorithm, and every
// check a response must pass: each case that must fail does, with its reason.
#include "authenticator.h"

#include "sc_test.h"

namespace {
    const sc::passkey::verifier rp{"example.com", "Example", {"https://*.example.com", "https://example.org.example.com"}};

    // The reason a call failed with, "" when it didn't.
    template<typename Call>
    std::string reason_of(Call call) {
        try {
            (void) call();
        } catch (const sc::passkey::error &problem) {
            return problem.reason();
        }
        return "";
    }

    std::string challenge() { return rp.authentication_options({})["challenge"].get<std::string>(); }
}

int main() {
    using namespace test;

    SECTION("Origins: exact ones, and a wildcard's subdomains at any depth");
    {
        CHECK(rp.origin_allowed("https://roelof.example.com"));
        CHECK(rp.origin_allowed("https://feature-x.test.example.com"));
        CHECK(rp.origin_allowed("https://example.org.example.com"));
        CHECK(!rp.origin_allowed("https://example.com"));            // the wildcard isn't the bare domain
        CHECK(!rp.origin_allowed("http://roelof.example.com"));      // https only
        CHECK(!rp.origin_allowed("https://roelof.example.com:8443")); // no ports
        CHECK(!rp.origin_allowed("https://roelof.example.com/"));
        CHECK(!rp.origin_allowed("https://evilexample.com"));
        CHECK(!rp.origin_allowed("https://example.com.evil.com"));
        CHECK(!rp.origin_allowed("https://Roelof.example.com"));
        CHECK_THROWS_AS((void) sc::passkey::verifier("example.com", "x", {"https://*.example.net"}), std::invalid_argument);
        CHECK_THROWS_AS((void) sc::passkey::verifier("example.com", "x", {"http://www.example.com"}), std::invalid_argument);
        CHECK_THROWS_AS((void) sc::passkey::verifier("example.com", "x", {"https://www.example.com:443"}), std::invalid_argument);
        CHECK_THROWS_AS((void) sc::passkey::verifier("example.com", "x", {}), std::invalid_argument);
    }

    SECTION("Options as navigator.credentials takes them");
    {
        const auto made = rp.registration_options({"user-7", "roelof", "Roelof"}, {{"AAAA", {"usb"}}});
        CHECK_EQ(made["rp"]["id"].get<std::string>(), std::string{"example.com"});
        CHECK_EQ(made["user"]["id"].get<std::string>(), base64url_encode("user-7"));
        CHECK_EQ(sc::base64::decode_url(made["challenge"].get<std::string>()).size(), std::size_t{32});
        CHECK_EQ(made["pubKeyCredParams"][0]["alg"].get<int>(), -7);
        CHECK_EQ(made["pubKeyCredParams"][1]["alg"].get<int>(), -8);
        CHECK_EQ(made["pubKeyCredParams"][2]["alg"].get<int>(), -257);
        CHECK_EQ(made["excludeCredentials"][0]["transports"][0].get<std::string>(), std::string{"usb"});
        CHECK_EQ(made["attestation"].get<std::string>(), std::string{"none"});
        CHECK_EQ(made["authenticatorSelection"]["userVerification"].get<std::string>(), std::string{"preferred"});
        CHECK(made["challenge"] != rp.registration_options({"user-7", "roelof", ""}, {})["challenge"]);
        const auto asked = rp.authentication_options({{"AAAA", {}}});
        CHECK_EQ(asked["rpId"].get<std::string>(), std::string{"example.com"});
        CHECK_EQ(asked["allowCredentials"][0]["id"].get<std::string>(), std::string{"AAAA"});
        CHECK(!asked["allowCredentials"][0].contains("transports"));
        CHECK_THROWS_AS((void) rp.registration_options({"", "x", ""}, {}), std::invalid_argument);
        CHECK_THROWS_AS((void) rp.registration_options({std::string(65, 'x'), "x", ""}, {}), std::invalid_argument);
    }

    for (const int alg: {-7, -8, -257}) {
        SECTION(("Register and sign in, algorithm " + std::to_string(alg)).c_str());
        const key_pair key{alg};
        parts made;
        made.challenge = challenge();
        made.sign_count = 3;
        const auto credential = rp.verify_registration(registration(made, key), made.challenge);
        CHECK_EQ(credential.id, base64url_encode(made.credential_id));
        CHECK_EQ(credential.algorithm, alg);
        CHECK_EQ(credential.sign_count, std::uint32_t{3});
        CHECK_EQ(credential.aaguid, std::string{"11111111-1111-1111-1111-111111111111"});
        CHECK_EQ(credential.attestation_format, std::string{"none"});
        CHECK_EQ(credential.attachment, std::string{"platform"});
        CHECK_EQ(credential.transports.size(), std::size_t{2});
        CHECK(credential.user_verified);
        CHECK(!credential.backed_up);
        CHECK_EQ(sc::passkey::credential_id(registration(made, key)), base64url_encode(made.credential_id));

        parts used = made;
        used.type = "webauthn.get";
        used.challenge = challenge();
        used.flags = 0x05; // UP, UV
        used.sign_count = 4;
        used.user_handle = "user-7";
        const auto signed_in = rp.verify_authentication(authentication(used, key), used.challenge, credential.public_key, credential.sign_count);
        CHECK_EQ(signed_in.id, credential.id);
        CHECK_EQ(signed_in.sign_count, std::uint32_t{4});
        CHECK(signed_in.user_handle.has_value());
        CHECK_EQ(*signed_in.user_handle, base64url_encode("user-7"));
        CHECK(signed_in.user_verified);

        // Another key's signature, a changed byte, the counter going back.
        const key_pair other{alg};
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(used, other), used.challenge, credential.public_key, 3); }),
                 std::string{"signature"});
        auto tampered = authentication(used, key);
        const auto at = tampered.find("\"signature\":\"") + 14;
        tampered[at] = tampered[at] == 'A' ? 'B' : 'A';
        CHECK(!reason_of([&] { return rp.verify_authentication(tampered, used.challenge, credential.public_key, 3); }).empty());
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(used, key), used.challenge, credential.public_key, 4); }),
                 std::string{"counter"});
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(used, key), used.challenge, credential.public_key, 9); }),
                 std::string{"counter"});
        // Synced passkeys count nothing: 0 and 0 is fine.
        used.sign_count = 0;
        CHECK_EQ(rp.verify_authentication(authentication(used, key), used.challenge, credential.public_key, 0).sign_count, std::uint32_t{0});
    }

    SECTION("Registration: each check");
    {
        const key_pair key{-7};
        parts good;
        good.challenge = challenge();
        const auto fails = [&](parts p, const std::string &reason, const bool require_uv = false) {
            const auto got = reason_of([&] { return rp.verify_registration(registration(p, key), good.challenge, require_uv); });
            if (got != reason) std::cerr << "    wanted " << reason << ", got \"" << got << "\"\n";
            return got == reason;
        };
        CHECK(reason_of([&] { return rp.verify_registration(registration(good, key), good.challenge); }).empty());
        auto p = good;
        p.type = "webauthn.get";
        CHECK(fails(p, "type"));
        p = good;
        p.challenge = challenge();
        CHECK(fails(p, "challenge"));
        p = good;
        p.origin = "https://evil.example.net";
        CHECK(fails(p, "origin"));
        p = good;
        p.origin = "https://example.com.evil.com";
        CHECK(fails(p, "origin"));
        p = good;
        p.client_extra = R"(,"crossOrigin":true)";
        CHECK(fails(p, "cross_origin"));
        p = good;
        p.client_extra = R"(,"crossOrigin":false)";
        CHECK(reason_of([&] { return rp.verify_registration(registration(p, key), good.challenge); }).empty());
        p = good;
        p.client_extra = R"(,"topOrigin":"https://evil.example.net")";
        CHECK(fails(p, "cross_origin"));
        p = good;
        p.rp_id = "evil.example.net";
        CHECK(fails(p, "rp_id"));
        p = good;
        p.flags = 0x44; // UV, AT, not UP
        CHECK(fails(p, "user_presence"));
        p = good;
        p.flags = 0x41; // UP, AT, not UV
        CHECK(reason_of([&] { return rp.verify_registration(registration(p, key), good.challenge); }).empty());
        CHECK(fails(p, "user_verification", true));
        p = good;
        p.flags = 0x55; // BS without BE
        CHECK(fails(p, "flags"));
        p = good;
        p.flags = 0x05; // no AT
        CHECK(fails(p, "format"));
        p = good;
        p.extra_auth_data = "x";
        CHECK(fails(p, "format"));
        p = good;
        p.fmt = "packed"; // any format, its statement not checked
        CHECK_EQ(rp.verify_registration(registration(p, key), good.challenge).attestation_format, std::string{"packed"});

        // The authenticator data for another credential id than rawId.
        auto other_id = registration(good, key);
        const auto id = base64url_encode(good.credential_id), elsewhere = base64url_encode(random_id());
        for (std::size_t at = other_id.find(id); at != std::string::npos; at = other_id.find(id)) other_id.replace(at, id.size(), elsewhere);
        CHECK_EQ(reason_of([&] { return rp.verify_registration(other_id, good.challenge); }), std::string{"credential"});

        // The kept challenge isn't the caller's to get wrong silently.
        CHECK_THROWS_AS((void) rp.verify_registration(registration(good, key), "not base64url!"), std::invalid_argument);
    }

    SECTION("Authentication: each check");
    {
        const key_pair key{-8};
        parts made;
        made.challenge = challenge();
        const auto credential = rp.verify_registration(registration(made, key), made.challenge);
        parts good = made;
        good.type = "webauthn.get";
        good.challenge = challenge();
        good.flags = 0x01;
        const auto fails = [&](const parts &p, const std::string &reason) {
            const auto got = reason_of([&] { return rp.verify_authentication(authentication(p, key), good.challenge, credential.public_key, 0); });
            if (got != reason) std::cerr << "    wanted " << reason << ", got \"" << got << "\"\n";
            return got == reason;
        };
        CHECK(reason_of([&] { return rp.verify_authentication(authentication(good, key), good.challenge, credential.public_key, 0); }).empty());
        CHECK(!rp.verify_authentication(authentication(good, key), good.challenge, credential.public_key, 0).user_handle);
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(good, key), good.challenge, credential.public_key, 0, true); }),
                 std::string{"user_verification"});
        auto p = good;
        p.type = "webauthn.create";
        CHECK(fails(p, "type"));
        p = good;
        p.challenge = made.challenge;
        CHECK(fails(p, "challenge"));
        p = good;
        p.origin = "https://roelof.example.com.evil.com";
        CHECK(fails(p, "origin"));
        p = good;
        p.rp_id = "example.co";
        CHECK(fails(p, "rp_id"));
        p = good;
        p.flags = 0x00;
        CHECK(fails(p, "user_presence"));
        p = good;
        p.extra_auth_data = std::string(3, '\0');
        CHECK(fails(p, "format"));
        // A signature that's empty.
        const std::string none;
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(good, key, &none), good.challenge, credential.public_key, 0); }),
                 std::string{"signature"});
        // A kept key with an algorithm that isn't taken (ES384, -35).
        const auto es384 = base64url_encode(sc::cbor::encode(value::map_of({{1, 2}, {3, -35}})));
        CHECK_EQ(reason_of([&] { return rp.verify_authentication(authentication(good, key), good.challenge, es384, 0); }), std::string{"algorithm"});
        CHECK_THROWS_AS((void) rp.verify_authentication(authentication(good, key), good.challenge, "%%%", 0), std::invalid_argument);
    }

    SECTION("Not JSON, not a response, mismatched ids");
    {
        const auto c = challenge();
        CHECK_EQ(reason_of([&] { return rp.verify_registration("", c); }), std::string{"format"});
        CHECK_EQ(reason_of([&] { return rp.verify_registration("[]", c); }), std::string{"format"});
        CHECK_EQ(reason_of([&] { return rp.verify_registration(R"({"id":"AA","rawId":"AA","type":"public-key"})", c); }), std::string{"format"});
        CHECK_EQ(reason_of([&] { return rp.verify_registration(R"({"id":"AA","rawId":"AQ","type":"public-key","response":{}})", c); }),
                 std::string{"credential"});
        CHECK_EQ(reason_of([&] { return rp.verify_registration(R"({"id":"AA","rawId":"AA","type":"password","response":{}})", c); }),
                 std::string{"type"});
        CHECK_EQ(reason_of([&] { return rp.verify_registration(std::string(300000, ' '), c); }), std::string{"format"});
        CHECK_EQ(reason_of([&] { return sc::passkey::credential_id("{}"); }), std::string{"format"});
    }

    TEST_SUMMARY();
}
