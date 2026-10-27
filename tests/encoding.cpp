// A fuzz run of random and mutated input through the whole verifier, which must only ever throw its
// own errors (sc-cbor and sc-core test CBOR and base64url themselves).
#include "authenticator.h"

#include "sc_test.h"

#include <random>

int main() {
    using namespace sc::passkey;
    namespace cbor = sc::cbor;

    SECTION("Fuzz: random and mutated input only ever throws its own errors");
    {
        const verifier rp{"example.com", "Example", {"https://*.example.com"}};
        const test::key_pair key{-7};
        test::parts p;
        p.challenge = sc::base64::encode_url(test::random_id());
        const auto registration = test::registration(p, key);
        std::mt19937 random{20261027};
        int unexpected = 0, decoded = 0;
        const auto run = [&](auto call) {
            try {
                (void) call();
            } catch (const error &) {
            } catch (const cbor::error &) {
            } catch (const std::invalid_argument &) {
            } catch (const std::exception &problem) {
                if (++unexpected <= 5) std::cerr << "    unexpected: " << problem.what() << "\n";
            }
        };
        for (int round = 0; round < 20000; ++round) {
            // Random bytes, as CBOR.
            std::string bytes(random() % 64, '\0');
            for (auto &c: bytes) c = static_cast<char>(random());
            try {
                (void) cbor::decode(bytes, cbor::decode_options::strict());
                ++decoded;
            } catch (const cbor::error &) {
            }
            // The registration with a byte changed, dropped or added.
            auto changed = registration;
            const auto at = random() % changed.size();
            switch (random() % 3) {
                case 0: changed[at] = static_cast<char>(random()); break;
                case 1: changed.erase(at, 1); break;
                default: changed.insert(at, 1, static_cast<char>(random())); break;
            }
            run([&] { return rp.verify_registration(changed, p.challenge); });
            // The attestation object's bytes changed (base64url stays valid).
            const auto from = registration.find("\"attestationObject\":\"") + 21, to = registration.find('"', from);
            auto object = sc::base64::decode_url(registration.substr(from, to - from));
            object[random() % object.size()] = static_cast<char>(random());
            if (random() % 2) object.resize(random() % object.size());
            const auto mutated = registration.substr(0, from) + sc::base64::encode_url(object) + registration.substr(to);
            run([&] { return rp.verify_registration(mutated, p.challenge); });
        }
        CHECK_EQ(unexpected, 0);
        std::cout << "    " << decoded << " random inputs decoded as CBOR\n";
    }

    TEST_SUMMARY();
}
