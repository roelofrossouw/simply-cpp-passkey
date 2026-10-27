// Prints the options a browser takes to make a passkey, or checks what a browser answered: a
// RegistrationResponseJSON saved to a file, against the challenge its options had.
//
//     sc-passkey-demo --rp example.com --origin 'https://*.example.com' --user roelof
//     sc-passkey-demo --rp example.com --origin 'https://*.example.com' --challenge <base64url> answer.json

#include <sc_passkey.h>
#include <params.h>

#include <fstream>
#include <iostream>
#include <sstream>

int main(int argc, char **argv) {
    const sc::params args{argc, argv, {
        {"name", "sc-passkey-demo"},
        {"description", "Prints the registration options a browser's navigator.credentials.create() takes for a passkey, or, given "
                        "a saved RegistrationResponseJSON and its challenge, checks it and prints the credential to keep."},
        {"options", {
            {"rp", {{"value", "DOMAIN"}, {"default", "localhost"}, {"help", "the relying party's ID"}}},
            {"origin", {{"value", "ORIGIN"}, {"default", "http://localhost"}, {"help", "the origin allowed (https://*.DOMAIN for any subdomain)"}}},
            {"user", {{"short", "u"}, {"value", "NAME"}, {"default", "someone"}, {"help", "the user's name in the options"}}},
            {"challenge", {{"short", "c"}, {"value", "BASE64URL"}, {"default", ""}, {"help", "the challenge the options had"}}}}},
        {"positional", {
            {"file", {{"default", ""}, {"help", "a RegistrationResponseJSON to check"}}}}}}};
    try {
        // [readme]
        const sc::passkey::verifier rp{args.as<std::string>("rp"), "Demo", {args.as<std::string>("origin")}};
        const auto file = args.as<std::string>("file");
        if (file.empty()) {
            std::cout << rp.registration_options({"user:" + args.as<std::string>("user"), args.as<std::string>("user"), ""}, {}).dump(2) << '\n';
            return 0;
        }
        std::ifstream in{file};
        std::stringstream answer;
        answer << in.rdbuf();
        const auto made = rp.verify_registration(answer.str(), args.as<std::string>("challenge"));
        std::cout << made.to_json().dump(2) << '\n';
        // [readme]
        return 0;
    } catch (const sc::passkey::error &problem) {
        std::cerr << "Not taken (" << problem.reason() << "): " << problem.what() << '\n';
    } catch (const std::exception &problem) {
        std::cerr << problem.what() << '\n';
    }
    return 1;
}
