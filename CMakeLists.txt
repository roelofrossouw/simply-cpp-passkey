cmake_minimum_required(VERSION 3.22)
set(SC_MODULE passkey)
project(simply-cpp-${SC_MODULE} HOMEPAGE_URL "https://github.com/roelofrossouw/simply-cpp-passkey" LANGUAGES CXX)
include(cmake/sc_bootstrap.cmake)

option(SC_PASSKEY_BUILD_TESTS "Build simply-cpp-passkey tests" ${PROJECT_IS_TOP_LEVEL})

get_sc_version()
message(STATUS "SimplyCPP ${SC_MODULE} Version: ${SC_VERSION}")

# 1.26.0: sc::base64::encode_url and decode_url.
find_or_install_package(sc-core simply-cpp-dev simply-cpp 1.26.0)
find_or_install_package(sc-cbor simply-cpp-cbor-dev simply-cpp-cbor 0.0.0)
find_or_install_package(nlohmann_json nlohmann-json3-dev nlohmann_json)
# OpenSSL 3 (EVP_PKEY_fromdata, OSSL_PARAM_BLD): the keys and signatures.
find_or_install_package(OpenSSL libssl-dev openssl 3.0)

set(SOURCE_OBJECTS)
set(SOURCE_LIBRARIES)
set(SOURCE_LINK_LIBRARIES)

add_sc_object(sc_passkey
        LINK_LIBRARIES sc::sc-core sc::sc-cbor nlohmann_json::nlohmann_json OpenSSL::Crypto
        PUBLIC_LINK_LIBRARIES sc::sc-core sc::sc-cbor nlohmann_json::nlohmann_json OpenSSL::Crypto)

add_sc_libraries(DESCRIPTION "simply-cpp passkeys: WebAuthn registration and authentication for a relying party (OpenSSL)")
target_compile_features(sc-passkey PUBLIC cxx_std_20)
target_compile_features(sc-passkey-shared PUBLIC cxx_std_20)

install_sc_module(PATH_VARS CMAKE_INSTALL_INCLUDEDIR)
install(FILES cmake/SimplyCppFunctions.cmake cmake/sc_bootstrap.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sc-passkey
        COMPONENT development)
# The browser side: navigator.credentials with the JSON forms, for browsers without toJSON().
install(FILES js/sc-passkey.js DESTINATION ${CMAKE_INSTALL_DATADIR}/simply-cpp-passkey COMPONENT development)

if (SC_PASSKEY_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests sc-passkey-test)
endif ()

add_sc_example(sc-passkey-demo)

package_sc_module(DEPENDS simply-cpp-cbor DEV_DEPENDS "simply-cpp-dev (>= 1.26.0~)" simply-cpp-cbor-dev nlohmann-json3-dev libssl-dev)
