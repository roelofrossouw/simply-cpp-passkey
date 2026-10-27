/*
 * sc-passkey.js: passkeys in the browser, for the options SC\Passkey (sc-passkey) makes and the
 * responses it checks. No dependencies.
 *
 *   const answer = await scPasskey.create(optionsJson); // registration: send answer to the server
 *   const answer = await scPasskey.get(optionsJson);    // authentication
 *
 * optionsJson is the server's options, as an object or JSON text. The answer is the JSON form
 * (RegistrationResponseJSON / AuthenticationResponseJSON) as PublicKeyCredential.toJSON() gives it;
 * browsers without toJSON() or parse*OptionsFromJSON() (older Safari) get the same by hand.
 * scPasskey.supported() says whether the browser has passkeys at all. Errors are the browser's
 * (a DOMException: NotAllowedError when the user cancels or it times out, InvalidStateError when
 * the authenticator already holds an excluded credential).
 *
 * Copyright 2026 Roelof Rossouw. Licensed under the Apache License, Version 2.0.
 */
(function (root) {
    'use strict';

    function toBytes(text) {
        const base64 = text.replace(/-/g, '+').replace(/_/g, '/');
        const padded = base64 + '==='.slice((base64.length + 3) % 4);
        const binary = atob(padded);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out.buffer;
    }

    function toText(buffer) {
        if (!buffer) return null;
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function parsed(options) {
        return typeof options === 'string' ? JSON.parse(options) : options;
    }

    function descriptors(list) {
        return (list || []).map(function (each) {
            const out = {type: each.type || 'public-key', id: toBytes(each.id)};
            if (each.transports) out.transports = each.transports;
            return out;
        });
    }

    function creationOptions(json) {
        if (window.PublicKeyCredential && PublicKeyCredential.parseCreationOptionsFromJSON) {
            return PublicKeyCredential.parseCreationOptionsFromJSON(json);
        }
        const out = Object.assign({}, json);
        out.challenge = toBytes(json.challenge);
        out.user = Object.assign({}, json.user, {id: toBytes(json.user.id)});
        out.excludeCredentials = descriptors(json.excludeCredentials);
        return out;
    }

    function requestOptions(json) {
        if (window.PublicKeyCredential && PublicKeyCredential.parseRequestOptionsFromJSON) {
            return PublicKeyCredential.parseRequestOptionsFromJSON(json);
        }
        const out = Object.assign({}, json);
        out.challenge = toBytes(json.challenge);
        out.allowCredentials = descriptors(json.allowCredentials);
        return out;
    }

    // The credential's JSON form: toJSON() when there is one, else built the same way.
    function answer(credential) {
        if (typeof credential.toJSON === 'function') {
            try {
                return credential.toJSON();
            } catch (ignored) {
                // Some versions throw for some authenticators: by hand below.
            }
        }
        const response = credential.response;
        const out = {
            id: credential.id,
            rawId: toText(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment || null,
            clientExtensionResults: credential.getClientExtensionResults ? credential.getClientExtensionResults() : {},
            response: {clientDataJSON: toText(response.clientDataJSON)}
        };
        if (response.attestationObject) {
            out.response.attestationObject = toText(response.attestationObject);
            out.response.transports = response.getTransports ? response.getTransports() : [];
            if (response.getAuthenticatorData) out.response.authenticatorData = toText(response.getAuthenticatorData());
            if (response.getPublicKeyAlgorithm) out.response.publicKeyAlgorithm = response.getPublicKeyAlgorithm();
        } else {
            out.response.authenticatorData = toText(response.authenticatorData);
            out.response.signature = toText(response.signature);
            out.response.userHandle = toText(response.userHandle);
        }
        return out;
    }

    const scPasskey = {
        supported: function () {
            return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
        },
        create: async function (options) {
            const credential = await navigator.credentials.create({publicKey: creationOptions(parsed(options))});
            return answer(credential);
        },
        get: async function (options) {
            const credential = await navigator.credentials.get({publicKey: requestOptions(parsed(options))});
            return answer(credential);
        }
    };

    root.scPasskey = scPasskey;
    if (typeof module === 'object' && module.exports) module.exports = scPasskey;
})(typeof window !== 'undefined' ? window : this);
