"use strict";

console.log(
    "LINUX WEBAUTHN NEW >>> content script loaded"
);


/*
 * ------------------------------------------------------------
 * Inject page-context bridge
 * ------------------------------------------------------------
 */

function injectPageBridge() {

    if (!document.documentElement) {
        setTimeout(
            injectPageBridge,
            0
        );
        return;
    }

    if (
        document.documentElement
            .dataset
            .linuxWebauthnInjected === "1"
    ) {
        return;
    }

    document.documentElement
        .dataset
        .linuxWebauthnInjected = "1";

    const script =
        document.createElement("script");

    script.src =
        browser.runtime.getURL(
            "page-bridge.js"
        );

    script.type =
        "text/javascript";

    script.onload = function () {

        console.log(
            "LINUX WEBAUTHN NEW >>> page bridge injected"
        );

        script.remove();
    };

    script.onerror = function (error) {

        console.error(
            "LINUX WEBAUTHN NEW >>> page bridge injection failed",
            error
        );
    };

    (
        document.head ||
        document.documentElement
    ).appendChild(script);
}


if (document.documentElement) {

    injectPageBridge();

} else {

    document.addEventListener(
        "DOMContentLoaded",
        injectPageBridge,
        { once: true }
    );
}


/*
 * ------------------------------------------------------------
 * Page -> Background
 * ------------------------------------------------------------
 */

window.addEventListener(
    "message",
    function (event) {

        if (event.source !== window)
            return;

        const message = event.data;

        if (
            !message ||
            message.source !==
                "LINUX-webauthn-page"
        ) {
            return;
        }

        console.log(
            "LINUX WEBAUTHN NEW >>> page request",
            message
        );

        browser.runtime.sendMessage({
            type:
                "native-request",

            operation:
                message.operation,

            data:
                message.data

        }).then(function (response) {

            console.log(
                "LINUX WEBAUTHN NEW >>> background acknowledgement",
                response
            );

        }).catch(function (error) {

            console.error(
                "LINUX WEBAUTHN NEW >>> background error",
                error
            );
        });
    }
);


/*
 * ------------------------------------------------------------
 * Background -> Page
 * ------------------------------------------------------------
 */

browser.runtime.onMessage.addListener(
    function (message) {

        if (
            !message ||
            message.source !==
                "LINUX-webauthn-extension"
        ) {
            return;
        }

        console.log(
            "LINUX WEBAUTHN NEW >>> native response",
            message
        );

        window.postMessage(
            {
                source:
                    "LINUX-webauthn-native",

                type:
                    "native-response",

                id:
                    message.id,

                ok:
                    message.ok,

                data:
                    message.data || [],

                error:
                    message.error || null
            },

            window.location.origin
        );
    }
);
