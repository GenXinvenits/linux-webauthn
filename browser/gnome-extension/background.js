"use strict";

console.log(
    "LINUX WEBAUTHN NEW >>> background loaded"
);


let nativePort = null;
let nextNativeId = 1;

const pending = new Map();


function connectNative() {

    if (nativePort)
        return nativePort;


    console.log(
        "LINUX WEBAUTHN NEW >>> connecting to native host"
    );


    try {

        nativePort =
            browser.runtime.connectNative(
                "org.linux.WebAuthn"
            );

    } catch (error) {

        console.error(
            "LINUX WEBAUTHN NEW >>> connectNative failed",
            error
        );

        nativePort = null;

        return null;
    }


    console.log(
        "LINUX WEBAUTHN NEW >>> native host connected"
    );


    /*
     * Native host -> Extension
     */

    nativePort.onMessage.addListener(
        function (message) {

            console.log(
                "LINUX WEBAUTHN NEW >>> native response",
                message
            );


            const id =
                Number(message && message.id);


            if (!Number.isFinite(id)) {

                console.error(
                    "LINUX WEBAUTHN NEW >>> invalid response id"
                );

                return;
            }


            const request =
                pending.get(id);


            if (!request) {

                console.error(
                    "LINUX WEBAUTHN NEW >>> unknown response id",
                    id
                );

                return;
            }


            pending.delete(id);


            browser.tabs.sendMessage(
                request.tabId,
                {
                    source:
                        "linux-webauthn-extension",

                    id,

                    ok:
                        message.ok === true,

                    data:
                        Array.isArray(message.data)
                            ? message.data
                            : [],

                    error:
                        message.error || null
                }
            )
            .then(function () {

                console.log(
                    "LINUX WEBAUTHN NEW >>> response delivered"
                );

            })
            .catch(function (error) {

                console.error(
                    "LINUX WEBAUTHN NEW >>> response relay failed",
                    error
                );

            });

        }
    );



    /*
     * Native disconnect
     */

    nativePort.onDisconnect.addListener(
        function () {


            console.error(
                "LINUX WEBAUTHN NEW >>> native host disconnected"
            );


            nativePort = null;


            for (
                const request
                of pending.values()
            ) {


                browser.tabs.sendMessage(
                    request.tabId,
                    {
                        source:
                            "linux-webauthn-extension",

                        id:
                            request.id,

                        ok:false,

                        data:[],

                        error:
                            "Native host disconnected"
                    }
                )
                .catch(function(){});


            }


            pending.clear();

        }
    );


    return nativePort;
}





browser.runtime.onMessage.addListener(
    function (message, sender) {


        if (
            !message ||
            message.type !== "native-request"
        ) {
            return;
        }



        if (
            !sender ||
            !sender.tab ||
            typeof sender.tab.id !== "number"
        ) {

            return Promise.reject(
                new Error(
                    "No originating tab"
                )
            );
        }



        const data =
            Array.isArray(message.data)
                ? message.data
                : [];



        if (data.length > 65536) {

            return Promise.reject(
                new Error(
                    "Native request too large"
                )
            );

        }



        const port =
            connectNative();



        if (!port) {

            return Promise.reject(
                new Error(
                    "Native host unavailable"
                )
            );

        }



        /*
         * Preserve page request ID
         */

        const id =
            message.id ||
            nextNativeId++;



        const nativeRequest = {

            id,

            type:
                "ctap2",

            operation:
                message.operation || null,

            data

        };



        console.log(
            "LINUX WEBAUTHN NEW >>> native request",
            nativeRequest
        );



        pending.set(
            id,
            {
                id,

                tabId:
                    sender.tab.id
            }
        );



        try {

            port.postMessage(
                nativeRequest
            );


        } catch(error) {


            pending.delete(id);


            return Promise.reject(
                error
            );

        }



        /*
         * Acknowledge transport only.
         * Actual response comes through onMessage.
         */

        return Promise.resolve(
            {
                ok:true,
                id
            }
        );

    }
);
