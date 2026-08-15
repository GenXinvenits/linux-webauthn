(function () {
    "use strict";

    const PAGE_SOURCE =
        "LINUX-webauthn-page";

    const NATIVE_SOURCE =
        "LINUX-webauthn-native";


    console.log(
        "LINUX WEBAUTHN NEW >>> page bridge loaded"
    );


    /*
     * ------------------------------------------------------------
     * Native response -> page
     * ------------------------------------------------------------
     */

    window.addEventListener(
        "message",
        function (event) {

            if (event.source !== window)
                return;


            const message =
                event.data;


            if (
                !message ||
                message.source !== NATIVE_SOURCE ||
                message.type !== "native-response"
            ) {
                return;
            }


            console.log(
                "LINUX WEBAUTHN NEW >>> page received native response",
                message
            );


            window.dispatchEvent(
                new CustomEvent(
                    "LINUX-webauthn-native-response",
                    {
                        detail: message
                    }
                )
            );
        }
    );



    /*
     * ------------------------------------------------------------
     * Temporary bridge test
     * ------------------------------------------------------------
     */

    window.LinuxWebAuthnTest = function () {

        const request = {

            source:
                PAGE_SOURCE,

            type:
                "bridge-test",

            operation:
                "getInfo",

            data:
                []

        };


        console.log(
            "LINUX WEBAUTHN NEW >>> sending bridge test",
            request
        );


        window.postMessage(
            request,
            window.location.origin
        );

    };




    /*
     * ------------------------------------------------------------
     * Temporary response logger
     * ------------------------------------------------------------
     */

    window.addEventListener(
        "LINUX-webauthn-native-response",
        function (event) {

            console.log(
                "LINUX WEBAUTHN NEW >>> TEST RESPONSE",
                event.detail
            );

        }
    );





    /*
     * ------------------------------------------------------------
     * Build temporary MakeCredential request
     *
     * This is NOT CTAP CBOR yet.
     *
     * It converts browser WebAuthn format
     * into a native-friendly object.
     * ------------------------------------------------------------
     */


    function buildMakeCredentialRequest(
        publicKey
    ) {

        return {

            rp:
                publicKey.rp,


            user:
                {
                    id:
                        Array.from(
                            new Uint8Array(
                                publicKey.user.id
                            )
                        ),

                    name:
                        publicKey.user.name,

                    displayName:
                        publicKey.user.displayName
                },


            challenge:
                Array.from(
                    new Uint8Array(
                        publicKey.challenge
                    )
                ),


            pubKeyCredParams:
                publicKey.pubKeyCredParams,


            authenticatorSelection:
                publicKey.authenticatorSelection || null,


            attestation:
                publicKey.attestation || "none"

        };

    }





    /*
     * ------------------------------------------------------------
     * Send request to native host
     * ------------------------------------------------------------
     */


    function sendLinuxRequest(
        operation,
        data
    ) {


        return new Promise(
            function(resolve, reject) {


                const requestId =
                    Date.now();



                function responseHandler(event) {


                    const response =
                        event.detail;



                    if (
                        response.id !== requestId
                    )
                        return;



                    window.removeEventListener(
                        "LINUX-webauthn-native-response",
                        responseHandler
                    );



                    console.log(
                        "LINUX WEBAUTHN >>> native response matched",
                        response
                    );



                    if (!response.ok) {

                        reject(
                            new Error(
                                response.error ||
                                "LINUX WebAuthn failed"
                            )
                        );

                        return;
                    }



                    resolve(response);

                }




                window.addEventListener(
                    "LINUX-webauthn-native-response",
                    responseHandler
                );




                const request =
                {

                    source:
                        PAGE_SOURCE,


                    type:
                        "ctap2",


                    id:
                        requestId,


                    operation,


                    data

                };



                console.log(
                    "LINUX WEBAUTHN >>> sending native request",
                    request
                );



                window.postMessage(
                    request,
                    window.location.origin
                );


            }
        );

    }







    /*
     * ------------------------------------------------------------
     * WebAuthn API interception
     * ------------------------------------------------------------
     */


    if (navigator.credentials) {


        const originalCreate =
            navigator.credentials.create.bind(
                navigator.credentials
            );



        navigator.credentials.create =
            async function(options) {


                console.log(
                    "LINUX WEBAUTHN NEW >>> create intercepted",
                    options
                );



                const request =
                    buildMakeCredentialRequest(
                        options.publicKey
                    );



                console.log(
                    "LINUX WEBAUTHN >>> makeCredential request",
                    request
                );



                const response =
                    await sendLinuxRequest(
                        "makeCredential",
                        request
                    );



                console.log(
                    "LINUX WEBAUTHN >>> makeCredential response",
                    response
                );



                return response;

            };







        const originalGet =
            navigator.credentials.get.bind(
                navigator.credentials
            );



        navigator.credentials.get =
            async function(options) {


                console.log(
                    "LINUX WEBAUTHN NEW >>> get intercepted",
                    options
                );



                throw new Error(
                    "LINUX GetAssertion not implemented yet"
                );

            };





        console.log(
            "LINUX WEBAUTHN NEW >>> WebAuthn API wrapped"
        );


    }
    else {


        console.warn(
            "LINUX WEBAUTHN NEW >>> navigator.credentials unavailable"
        );

    }



})();
