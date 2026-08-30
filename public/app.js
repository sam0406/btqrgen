"use strict";


/*
|--------------------------------------------------------------------------
| DOM
|--------------------------------------------------------------------------
*/

const loginScreen =
    document.getElementById(
        "loginScreen"
    );

const generatorScreen =
    document.getElementById(
        "generatorScreen"
    );

const loginForm =
    document.getElementById(
        "loginForm"
    );

const loginButton =
    document.getElementById(
        "loginButton"
    );

const loginError =
    document.getElementById(
        "loginError"
    );

const logoutButton =
    document.getElementById(
        "logoutButton"
    );

const wordGrid =
    document.getElementById(
        "wordGrid"
    );

const qrImage =
    document.getElementById(
        "qrImage"
    );

const generateButton =
    document.getElementById(
        "generateButton"
    );

const generationError =
    document.getElementById(
        "generationError"
    );

const codeNumber =
    document.getElementById(
        "codeNumber"
    );

const randomModeButton =
    document.getElementById(
        "randomModeButton"
    );

const kangarooModeButton =
    document.getElementById(
        "kangarooModeButton"
    );

const modeDescription =
    document.getElementById(
        "modeDescription"
    );

const kangarooStatus =
    document.getElementById(
        "kangarooStatus"
    );


/*
|--------------------------------------------------------------------------
| Application state
|--------------------------------------------------------------------------
*/

let currentMode =
    "random";

let displayedCodeCount =
    0;


/*
|--------------------------------------------------------------------------
| Show generator
|--------------------------------------------------------------------------
*/

function showGenerator() {

    loginScreen.hidden =
        true;

    generatorScreen.hidden =
        false;

}


/*
|--------------------------------------------------------------------------
| Show login
|--------------------------------------------------------------------------
*/

function showLogin() {

    generatorScreen.hidden =
        true;

    loginScreen.hidden =
        false;

}


/*
|--------------------------------------------------------------------------
| Login
|--------------------------------------------------------------------------
*/

async function login(
    username,
    password
) {

    loginButton.disabled =
        true;

    loginButton.textContent =
        "Logging in…";

    loginError.hidden =
        true;

    try {

        const response =
            await fetch(
                "/api/login",
                {
                    method:
                        "POST",

                    headers:
                        {
                            "Content-Type":
                                "application/json"
                        },

                    credentials:
                        "same-origin",

                    body:
                        JSON.stringify({
                            username,
                            password
                        })
                }
            );


        const data =
            await response.json();


        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Login failed."
            );

        }


        loginForm.reset();

        showGenerator();

        await generateCode();


    } catch (
        error
    ) {

        loginError.textContent =
            error.message ||
            "Login failed.";

        loginError.hidden =
            false;

    } finally {

        loginButton.disabled =
            false;

        loginButton.textContent =
            "Login";

    }

}


/*
|--------------------------------------------------------------------------
| Login form
|--------------------------------------------------------------------------
*/

loginForm.addEventListener(
    "submit",
    async event => {

        event.preventDefault();


        const username =
            document
                .getElementById(
                    "username"
                )
                .value
                .trim();


        const password =
            document
                .getElementById(
                    "password"
                )
                .value;


        await login(
            username,
            password
        );

    }
);


/*
|--------------------------------------------------------------------------
| Logout
|--------------------------------------------------------------------------
*/

async function logout() {

    logoutButton.disabled =
        true;


    try {

        await fetch(
            "/api/logout",
            {
                method:
                    "POST",

                credentials:
                    "same-origin"
            }
        );

    } catch (
        error
    ) {

        console.error(
            "Logout error:",
            error
        );

    }


    displayedCodeCount =
        0;


    wordGrid.innerHTML =
        "";


    qrImage.removeAttribute(
        "src"
    );


    showLogin();


    logoutButton.disabled =
        false;

}


/*
|--------------------------------------------------------------------------
| Logout button
|--------------------------------------------------------------------------
*/

logoutButton.addEventListener(
    "click",
    logout
);


/*
|--------------------------------------------------------------------------
| Change mode
|--------------------------------------------------------------------------
*/

function setMode(
    mode
) {

    currentMode =
        mode;


    if (
        mode ===
        "kangaroo"
    ) {

        kangarooModeButton.classList.add(
            "active"
        );

        randomModeButton.classList.remove(
            "active"
        );

        modeDescription.textContent =
            "🦘 Searches valid BIP-39 candidates for one that is far from recent codes.";

    } else {

        randomModeButton.classList.add(
            "active"
        );

        kangarooModeButton.classList.remove(
            "active"
        );

        modeDescription.textContent =
            "Cryptographically secure BIP-39 12-word mnemonic.";

    }

}


/*
|--------------------------------------------------------------------------
| Mode buttons
|--------------------------------------------------------------------------
*/

randomModeButton.addEventListener(
    "click",
    () => {

        setMode(
            "random"
        );

    }
);


kangarooModeButton.addEventListener(
    "click",
    () => {

        setMode(
            "kangaroo"
        );

    }
);


/*
|--------------------------------------------------------------------------
| Display words
|--------------------------------------------------------------------------
*/

function displayWords(
    words
) {

    wordGrid.innerHTML =
        "";


    words.forEach(
        (
            word,
            index
        ) => {

            const element =
                document.createElement(
                    "div"
                );


            element.className =
                "word";


            element.textContent =
                word;


            element.setAttribute(
                "aria-label",
                `Word ${index + 1}: ${word}`
            );


            wordGrid.appendChild(
                element
            );

        }
    );

}


/*
|--------------------------------------------------------------------------
| Display QR
|--------------------------------------------------------------------------
*/

function displayQRCode(
    qr
) {

    qrImage.src =
        qr;

}


/*
|--------------------------------------------------------------------------
| Strict mnemonic normalization
|--------------------------------------------------------------------------
*/

function normalizeMnemonic(
    mnemonic
) {

    return String(
        mnemonic || ""
    )
        .normalize("NFKD")
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");

}


/*
|--------------------------------------------------------------------------
| Validate returned mnemonic
|--------------------------------------------------------------------------
*/

function validateReturnedMnemonic(
    data
) {


    /*
    |--------------------------------------------------------------------------
    | code must exist
    |--------------------------------------------------------------------------
    */

    if (
        typeof data.code !==
        "string"
    ) {

        throw new Error(
            "Server did not return the mnemonic code."
        );

    }


    const code =
        normalizeMnemonic(
            data.code
        );


    /*
    |--------------------------------------------------------------------------
    | Exactly 12 words
    |--------------------------------------------------------------------------
    */

    const codeWords =
        code.split(" ");


    if (
        codeWords.length !==
        12
    ) {

        throw new Error(
            "Server returned a mnemonic that does not contain exactly 12 words."
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Every word lowercase
    |--------------------------------------------------------------------------
    */

    for (
        const word
        of codeWords
    ) {

        if (
            word !==
            word.toLowerCase()
        ) {

            throw new Error(
                "Server returned a non-lowercase mnemonic."
            );

        }

    }


    /*
    |--------------------------------------------------------------------------
    | data.words must exist
    |--------------------------------------------------------------------------
    */

    if (
        !Array.isArray(
            data.words
        )
    ) {

        throw new Error(
            "Invalid word data received from server."
        );

    }


    if (
        data.words.length !==
        12
    ) {

        throw new Error(
            "The server did not return exactly 12 words."
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Normalize returned words
    |--------------------------------------------------------------------------
    */

    const returnedWords =
        data.words.map(
            word =>
                normalizeMnemonic(
                    word
                )
        );


    /*
    |--------------------------------------------------------------------------
    | No duplicate words
    |--------------------------------------------------------------------------
    */

    if (
        new Set(
            returnedWords
        ).size !==
        12
    ) {

        throw new Error(
            "The server returned duplicate words."
        );

    }


    /*
    |--------------------------------------------------------------------------
    | CRITICAL:
    |
    | The displayed words MUST equal
    | the exact mnemonic used for QR.
    |--------------------------------------------------------------------------
    */

    const reconstructedCode =
        returnedWords.join(" ");


    if (
        reconstructedCode !==
        code
    ) {

        throw new Error(
            "Security check failed: displayed words do not match the mnemonic."
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Return the single canonical value.
    |--------------------------------------------------------------------------
    */

    return {
        code,
        words:
            codeWords
    };

}


/*
|--------------------------------------------------------------------------
| Generate code
|--------------------------------------------------------------------------
*/

async function generateCode() {

    generateButton.disabled =
        true;

    generateButton.textContent =
        "Generating…";

    generationError.hidden =
        true;

    generationError.textContent =
        "";

    kangarooStatus.hidden =
        true;


    try {


        const response =
            await fetch(
                "/api/generate",
                {

                    method:
                        "POST",

                    headers:
                        {
                            "Content-Type":
                                "application/json"
                        },

                    credentials:
                        "same-origin",

                    body:
                        JSON.stringify({
                            mode:
                                currentMode
                        })

                }
            );


        let data;


        try {

            data =
                await response.json();

        } catch (
            jsonError
        ) {

            throw new Error(
                "The server returned an invalid response."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Session expired
        |--------------------------------------------------------------------------
        */

        if (
            response.status ===
            401
        ) {

            showLogin();

            throw new Error(
                "Your session has expired. Please log in again."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Rate limit
        |--------------------------------------------------------------------------
        */

        if (
            response.status ===
            429
        ) {

            throw new Error(
                data.error ||
                "Please wait before generating another code."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | API error
        |--------------------------------------------------------------------------
        */

        if (
            !response.ok ||
            !data.success
        ) {

            throw new Error(
                data.error ||
                "Unable to generate code."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Server must explicitly say BIP-39 valid
        |--------------------------------------------------------------------------
        */

        if (
            data.bip39Valid !==
            true
        ) {

            throw new Error(
                "Server did not confirm BIP-39 validation."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Server must explicitly return 12
        |--------------------------------------------------------------------------
        */

        if (
            data.wordCount !==
            12
        ) {

            throw new Error(
                "Server did not confirm a 12-word mnemonic."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Validate code + words consistency
        |--------------------------------------------------------------------------
        */

        const validated =
            validateReturnedMnemonic(
                data
            );


        /*
        |--------------------------------------------------------------------------
        | Validate QR data URL
        |--------------------------------------------------------------------------
        */

        if (
            typeof data.qr !==
            "string" ||
            !data.qr.startsWith(
                "data:image/"
            )
        ) {

            throw new Error(
                "Invalid QR code received from server."
            );

        }


        /*
        |--------------------------------------------------------------------------
        | Display ONLY the validated mnemonic
        |--------------------------------------------------------------------------
        */

        displayWords(
            validated.words
        );


        /*
        |--------------------------------------------------------------------------
        | Display QR generated from
        | that exact same mnemonic
        |--------------------------------------------------------------------------
        */

        displayQRCode(
            data.qr
        );


        displayedCodeCount++;


        codeNumber.textContent =
            `Code #${displayedCodeCount}`;


        /*
        |--------------------------------------------------------------------------
        | Kangaroo information
        |--------------------------------------------------------------------------
        */

        if (
            data.mode ===
            "kangaroo"
        ) {

            kangarooStatus.textContent =
                "🦘 Kangaroo mode: valid BIP-39 candidates were compared and the selected code was stored.";

            kangarooStatus.hidden =
                false;

        }


    } catch (
        error
    ) {

        console.error(
            "Generation error:",
            error
        );


        generationError.textContent =
            error.message ||
            "Unable to generate code.";


        generationError.hidden =
            false;

    } finally {

        generateButton.disabled =
            false;

        generateButton.textContent =
            "Generate New Code";

    }

}


/*
|--------------------------------------------------------------------------
| Generate button
|--------------------------------------------------------------------------
*/

generateButton.addEventListener(
    "click",
    generateCode
);
