"use strict";

const crypto = require("crypto");
const bip39 = require("bip39");


/*
|--------------------------------------------------------------------------
| BIP-39 Diagnostic
|--------------------------------------------------------------------------
|
| This endpoint does NOT generate or return a wallet recovery phrase.
|
| It verifies that the installed bip39 package:
|
| 1. Uses the official English BIP-39 wordlist
| 2. Correctly converts entropy -> mnemonic
| 3. Correctly converts mnemonic -> entropy
| 4. Correctly validates the checksum
| 5. Produces exactly 12 words for 128-bit entropy
|
|--------------------------------------------------------------------------
*/


/*
|--------------------------------------------------------------------------
| Official BIP-39 128-bit test vector
|--------------------------------------------------------------------------
|
| ENTROPY:
|
| 00000000000000000000000000000000
|
| Expected mnemonic:
|
| abandon abandon abandon abandon abandon abandon abandon abandon
| abandon abandon abandon about
|
|--------------------------------------------------------------------------
*/

const TEST_ENTROPY =
    "00000000000000000000000000000000";

const EXPECTED_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";


/*
|--------------------------------------------------------------------------
| SHA-256 helper
|--------------------------------------------------------------------------
*/

function sha256(buffer) {
    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest();
}


/*
|--------------------------------------------------------------------------
| Convert bytes to binary
|--------------------------------------------------------------------------
*/

function bytesToBinary(bytes) {
    return bytes
        .map(byte =>
            byte
                .toString(2)
                .padStart(8, "0")
        )
        .join("");
}


/*
|--------------------------------------------------------------------------
| Independent BIP-39 checksum calculation
|--------------------------------------------------------------------------
|
| For 128-bit entropy:
|
| checksum length = ENT / 32
|                 = 128 / 32
|                 = 4 bits
|
|--------------------------------------------------------------------------
*/

function calculateChecksum(entropyHex) {
    const entropyBuffer =
        Buffer.from(
            entropyHex,
            "hex"
        );

    const hash =
        sha256(entropyBuffer);

    const binary =
        bytesToBinary(
            Array.from(hash)
        );

    return binary.slice(0, 4);
}


/*
|--------------------------------------------------------------------------
| Independently inspect the mnemonic
|--------------------------------------------------------------------------
*/

function independentlyInspectMnemonic(
    mnemonic
) {
    const normalized =
        mnemonic
            .normalize("NFKD")
            .trim()
            .toLowerCase()
            .replace(/\s+/g, " ");

    const words =
        normalized.split(" ");

    const wordCount =
        words.length;

    const englishWordlist =
        bip39.wordlists.english;

    const indexes =
        words.map(word =>
            englishWordlist.indexOf(word)
        );

    const allWordsInEnglishList =
        indexes.every(
            index => index >= 0
        );

    let reconstructedEntropy = null;

    let reconstructedChecksum = null;

    let expectedChecksum = null;

    let checksumMatches = false;

    let entropyError = null;

    if (allWordsInEnglishList) {
        try {
            const bits =
                indexes
                    .map(index =>
                        index
                            .toString(2)
                            .padStart(11, "0")
                    )
                    .join("");

            /*
             * 12 words = 132 bits
             *
             * First 128 bits = entropy
             * Last 4 bits = checksum
             */

            const entropyBits =
                bits.slice(0, 128);

            const checksumBits =
                bits.slice(128);

            const entropyBytes = [];

            for (
                let i = 0;
                i < 128;
                i += 8
            ) {
                entropyBytes.push(
                    parseInt(
                        entropyBits.slice(
                            i,
                            i + 8
                        ),
                        2
                    )
                );
            }

            const entropyBuffer =
                Buffer.from(
                    entropyBytes
                );

            reconstructedEntropy =
                entropyBuffer.toString(
                    "hex"
                );

            reconstructedChecksum =
                checksumBits;

            expectedChecksum =
                calculateChecksum(
                    reconstructedEntropy
                );

            checksumMatches =
                reconstructedChecksum ===
                expectedChecksum;

        } catch (error) {
            entropyError =
                error.message;
        }
    }


    return {
        normalizedWordCount:
            wordCount,

        allWordsInOfficialEnglishList:
            allWordsInEnglishList,

        checksumLength:
            reconstructedChecksum
                ? reconstructedChecksum.length
                : null,

        checksumMatches,

        reconstructedEntropy,

        reconstructedChecksum,

        expectedChecksum,

        entropyError
    };
}


/*
|--------------------------------------------------------------------------
| Main handler
|--------------------------------------------------------------------------
*/

module.exports = async function handler(
    req,
    res
) {
    if (req.method !== "GET") {
        res.setHeader(
            "Allow",
            "GET"
        );

        return res
            .status(405)
            .json({
                success: false,
                error:
                    "Method not allowed."
            });
    }


    try {
        /*
        |--------------------------------------------------------------------------
        | 1. Generate expected mnemonic using installed BIP-39 package
        |--------------------------------------------------------------------------
        */

        const generatedFromTestEntropy =
            bip39.entropyToMnemonic(
                TEST_ENTROPY,
                bip39.wordlists.english
            );


        /*
        |--------------------------------------------------------------------------
        | 2. Compare against official test vector
        |--------------------------------------------------------------------------
        */

        const generatedMatchesOfficialVector =
            generatedFromTestEntropy ===
            EXPECTED_MNEMONIC;


        /*
        |--------------------------------------------------------------------------
        | 3. Validate using bip39
        |--------------------------------------------------------------------------
        */

        const packageValidation =
            bip39.validateMnemonic(
                generatedFromTestEntropy,
                bip39.wordlists.english
            );


        /*
        |--------------------------------------------------------------------------
        | 4. Convert back to entropy
        |--------------------------------------------------------------------------
        */

        let roundTripEntropy = null;

        let roundTripError = null;

        try {
            roundTripEntropy =
                bip39.mnemonicToEntropy(
                    generatedFromTestEntropy,
                    bip39.wordlists.english
                );
        } catch (error) {
            roundTripError =
                error.message;
        }


        /*
        |--------------------------------------------------------------------------
        | 5. Independently inspect the test vector
        |--------------------------------------------------------------------------
        */

        const independent =
            independentlyInspectMnemonic(
                EXPECTED_MNEMONIC
            );


        /*
        |--------------------------------------------------------------------------
        | 6. Overall result
        |--------------------------------------------------------------------------
        */

        const diagnosticPassed =
            generatedMatchesOfficialVector &&
            packageValidation &&
            roundTripEntropy === TEST_ENTROPY &&
            independent.wordCount === 12 &&
            independent.allWordsInOfficialEnglishList &&
            independent.checksumMatches;


        /*
        |--------------------------------------------------------------------------
        | 7. Return diagnostics only
        |--------------------------------------------------------------------------
        */

        return res
            .status(200)
            .json({
                success: true,

                diagnosticPassed,

                bip39Package:
                    "working",

                generatedMnemonicMatchesOfficialVector:
                    generatedMatchesOfficialVector,

                packageValidation,

                roundTripEntropyMatches:
                    roundTripEntropy ===
                    TEST_ENTROPY,

                independentChecksumValidation:
                    independent.checksumMatches,

                wordCount:
                    independent.normalizedWordCount,

                allWordsInOfficialEnglishList:
                    independent.allWordsInOfficialEnglishList,

                checksumLength:
                    independent.checksumLength,

                reconstructedEntropy:
                    independent.reconstructedEntropy,

                reconstructedChecksum:
                    independent.reconstructedChecksum,

                expectedChecksum:
                    independent.expectedChecksum,

                roundTripError,

                entropyError:
                    independent.entropyError
            });

    } catch (error) {
        console.error(
            "BIP-39 diagnostic error:",
            error
        );

        return res
            .status(500)
            .json({
                success: false,
                diagnosticPassed: false,
                error:
                    "BIP-39 diagnostic failed."
            });
    }
};
