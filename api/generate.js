"use strict";

const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");
const bip39 = require("bip39");
const QRCode = require("qrcode");

const sql = neon(process.env.DATABASE_URL);


/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const WORD_COUNT = 12;

const KANGAROO_HISTORY = Math.max(
    1,
    Number(process.env.KANGAROO_HISTORY || 100)
);

const KANGAROO_CANDIDATES = Math.max(
    5,
    Number(process.env.KANGAROO_CANDIDATES || 75)
);

const GENERATION_LIMIT_PER_MINUTE = Math.max(
    1,
    Number(process.env.GENERATION_LIMIT_PER_MINUTE || 30)
);

const GENERATION_WINDOW_MINUTES = 1;

const MAX_DATABASE_ATTEMPTS = 25;


/*
|--------------------------------------------------------------------------
| SHA-256
|--------------------------------------------------------------------------
*/

function sha256(value) {
    return crypto
        .createHash("sha256")
        .update(value, "utf8")
        .digest("hex");
}


/*
|--------------------------------------------------------------------------
| Read cookie
|--------------------------------------------------------------------------
*/

function getCookie(req, name) {
    const cookieHeader = req.headers.cookie || "";

    const cookies = cookieHeader
        .split(";")
        .map(item => item.trim());

    for (const cookie of cookies) {
        const separator = cookie.indexOf("=");

        if (separator === -1) {
            continue;
        }

        const key = cookie.slice(0, separator);
        const value = cookie.slice(separator + 1);

        if (key === name) {
            return value;
        }
    }

    return null;
}


/*
|--------------------------------------------------------------------------
| Authenticate session
|--------------------------------------------------------------------------
*/

async function authenticate(req) {
    const sessionToken = getCookie(req, "session");

    if (!sessionToken) {
        return false;
    }

    const sessionHash = sha256(sessionToken);

    const result = await sql`
        SELECT id
        FROM auth_sessions
        WHERE
            session_hash = ${sessionHash}
            AND expires_at > NOW()
        LIMIT 1
    `;

    return result.length > 0;
}


/*
|--------------------------------------------------------------------------
| Generate a genuine BIP-39 12-word mnemonic
|--------------------------------------------------------------------------
|
| 128 bits of cryptographically secure entropy
| +
| 4-bit SHA-256 checksum
| =
| 132 bits
| =
| 12 x 11-bit word indexes
|
|--------------------------------------------------------------------------
*/

function generateBip39Mnemonic() {
    const mnemonic = bip39.generateMnemonic(128);

    const normalized = mnemonic
        .trim()
        .toLowerCase()
        .replace(/\s+/g, " ");

    const words = normalized.split(" ");

    /*
    |--------------------------------------------------------------------------
    | Defensive validation
    |--------------------------------------------------------------------------
    */

    if (words.length !== WORD_COUNT) {
        throw new Error(
            "Generated mnemonic does not contain exactly 12 words."
        );
    }

    if (!bip39.validateMnemonic(normalized)) {
        throw new Error(
            "Generated mnemonic failed BIP-39 checksum validation."
        );
    }

    return words;
}


/*
|--------------------------------------------------------------------------
| Word overlap distance
|--------------------------------------------------------------------------
|
| 12 shared words = distance 0
| 0 shared words  = distance 12
|
|--------------------------------------------------------------------------
*/

function wordDistance(first, second) {
    const secondSet = new Set(second);

    let shared = 0;

    for (const word of first) {
        if (secondSet.has(word)) {
            shared++;
        }
    }

    return WORD_COUNT - shared;
}


/*
|--------------------------------------------------------------------------
| Position distance
|--------------------------------------------------------------------------
*/

function positionDistance(first, second) {
    let different = 0;

    for (let i = 0; i < WORD_COUNT; i++) {
        if (first[i] !== second[i]) {
            different++;
        }
    }

    return different;
}


/*
|--------------------------------------------------------------------------
| Combined candidate score
|--------------------------------------------------------------------------
*/

function calculateCandidateScore(
    candidate,
    previousCodes
) {
    let minimumWordDistance = WORD_COUNT;
    let totalPositionDistance = 0;

    for (const previous of previousCodes) {
        const wordDistanceValue = wordDistance(
            candidate,
            previous
        );

        const positionDistanceValue = positionDistance(
            candidate,
            previous
        );

        minimumWordDistance = Math.min(
            minimumWordDistance,
            wordDistanceValue
        );

        totalPositionDistance +=
            positionDistanceValue;
    }

    return {
        minimumWordDistance,
        totalPositionDistance
    };
}


/*
|--------------------------------------------------------------------------
| Fetch recent mnemonics
|--------------------------------------------------------------------------
*/

async function getRecentCodes() {
    const result = await sql`
        SELECT words
        FROM generated_codes
        ORDER BY id DESC
        LIMIT ${KANGAROO_HISTORY}
    `;

    return result
        .map(row => String(row.words).trim())
        .filter(Boolean)
        .map(words => words.split(/\s+/))
        .filter(words => words.length === WORD_COUNT);
}


/*
|--------------------------------------------------------------------------
| Kangaroo candidate selection
|--------------------------------------------------------------------------
|
| Every candidate is independently generated as a VALID BIP-39
| mnemonic.
|
| We never modify individual words of an existing mnemonic.
|
|--------------------------------------------------------------------------
*/

function chooseKangarooCandidate(previousCodes) {
    if (previousCodes.length === 0) {
        return generateBip39Mnemonic();
    }

    let bestCandidate = null;

    let bestMinimumWordDistance = -1;

    let bestTotalPositionDistance = -1;

    for (
        let i = 0;
        i < KANGAROO_CANDIDATES;
        i++
    ) {
        const candidate = generateBip39Mnemonic();

        const score = calculateCandidateScore(
            candidate,
            previousCodes
        );

        if (
            score.minimumWordDistance >
            bestMinimumWordDistance
        ) {
            bestCandidate = candidate;

            bestMinimumWordDistance =
                score.minimumWordDistance;

            bestTotalPositionDistance =
                score.totalPositionDistance;

            continue;
        }

        if (
            score.minimumWordDistance ===
            bestMinimumWordDistance
        ) {
            if (
                score.totalPositionDistance >
                bestTotalPositionDistance
            ) {
                bestCandidate = candidate;

                bestTotalPositionDistance =
                    score.totalPositionDistance;
            }
        }
    }

    return bestCandidate;
}


/*
|--------------------------------------------------------------------------
| Rate limiting
|--------------------------------------------------------------------------
*/

async function checkGenerationRateLimit(
    sessionToken
) {
    const sessionHash = sha256(sessionToken);

    const key = `generate:${sessionHash}`;

    const existing = await sql`
        SELECT
            attempts,
            window_started_at
        FROM rate_limits
        WHERE rate_key = ${key}
        LIMIT 1
    `;

    if (existing.length === 0) {
        await sql`
            INSERT INTO rate_limits
            (
                rate_key,
                attempts,
                window_started_at
            )
            VALUES
            (
                ${key},
                1,
                NOW()
            )
            ON CONFLICT (rate_key)
            DO NOTHING
        `;

        return true;
    }

    const record = existing[0];

    const elapsed =
        Date.now() -
        new Date(
            record.window_started_at
        ).getTime();

    const windowMs =
        GENERATION_WINDOW_MINUTES *
        60 *
        1000;

    if (elapsed >= windowMs) {
        await sql`
            UPDATE rate_limits
            SET
                attempts = 1,
                window_started_at = NOW()
            WHERE rate_key = ${key}
        `;

        return true;
    }

    if (
        Number(record.attempts) >=
        GENERATION_LIMIT_PER_MINUTE
    ) {
        return false;
    }

    await sql`
        UPDATE rate_limits
        SET attempts = attempts + 1
        WHERE rate_key = ${key}
    `;

    return true;
}


/*
|--------------------------------------------------------------------------
| Reserve globally unique mnemonic
|--------------------------------------------------------------------------
*/

async function reserveCode(words) {
    const code = words.join(" ");

    const codeHash = sha256(code);

    const result = await sql`
        INSERT INTO generated_codes
        (
            code_hash,
            words
        )
        VALUES
        (
            ${codeHash},
            ${code}
        )
        ON CONFLICT (code_hash)
        DO NOTHING
        RETURNING
            id,
            created_at
    `;

    if (result.length === 0) {
        return null;
    }

    return {
        id: result[0].id,
        createdAt: result[0].created_at,
        code,
        words
    };
}


/*
|--------------------------------------------------------------------------
| Create QR
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| The QR contains ONLY the exact lowercase 12-word mnemonic.
|
| No JSON.
| No URL.
| No extra metadata.
|
|--------------------------------------------------------------------------
*/

async function createQRCode(code) {
    return QRCode.toDataURL(
        code,
        {
            errorCorrectionLevel: "M",
            margin: 2,
            width: 500,

            color: {
                dark: "#000000",
                light: "#FFFFFF"
            }
        }
    );
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
    /*
    |--------------------------------------------------------------------------
    | Method
    |--------------------------------------------------------------------------
    */

    if (req.method !== "POST") {
        res.setHeader(
            "Allow",
            "POST"
        );

        return res
            .status(405)
            .json({
                success: false,
                error: "Method not allowed."
            });
    }


    try {
        /*
        |--------------------------------------------------------------------------
        | Authentication
        |--------------------------------------------------------------------------
        */

        const sessionToken =
            getCookie(
                req,
                "session"
            );

        const authenticated =
            await authenticate(req);

        if (!authenticated) {
            return res
                .status(401)
                .json({
                    success: false,
                    error:
                        "Authentication required."
                });
        }


        /*
        |--------------------------------------------------------------------------
        | Generation rate limit
        |--------------------------------------------------------------------------
        */

        const allowed =
            await checkGenerationRateLimit(
                sessionToken
            );

        if (!allowed) {
            return res
                .status(429)
                .json({
                    success: false,
                    error:
                        "Generation limit reached. Please wait a moment."
                });
        }


        /*
        |--------------------------------------------------------------------------
        | Requested mode
        |--------------------------------------------------------------------------
        */

        const body =
            req.body || {};

        const mode =
            body.mode === "kangaroo"
                ? "kangaroo"
                : "random";


        /*
        |--------------------------------------------------------------------------
        | Get Kangaroo history
        |--------------------------------------------------------------------------
        */

        let recentCodes = [];

        if (mode === "kangaroo") {
            recentCodes =
                await getRecentCodes();
        }


        /*
        |--------------------------------------------------------------------------
        | Generate + globally reserve
        |--------------------------------------------------------------------------
        */

        for (
            let attempt = 0;
            attempt < MAX_DATABASE_ATTEMPTS;
            attempt++
        ) {
            let words;

            if (mode === "kangaroo") {
                words =
                    chooseKangarooCandidate(
                        recentCodes
                    );
            } else {
                words =
                    generateBip39Mnemonic();
            }


            /*
            |--------------------------------------------------------------------------
            | Final validation before database reservation
            |--------------------------------------------------------------------------
            */

            const mnemonic =
                words.join(" ");


            if (
                words.length !==
                WORD_COUNT
            ) {
                throw new Error(
                    "Invalid mnemonic word count."
                );
            }


            if (
                !bip39.validateMnemonic(
                    mnemonic
                )
            ) {
                throw new Error(
                    "Generated mnemonic failed final BIP-39 validation."
                );
            }


            /*
            |--------------------------------------------------------------------------
            | Global uniqueness
            |--------------------------------------------------------------------------
            */

            const reserved =
                await reserveCode(
                    words
                );


            if (
                reserved !== null
            ) {
                /*
                |--------------------------------------------------------------------------
                | QR
                |--------------------------------------------------------------------------
                */

                const qr =
                    await createQRCode(
                        reserved.code
                    );


                /*
                |--------------------------------------------------------------------------
                | Response
                |--------------------------------------------------------------------------
                */

                return res
                    .status(200)
                    .json({
                        success: true,

                        id:
                            reserved.id,

                        mode,

                        words:
                            reserved.words,

                        code:
                            reserved.code,

                        qr,

                        bip39Valid:
                            true,

                        wordCount:
                            WORD_COUNT,

                        createdAt:
                            reserved.createdAt
                    });
            }
        }


        /*
        |--------------------------------------------------------------------------
        | Database collision / temporary failure
        |--------------------------------------------------------------------------
        */

        return res
            .status(503)
            .json({
                success: false,
                error:
                    "Unable to reserve a unique mnemonic. Please try again."
            });


    } catch (error) {
        console.error(
            "Generation error:",
            error
        );

        return res
            .status(500)
            .json({
                success: false,
                error:
                    "Server error while generating mnemonic."
            });
    }
};
