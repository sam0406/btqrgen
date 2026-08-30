"use strict";

const crypto = require("crypto");

const {
    neon
} = require(
    "@neondatabase/serverless"
);

const bip39 =
    require("bip39");

const QRCode =
    require("qrcode");


const sql =
    neon(
        process.env.DATABASE_URL
    );


/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const WORD_COUNT = 12;


const KANGAROO_HISTORY =
    Math.max(
        1,
        Number(
            process.env.KANGAROO_HISTORY ||
            100
        )
    );


const KANGAROO_CANDIDATES =
    Math.max(
        5,
        Number(
            process.env.KANGAROO_CANDIDATES ||
            75
        )
    );


const KANGAROO_MIN_DISTANCE =
    Math.min(
        12,
        Math.max(
            0,
            Number(
                process.env.KANGAROO_MIN_DISTANCE ||
                9
            )
        )
    );


const GENERATION_LIMIT_PER_MINUTE =
    Math.max(
        1,
        Number(
            process.env.GENERATION_LIMIT_PER_MINUTE ||
            30
        )
    );


const GENERATION_WINDOW_MINUTES = 1;


const MAX_DATABASE_ATTEMPTS = 25;


/*
|--------------------------------------------------------------------------
| SHA-256
|--------------------------------------------------------------------------
*/

function sha256(
    value
) {

    return crypto
        .createHash("sha256")
        .update(
            value,
            "utf8"
        )
        .digest("hex");

}


/*
|--------------------------------------------------------------------------
| Read cookie
|--------------------------------------------------------------------------
*/

function getCookie(
    req,
    name
) {

    const cookieHeader =
        req.headers.cookie || "";


    const cookies =
        cookieHeader
            .split(";")
            .map(
                item => item.trim()
            );


    for (
        const cookie of cookies
    ) {


        const separator =
            cookie.indexOf("=");


        if (
            separator === -1
        ) {

            continue;

        }


        const key =
            cookie.slice(
                0,
                separator
            );


        const value =
            cookie.slice(
                separator + 1
            );


        if (
            key === name
        ) {

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

async function authenticate(
    req
) {

    const sessionToken =
        getCookie(
            req,
            "session"
        );


    if (
        !sessionToken
    ) {

        return false;

    }


    const sessionHash =
        sha256(
            sessionToken
        );


    const result =
        await sql`
            SELECT id
            FROM auth_sessions
            WHERE
                session_hash = ${sessionHash}
                AND expires_at > NOW()
            LIMIT 1
        `;


    return (
        result.length > 0
    );

}


/*
|--------------------------------------------------------------------------
| Get word list
|--------------------------------------------------------------------------
*/

function getWordList() {

    const words =
        bip39
            .wordlists
            .english;


    if (
        !Array.isArray(words)
    ) {

        throw new Error(
            "English word list is unavailable."
        );

    }


    if (
        words.length !== 2048
    ) {

        throw new Error(
            `Expected 2048 words but received ${words.length}.`
        );

    }


    const uniqueWords =
        new Set(words);


    if (
        uniqueWords.size !== 2048
    ) {

        throw new Error(
            "Word list contains duplicate entries."
        );

    }


    return words;

}


/*
|--------------------------------------------------------------------------
| Secure random integer
|--------------------------------------------------------------------------
*/

function secureRandomInt(
    max
) {

    if (
        !Number.isSafeInteger(max) ||
        max <= 0
    ) {

        throw new Error(
            "Invalid random range."
        );

    }


    return crypto.randomInt(
        0,
        max
    );

}


/*
|--------------------------------------------------------------------------
| Generate 12 unique words
|--------------------------------------------------------------------------
*/

function generateWords(
    wordList
) {

    const pool =
        [...wordList];


    const selected =
        [];


    while (
        selected.length <
        WORD_COUNT
    ) {


        const index =
            secureRandomInt(
                pool.length
            );


        selected.push(
            pool[index]
        );


        pool.splice(
            index,
            1
        );

    }


    return selected;

}


/*
|--------------------------------------------------------------------------
| Word overlap distance
|--------------------------------------------------------------------------
|
| 12 shared words = distance 0
| 0 shared words  = distance 12
|
*/

function wordDistance(
    first,
    second
) {

    const secondSet =
        new Set(second);


    let shared =
        0;


    for (
        const word of first
    ) {

        if (
            secondSet.has(word)
        ) {

            shared++;

        }

    }


    return (
        WORD_COUNT -
        shared
    );

}


/*
|--------------------------------------------------------------------------
| Position distance
|--------------------------------------------------------------------------
|
| Counts how many positions contain different words.
|
| This makes Kangaroo less likely to produce something
| that looks almost identical in the same order.
|
*/

function positionDistance(
    first,
    second
) {

    let different =
        0;


    for (
        let i = 0;
        i < WORD_COUNT;
        i++
    ) {

        if (
            first[i] !==
            second[i]
        ) {

            different++;

        }

    }


    return different;

}


/*
|--------------------------------------------------------------------------
| Combined distance
|--------------------------------------------------------------------------
|
| Word overlap is the primary measurement.
|
| Position distance is a secondary tie-breaker.
|
*/

function distanceScore(
    candidate,
    previous
) {

    const overlapDistance =
        wordDistance(
            candidate,
            previous
        );


    const positionalDistance =
        positionDistance(
            candidate,
            previous
        );


    return {

        overlapDistance,

        positionalDistance

    };

}


/*
|--------------------------------------------------------------------------
| Fetch recent codes
|--------------------------------------------------------------------------
*/

async function getRecentCodes() {

    const result =
        await sql`
            SELECT words
            FROM generated_codes
            ORDER BY id DESC
            LIMIT ${KANGAROO_HISTORY}
        `;


    return result.map(
        row =>
            String(
                row.words
            ).split(" ")
    );

}


/*
|--------------------------------------------------------------------------
| Generate Kangaroo candidate
|--------------------------------------------------------------------------
*/

function chooseKangarooCandidate(
    wordList,
    previousCodes
) {


    /*
    |--------------------------------------------------------------------------
    | If there are no previous codes, simply generate one.
    |--------------------------------------------------------------------------
    */

    if (
        previousCodes.length === 0
    ) {

        return generateWords(
            wordList
        );

    }


    let bestCandidate =
        null;


    let bestMinimumDistance =
        -1;


    let bestPositionScore =
        -1;


    /*
    |--------------------------------------------------------------------------
    | Generate multiple secure candidates.
    |--------------------------------------------------------------------------
    */

    for (
        let i = 0;
        i < KANGAROO_CANDIDATES;
        i++
    ) {


        const candidate =
            generateWords(
                wordList
            );


        let minimumDistance =
            WORD_COUNT;


        let positionScore =
            0;


        /*
        |--------------------------------------------------------------------------
        | Compare candidate with every recent code.
        |--------------------------------------------------------------------------
        */

        for (
            const previous of previousCodes
        ) {


            const score =
                distanceScore(
                    candidate,
                    previous
                );


            minimumDistance =
                Math.min(
                    minimumDistance,
                    score.overlapDistance
                );


            positionScore +=
                score.positionalDistance;

        }


        /*
        |--------------------------------------------------------------------------
        | Keep candidate with greatest minimum distance.
        |--------------------------------------------------------------------------
        */

        if (
            minimumDistance >
            bestMinimumDistance
        ) {

            bestCandidate =
                candidate;

            bestMinimumDistance =
                minimumDistance;

            bestPositionScore =
                positionScore;

        } else if (
            minimumDistance ===
            bestMinimumDistance &&
            positionScore >
            bestPositionScore
        ) {

            bestCandidate =
                candidate;

            bestPositionScore =
                positionScore;

        }


        /*
        |--------------------------------------------------------------------------
        | We already achieved the requested minimum.
        |--------------------------------------------------------------------------
        */

        if (
            minimumDistance >=
            KANGAROO_MIN_DISTANCE
        ) {

            /*
            * Don't immediately return.
            *
            * We continue through the candidates so that
            * we have a chance to find an even better one.
            */

        }

    }


    return bestCandidate;

}


/*
|--------------------------------------------------------------------------
| Rate limit generation
|--------------------------------------------------------------------------
*/

async function checkGenerationRateLimit(
    sessionToken
) {

    const sessionHash =
        sha256(
            sessionToken
        );


    const key =
        `generate:${sessionHash}`;


    const existing =
        await sql`
            SELECT
                attempts,
                window_started_at
            FROM rate_limits
            WHERE rate_key = ${key}
            LIMIT 1
        `;


    if (
        existing.length === 0
    ) {


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


    const record =
        existing[0];


    const elapsed =
        Date.now() -
        new Date(
            record.window_started_at
        ).getTime();


    const windowMs =
        GENERATION_WINDOW_MINUTES *
        60 *
        1000;


    if (
        elapsed >=
        windowMs
    ) {


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
        SET
            attempts = attempts + 1
        WHERE rate_key = ${key}
    `;


    return true;

}


/*
|--------------------------------------------------------------------------
| Reserve globally unique code
|--------------------------------------------------------------------------
*/

async function reserveCode(
    words
) {

    const code =
        words.join(" ");


    const codeHash =
        sha256(
            code
        );


    const result =
        await sql`
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


    if (
        result.length === 0
    ) {

        return null;

    }


    return {

        id:
            result[0].id,

        createdAt:
            result[0].created_at,

        code:
            code,

        words:
            words

    };

}


/*
|--------------------------------------------------------------------------
| Create QR code
|--------------------------------------------------------------------------
*/

async function createQRCode(
    code
) {

    return QRCode.toDataURL(
        code,
        {

            errorCorrectionLevel:
                "M",

            margin:
                2,

            width:
                500,

            color:
                {

                    dark:
                        "#000000",

                    light:
                        "#FFFFFF"

                }

        }
    );

}


/*
|--------------------------------------------------------------------------
| Main handler
|--------------------------------------------------------------------------
*/

module.exports =
    async function handler(
        req,
        res
    ) {


        /*
        |--------------------------------------------------------------------------
        | Method
        |--------------------------------------------------------------------------
        */

        if (
            req.method !== "POST"
        ) {

            res.setHeader(
                "Allow",
                "POST"
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
            | Authenticate
            |--------------------------------------------------------------------------
            */

            const sessionToken =
                getCookie(
                    req,
                    "session"
                );


            const authenticated =
                await authenticate(
                    req
                );


            if (
                !authenticated
            ) {

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
            | Rate limit
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
            | Word list
            |--------------------------------------------------------------------------
            */

            const wordList =
                getWordList();


            /*
            |--------------------------------------------------------------------------
            | Determine mode
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
            | Previous codes for Kangaroo
            |--------------------------------------------------------------------------
            */

            let recentCodes =
                [];


            if (
                mode === "kangaroo"
            ) {

                recentCodes =
                    await getRecentCodes();

            }


            /*
            |--------------------------------------------------------------------------
            | Generate and reserve
            |--------------------------------------------------------------------------
            */

            for (
                let attempt = 0;
                attempt <
                MAX_DATABASE_ATTEMPTS;
                attempt++
            ) {


                let words;


                if (
                    mode === "kangaroo"
                ) {

                    words =
                        chooseKangarooCandidate(
                            wordList,
                            recentCodes
                        );

                } else {

                    words =
                        generateWords(
                            wordList
                        );

                }


                /*
                |--------------------------------------------------------------------------
                | Reserve globally
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

                            success:
                                true,

                            id:
                                reserved.id,

                            mode:
                                mode,

                            words:
                                reserved.words,

                            code:
                                reserved.code,

                            qr:
                                qr,

                            createdAt:
                                reserved.createdAt

                        });

                }

            }


            /*
            |--------------------------------------------------------------------------
            | Unable to reserve
            |--------------------------------------------------------------------------
            */

            return res
                .status(503)
                .json({

                    success: false,

                    error:
                        "Unable to reserve a unique code. Please try again."

                });


        } catch (
            error
        ) {


            console.error(
                "Generation error:",
                error
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Server error while generating code."

                });

        }

    };
