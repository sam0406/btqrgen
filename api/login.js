"use strict";

const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const sql = neon(process.env.DATABASE_URL);


/*
|--------------------------------------------------------------------------
| Configuration
|--------------------------------------------------------------------------
*/

const SESSION_DURATION_HOURS =
    Number(
        process.env.SESSION_DURATION_HOURS || 24
    );

const LOGIN_LIMIT_PER_15_MINUTES =
    Number(
        process.env.LOGIN_LIMIT_PER_15_MINUTES || 10
    );


/*
|--------------------------------------------------------------------------
| Get client IP
|--------------------------------------------------------------------------
*/

function getClientIp(req) {

    const forwarded =
        req.headers["x-forwarded-for"];

    if (forwarded) {

        return forwarded
            .split(",")[0]
            .trim();

    }

    return (
        req.headers["x-real-ip"] ||
        "unknown"
    );

}


/*
|--------------------------------------------------------------------------
| SHA-256
|--------------------------------------------------------------------------
*/

function sha256(value) {

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
| Constant-time comparison
|--------------------------------------------------------------------------
*/

function safeEqual(
    first,
    second
) {

    const firstBuffer =
        Buffer.from(
            String(first)
        );

    const secondBuffer =
        Buffer.from(
            String(second)
        );


    if (
        firstBuffer.length !==
        secondBuffer.length
    ) {

        return false;

    }


    return crypto.timingSafeEqual(
        firstBuffer,
        secondBuffer
    );

}


/*
|--------------------------------------------------------------------------
| Login rate limiter
|--------------------------------------------------------------------------
*/

async function checkLoginRateLimit(
    ip
) {

    const key =
        `login:${ip}`;


    const windowMinutes =
        15;


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


    const started =
        new Date(
            record.window_started_at
        );


    const elapsed =
        Date.now() -
        started.getTime();


    const windowMs =
        windowMinutes *
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
        LOGIN_LIMIT_PER_15_MINUTES
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
| Create session
|--------------------------------------------------------------------------
*/

async function createSession() {

    const sessionToken =
        crypto
            .randomBytes(32)
            .toString("base64url");


    const sessionHash =
        sha256(
            sessionToken
        );


    const expiresAt =
        new Date(
            Date.now() +
            SESSION_DURATION_HOURS *
            60 *
            60 *
            1000
        );


    await sql`
        INSERT INTO auth_sessions
        (
            session_hash,
            expires_at
        )
        VALUES
        (
            ${sessionHash},
            ${expiresAt.toISOString()}
        )
    `;


    return {
        token: sessionToken,
        expiresAt
    };

}


/*
|--------------------------------------------------------------------------
| Main API handler
|--------------------------------------------------------------------------
*/

module.exports =
    async function handler(
        req,
        res
    ) {


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
            | Environment validation
            |--------------------------------------------------------------------------
            */

            if (
                !process.env.DATABASE_URL ||
                !process.env.ADMIN_USERNAME ||
                !process.env.ADMIN_PASSWORD
            ) {

                throw new Error(
                    "Authentication environment variables are not configured."
                );

            }


            /*
            |--------------------------------------------------------------------------
            | Rate limit
            |--------------------------------------------------------------------------
            */

            const ip =
                getClientIp(req);


            const allowed =
                await checkLoginRateLimit(
                    ip
                );


            if (!allowed) {

                return res
                    .status(429)
                    .json({

                        success: false,

                        error:
                            "Too many login attempts. Please wait and try again."

                    });

            }


            /*
            |--------------------------------------------------------------------------
            | Request body
            |--------------------------------------------------------------------------
            */

            const body =
                req.body || {};


            const username =
                String(
                    body.username || ""
                ).trim();


            const password =
                String(
                    body.password || ""
                );


            /*
            |--------------------------------------------------------------------------
            | Validate credentials
            |--------------------------------------------------------------------------
            */

            const validUsername =
                safeEqual(
                    username,
                    process.env.ADMIN_USERNAME
                );


            const validPassword =
                safeEqual(
                    password,
                    process.env.ADMIN_PASSWORD
                );


            if (
                !validUsername ||
                !validPassword
            ) {

                return res
                    .status(401)
                    .json({

                        success: false,

                        error:
                            "Invalid username or password."

                    });

            }


            /*
            |--------------------------------------------------------------------------
            | Create secure session
            |--------------------------------------------------------------------------
            */

            const session =
                await createSession();


            /*
            |--------------------------------------------------------------------------
            | Cookie
            |--------------------------------------------------------------------------
            */

            const cookie =
                [
                    `session=${session.token}`,
                    "HttpOnly",
                    "Secure",
                    "SameSite=Strict",
                    "Path=/",
                    `Max-Age=${Math.floor(
                        SESSION_DURATION_HOURS *
                        60 *
                        60
                    )}`
                ].join("; ");


            res.setHeader(
                "Set-Cookie",
                cookie
            );


            return res
                .status(200)
                .json({

                    success: true

                });


        } catch (
            error
        ) {


            console.error(
                "Login error:",
                error
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to process login."

                });

        }

    };
