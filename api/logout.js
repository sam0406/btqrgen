"use strict";

const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const sql = neon(process.env.DATABASE_URL);


/*
|--------------------------------------------------------------------------
| Hash session token
|--------------------------------------------------------------------------
*/

function hashSession(
    token
) {

    return crypto
        .createHash("sha256")
        .update(
            token,
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
| Handler
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


            const sessionToken =
                getCookie(
                    req,
                    "session"
                );


            if (
                sessionToken
            ) {


                const sessionHash =
                    hashSession(
                        sessionToken
                    );


                await sql`
                    DELETE FROM auth_sessions
                    WHERE session_hash = ${sessionHash}
                `;

            }


            /*
            |--------------------------------------------------------------------------
            | Delete browser cookie
            |--------------------------------------------------------------------------
            */

            res.setHeader(
                "Set-Cookie",
                [
                    "session=",
                    "HttpOnly",
                    "Secure",
                    "SameSite=Strict",
                    "Path=/",
                    "Max-Age=0"
                ].join("; ")
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
                "Logout error:",
                error
            );


            return res
                .status(500)
                .json({

                    success: false,

                    error:
                        "Unable to log out."

                });

        }

    };
