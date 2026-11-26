/**
 * @file lab_certificates.h
 * @brief Self-Signed Root CA & Mutual TLS (mTLS) X.509 Certificates Header
 *
 * ============================================================================
 * WHY DO WE NEED THIS FILE?
 * ============================================================================
 * When the ESP32 connects to your PC's Mosquitto broker over `mqtts://` (Port 8883),
 * mbedTLS performs a TLS handshake:
 *   1. Your PC's Mosquitto broker sends its `server.crt` (public certificate).
 *   2. How does the ESP32 know `server.crt` isn't from an attacker spoofing your IP?
 *   3. The ESP32 uses `LAB_CA_CERT_PEM` below (your self-signed Root CA public
 *      certificate) to cryptographically verify the digital signature on `server.crt`
 *      AND checks that the broker's IP matches the certificate's `subjectAltName`!
 *
 * SECURITY RULE:
 *   - NEVER put `ca.key` or `server.key` (Private Keys) on the ESP32!
 *   - `LAB_CA_CERT_PEM` is the PUBLIC Root CA certificate (`ca.crt`).
 *   - Only if you do the Bonus Challenge (Mutual TLS / mTLS) will you paste a
 *     device-specific `client.crt` and `client.key` in the Bonus section below.
 *
 * STUDENT INSTRUCTIONS (Module 3 & 4):
 *   After running OpenSSL to generate your team's `ca.crt`, copy the entire
 *   contents of `ca.crt` (including `-----BEGIN CERTIFICATE-----` and
 *   `-----END CERTIFICATE-----`) and paste it into `LAB_CA_CERT_PEM` below.
 */

#ifndef LAB_CERTIFICATES_H
#define LAB_CERTIFICATES_H

/* ============================================================================
 * 1. SERVER-SIDE TLS: Team Root CA Public Certificate (`ca.crt`)
 * ============================================================================
 * TODO (Module 3/4): Replace the placeholder PEM below with the contents of
 *                    your team's generated `ca.crt` file.
 */
static const char LAB_CA_CERT_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"MIIDozCCAougAwIBAgIUYetaQoxvC+YDGLdyuBNIIWzk8m0wDQYJKoZIhvcNAQEL\n"
"BQAwYTELMAkGA1UEBhMCQ08xDzANBgNVBAgMBkNhbGRhczESMBAGA1UEBwwJTWFu\n"
"aXphbGVzMRMwEQYDVQQKDApJb1QtTGFiLUNBMRgwFgYDVQQDDA9Jb1QtTGFiLVJv\n"
"b3QtQ0EwHhcNMjYxMTI2MDQxNzEwWhcNMzYxMTIzMDQxNzEwWjBhMQswCQYDVQQG\n"
"EwJDTzEPMA0GA1UECAwGQ2FsZGFzMRIwEAYDVQQHDAlNYW5pemFsZXMxEzARBgNV\n"
"BAoMCklvVC1MYWItQ0ExGDAWBgNVBAMMD0lvVC1MYWItUm9vdC1DQTCCASIwDQYJ\n"
"KoZIhvcNAQEBBQADggEPADCCAQoCggEBANygmEpWa3ZP7Q9jhy41pJJJe7AffV/w\n"
"H+jDxbY1jvCdxasJaeGJvtqmIVq/19iWozemKJq91GEkhLNB9ad/nIG6b63G3gtb\n"
"SCWA/jvZMsi0/LEYIsFUuy00JyAnpNwVmmycNngkPpKH6kvLHeIIKG+ZwNSYKu9w\n"
"I2lHLco2Iv6Ek/mm50X01IvymDIZDPlDqlVF2k3zbmfD/+lkwBiH7IF5siDbv/Xb\n"
"q8EleiNJbryvbaO/4d5ZqYx9uK4kgnh06MlvAw+7rraLrR+d7Yu///t17fSpiTWH\n"
"PbpeIIr9AkYgrJgHLIC0j0CErpUbe0OmZy6SWma+2JDNH+nkl5NnLAECAwEAAaNT\n"
"MFEwHQYDVR0OBBYEFFgJ2dQdRPhQQ/6fUkA00YQSf8FyMB8GA1UdIwQYMBaAFFgJ\n"
"2dQdRPhQQ/6fUkA00YQSf8FyMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQEL\n"
"BQADggEBAE9d2gBqM6AvOU2+LNXlAT9cEZ0nDOTKBopZnT0f9itaFWUc+CG52Reg\n"
"ubCQM72DNoNi5ElaLtMB4Iwh5JhJSPAV3yLb9m1hPmjhAcgTx9soi/WM5tlcYDoz\n"
"3GMPh4l1MFlTThZ6EvU+uqmKOAH7P/9fQYOM6c7afxWlq7hkmpOXGdmhNvIeXlyq\n"
"U/AVQd6wDu5XBwZUKyK3Lj9cu511MHyxJFUK4BvVlotTmWHJhE2jloUQQplwcUd2\n"
"LWvAQTBHVyNQAq5P9qYUqGhVjMuDO6oKKmyqBVzy+EyFcXzPA9Fh2ozV//NB/BZf\n"
"bg6DJYknWrEw7B55cL/W8Rma/UisqHw=\n"
"-----END CERTIFICATE-----\n"
;


/* ============================================================================
 * 2. BONUS CHALLENGE (mTLS): ESP32 Client Certificate & Client Private Key
 * ============================================================================
 * Only used if `require_certificate true` is enabled in `mosquitto_tls.conf`.
 */
static const char LAB_CLIENT_CERT_PEM[] =
"-----BEGIN CERTIFICATE-----\n"
"PASTE_YOUR_OPTIONAL_MTLS_CLIENT_CRT_HERE\n"
"-----END CERTIFICATE-----\n";

static const char LAB_CLIENT_KEY_PEM[] =
"-----BEGIN PRIVATE KEY-----\n"
"PASTE_YOUR_OPTIONAL_MTLS_CLIENT_KEY_HERE\n"
"-----END PRIVATE KEY-----\n";

#endif /* LAB_CERTIFICATES_H */
