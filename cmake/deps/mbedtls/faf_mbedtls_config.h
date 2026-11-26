/* Mbed TLS options on top of its default mbedtls_config.h (issue #238),
 * included through MBEDTLS_USER_CONFIG_FILE for Mbed TLS and every user.
 *
 * libdatachannel's DTLS transport sets the DTLS-SRTP protection profiles
 * (use_srtp) even when it is built without media. */
#define MBEDTLS_SSL_DTLS_SRTP
