#pragma once
#include "shared.cpp"
#if HAVE_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

bool cookie_init = 0;
unsigned char cookie_secret[16];

static void print_cert_hash(X509* cert)
{
    unsigned char hash[160 / 8];
    unsigned int hash_size = sizeof(hash);
    if (X509_digest(cert, EVP_sha1(), hash, &hash_size) != 1) return;

    for (unsigned int i = 0; i < hash_size; i++)
    {
        if (i % 2 == 0 && i != 0) printf(":");
        printf("%02x", hash[i]);
    }
}

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, result_len;
    struct sockaddr_in peer;

    if (!cookie_init)
    {
        if (!RAND_bytes(cookie_secret, sizeof(cookie_secret)))
        {
            fprintf(stderr, "Error generating cookie secret.\n");
            return 0;
        }

        cookie_init = 1;
    }

    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    length = sizeof(struct in_addr) + sizeof(in_port_t);
    buffer = (unsigned char*)OPENSSL_malloc(length);

    memcpy(buffer, &peer.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.sin_port), &peer.sin_addr, sizeof(struct in_addr));

    HMAC(EVP_sha1(), (const void*)cookie_secret, sizeof(cookie_secret), 
         (const unsigned char*)buffer, length, result, &result_len);
    OPENSSL_free(buffer);

    memcpy(cookie, result, result_len);
    *cookie_len = result_len;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len)
{
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
    unsigned int length = 0, result_len;
    struct sockaddr_in peer;

    if (!cookie_init)
    {
        fprintf(stderr, "Verification called before cookie secret is initialized.\n");
        return 0;
    }

    BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    length = sizeof(struct in_addr) + sizeof(in_port_t);
    buffer = (unsigned char*)OPENSSL_malloc(length);

    memcpy(buffer, &peer.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.sin_port), &peer.sin_addr, sizeof(struct in_addr));

    HMAC(EVP_sha1(), (const void*)cookie_secret, sizeof(cookie_secret), 
         (const unsigned char*)buffer, length, result, &result_len);
    OPENSSL_free(buffer);

    if (cookie_len == result_len && memcmp(result, cookie, result_len) == 0)
    {
        return 1;
    }

    return 0;
}

static int ssl_gen_cert(const char *cn, X509 **cert, EVP_PKEY **key)
{
    EVP_PKEY_CTX *ctx = NULL;
    X509_EXTENSION *ext = NULL;
    *cert = NULL;
    *key = NULL;
    int ret = EXIT_FAILURE;
    
    // Create a new key generation context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        ret = EXIT_FAILURE;
        goto cleanup_ctx;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        ret = EXIT_FAILURE;
        goto cleanup_ctx;
    }

    // Set RSA key length
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        ret = EXIT_FAILURE;
        goto cleanup_ctx;
    }

    // Generate the key
    if (EVP_PKEY_keygen(ctx, key) <= 0) {
        ret = EXIT_FAILURE;
        goto cleanup_ctx;
    }

    // Create X509 certificate
    *cert = X509_new();
    if (*cert == NULL) {
        ret = EXIT_FAILURE;
        goto cleanup_key;
    }

    if (X509_set_version(*cert, 2) == 0 ||
        X509_NAME_add_entry_by_txt(X509_get_subject_name(*cert), "commonName",
            MBSTRING_ASC, (unsigned char*)cn, -1, -1, 0) == 0 ||
        X509_set_issuer_name(*cert, X509_get_subject_name(*cert)) == 0) {
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(*cert), rand() & 0x7FFFFFFF);

    // Set DNS name
    char dnsName[128];
    if (snprintf(dnsName, sizeof(dnsName), "DNS:%s", cn) < 0) {
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }

    // Set up X509V3 context
    X509V3_CTX v3ctx;
    X509V3_set_ctx(&v3ctx, *cert, *cert, NULL, NULL, 0);

    // Add subject alternative name
    ext = X509V3_EXT_conf(NULL, &v3ctx, "subjectAltName", dnsName);
    if (ext == NULL) {
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }

    if (X509_add_ext(*cert, ext, -1) == 0) {
        X509_EXTENSION_free(ext);
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }
    X509_EXTENSION_free(ext);

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && !defined LIBRESSL_VERSION_NUMBER
    {
        ASN1_TIME *tb = NULL, *ta = NULL;
        tb = ASN1_STRING_dup(X509_get0_notBefore(*cert));
        ta = ASN1_STRING_dup(X509_get0_notAfter(*cert));
        
        if (!tb || !ta ||
            X509_gmtime_adj(tb, 0) == 0 ||
            X509_set1_notBefore(*cert, tb) == 0 ||
            X509_gmtime_adj(ta, 60) == 0 ||
            X509_set1_notAfter(*cert, ta) == 0 ||
            X509_set_pubkey(*cert, *key) == 0) {
            ASN1_STRING_free(tb);
            ASN1_STRING_free(ta);
            ret = EXIT_FAILURE;
            goto cleanup_cert;
        }
        ASN1_STRING_free(tb);
        ASN1_STRING_free(ta);
    }
#else
    if (X509_gmtime_adj(X509_get_notBefore(*cert), 0) == 0 ||
        X509_gmtime_adj(X509_get_notAfter(*cert), 60 * 60 * 24 * 365) == 0 ||
        X509_set_pubkey(*cert, *key) == 0) {
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }
#endif

    // Sign the certificate
    if (X509_sign(*cert, *key, EVP_sha1()) == 0) {
        ret = EXIT_FAILURE;
        goto cleanup_cert;
    }

    ret = EXIT_SUCCESS;
    goto cleanup_ctx;

cleanup_cert:
    if (ret != EXIT_SUCCESS) {
        X509_free(*cert);
        *cert = NULL;
    }

cleanup_key:
    if (ret != EXIT_SUCCESS) {
        EVP_PKEY_free(*key);
        *key = NULL;
    }

cleanup_ctx:
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }

    return ret;
}
#endif