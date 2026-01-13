#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <arpa/inet.h>

#define KEYLEN 16
#define IVLEN  12
#define TLS13_PFX "tls13 "

/* "secret" is the PRK argument in HKDF-Expand;
 * "Label and "Context" are put into a structure that is the
 * info argument in HKDF-expand
 * the length passes through unchanged
 */
int
hkdf_expand_label(unsigned char *secret, size_t secret_len,
        unsigned char *label, size_t label_len,
        unsigned char *context, size_t context_len,
        void *output, size_t *length)
{
    unsigned char hkdf_label[514]; // max length
    size_t len = 2;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);

    if (pctx == NULL) {
        printf("ctx failed\n");
        return -1;
    }
    if (EVP_PKEY_derive_init(pctx) < 1) {
        printf("derive init failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    /* Build HkdfLabel struct */
    *(uint16_t *)hkdf_label = htons((uint16_t)(*length));
    hkdf_label[len++] = (unsigned char)(label_len + strlen(TLS13_PFX));
    memcpy(&hkdf_label[len], TLS13_PFX, strlen(TLS13_PFX));
    len += strlen(TLS13_PFX);
    memcpy(&hkdf_label[len], label, label_len);
    len += label_len;
    hkdf_label[len++] = (unsigned char)context_len;
    if (context_len > 0) {
        memcpy(&hkdf_label[len], context, context_len);
        len += context_len;
    }

    /* Call HKDF-EXPAND (secret, hkdf_label, length) */
    if (EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) < 1) {
        printf("mode set failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()) <= 0) {
        printf("set hash failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret, secret_len) < 1) {
        printf("secret failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label, len) < 1) {
        printf("keylabel failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    if (EVP_PKEY_derive(pctx, output, length) < 1) {
        printf("key derive failed\n");
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);
    return 1;
}
