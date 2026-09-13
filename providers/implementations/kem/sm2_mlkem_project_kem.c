/*
 * Project curveSM2 + ML-KEM-768 hybrid KEM.
 *
 * Wire order:
 *
 * ClientShare = SM2_public || ML-KEM-768 public key
 * ServerShare = SM2_public || ML-KEM-768 ciphertext
 * Secret      = SM2_ECDH   || ML-KEM-768 shared secret
 */

#include "internal/deprecated.h"

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include "prov/sm2_mlkem_project.h"

typedef struct {
    PROJECT_SM2_MLKEM_KEY *key;
    int op;
} PROJECT_SM2_MLKEM_KEM_CTX;

static void *project_kem_newctx(void *provctx)
{
    PROJECT_SM2_MLKEM_KEM_CTX *ctx;

    (void)provctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    return ctx;
}

static void project_kem_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int project_kem_encapsulate_init(void *vctx,
                                        void *vkey,
                                        const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_KEM_CTX *ctx = vctx;
    PROJECT_SM2_MLKEM_KEY *key = vkey;

    (void)params;

    if (ctx == NULL || key == NULL || !key->has_public)
        return 0;

    ctx->key = key;
    ctx->op = EVP_PKEY_OP_ENCAPSULATE;

    return 1;
}

static int project_kem_decapsulate_init(void *vctx,
                                        void *vkey,
                                        const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_KEM_CTX *ctx = vctx;
    PROJECT_SM2_MLKEM_KEY *key = vkey;

    (void)params;

    if (ctx == NULL || key == NULL || !key->has_private)
        return 0;

    ctx->key = key;
    ctx->op = EVP_PKEY_OP_DECAPSULATE;

    return 1;
}

static int project_kem_encapsulate(void *vctx,
                                   unsigned char *ctext,
                                   size_t *clen,
                                   unsigned char *secret,
                                   size_t *slen)
{
    PROJECT_SM2_MLKEM_KEM_CTX *ctx = vctx;
    PROJECT_SM2_MLKEM_KEY *key;
    EC_KEY *server_sm2 = NULL;
    const EC_POINT *client_point;
    int ecdh_len;
    int ret = 0;

    if (ctx == NULL || (key = ctx->key) == NULL || !key->has_public)
        return 0;

    if (ctext == NULL) {
        if (clen != NULL)
            *clen = PROJECT_SM2_MLKEM_RESPONSE_BYTES;
        if (slen != NULL)
            *slen = PROJECT_SM2_MLKEM_SECRET_BYTES;
        return clen != NULL || slen != NULL;
    }

    if (clen == NULL || slen == NULL || secret == NULL)
        return 0;

    if (*clen < PROJECT_SM2_MLKEM_RESPONSE_BYTES
        || *slen < PROJECT_SM2_MLKEM_SECRET_BYTES)
        return 0;

    *clen = PROJECT_SM2_MLKEM_RESPONSE_BYTES;
    *slen = PROJECT_SM2_MLKEM_SECRET_BYTES;

    if (!ossl_project_mlkem768_check_public_key(key->mlkem_pk))
        goto end;

    server_sm2 =
        EC_KEY_new_by_curve_name_ex(key->libctx, NULL, NID_sm2);

    if (server_sm2 == NULL
        || EC_KEY_generate_key(server_sm2) != 1)
        goto end;

    if (!ossl_project_sm2_mlkem_export_sm2_public(
            server_sm2, ctext))
        goto end;

    client_point = EC_KEY_get0_public_key(key->sm2_key);
    if (client_point == NULL)
        goto end;

    ecdh_len = ECDH_compute_key(
        secret,
        PROJECT_SM2_SECRET_BYTES,
        client_point,
        server_sm2,
        NULL);

    if (ecdh_len != PROJECT_SM2_SECRET_BYTES)
        goto end;

    if (!ossl_project_mlkem768_encaps(
            ctext + PROJECT_SM2_PUBLIC_BYTES,
            secret + PROJECT_SM2_SECRET_BYTES,
            key->mlkem_pk))
        goto end;

    ret = 1;

end:
    if (!ret) {
        OPENSSL_cleanse(secret, PROJECT_SM2_MLKEM_SECRET_BYTES);
        OPENSSL_cleanse(ctext, PROJECT_SM2_MLKEM_RESPONSE_BYTES);
    }

    EC_KEY_free(server_sm2);
    return ret;
}

static int project_kem_decapsulate(void *vctx,
                                   unsigned char *secret,
                                   size_t *slen,
                                   const unsigned char *ctext,
                                   size_t clen)
{
    PROJECT_SM2_MLKEM_KEM_CTX *ctx = vctx;
    PROJECT_SM2_MLKEM_KEY *key;
    EC_KEY *server_sm2 = NULL;
    const EC_POINT *server_point;
    int ecdh_len;
    int ret = 0;

    if (ctx == NULL || (key = ctx->key) == NULL || !key->has_private)
        return 0;

    if (secret == NULL) {
        if (slen == NULL)
            return 0;

        *slen = PROJECT_SM2_MLKEM_SECRET_BYTES;
        return 1;
    }

    if (slen == NULL
        || *slen < PROJECT_SM2_MLKEM_SECRET_BYTES
        || ctext == NULL
        || clen != PROJECT_SM2_MLKEM_RESPONSE_BYTES)
        return 0;

    *slen = PROJECT_SM2_MLKEM_SECRET_BYTES;

    server_sm2 = ossl_project_sm2_mlkem_import_sm2_public(
        key->libctx, ctext);

    if (server_sm2 == NULL)
        goto end;

    server_point = EC_KEY_get0_public_key(server_sm2);
    if (server_point == NULL)
        goto end;

    ecdh_len = ECDH_compute_key(
        secret,
        PROJECT_SM2_SECRET_BYTES,
        server_point,
        key->sm2_key,
        NULL);

    if (ecdh_len != PROJECT_SM2_SECRET_BYTES)
        goto end;

    if (!ossl_project_mlkem768_decaps(
            secret + PROJECT_SM2_SECRET_BYTES,
            ctext + PROJECT_SM2_PUBLIC_BYTES,
            key->mlkem_sk))
        goto end;

    ret = 1;

end:
    if (!ret)
        OPENSSL_cleanse(secret, PROJECT_SM2_MLKEM_SECRET_BYTES);

    EC_KEY_free(server_sm2);
    return ret;
}

static int project_kem_set_ctx_params(void *vctx,
                                      const OSSL_PARAM params[])
{
    (void)vctx;
    (void)params;
    return 1;
}

static const OSSL_PARAM *project_kem_settable_ctx_params(
    void *vctx,
    void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;

    return params;
}

const OSSL_DISPATCH ossl_project_sm2_mlkem_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX,
      (void (*)(void))project_kem_newctx },

    { OSSL_FUNC_KEM_FREECTX,
      (void (*)(void))project_kem_freectx },

    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))project_kem_encapsulate_init },

    { OSSL_FUNC_KEM_ENCAPSULATE,
      (void (*)(void))project_kem_encapsulate },

    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))project_kem_decapsulate_init },

    { OSSL_FUNC_KEM_DECAPSULATE,
      (void (*)(void))project_kem_decapsulate },

    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))project_kem_set_ctx_params },

    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))project_kem_settable_ctx_params },

    OSSL_DISPATCH_END
};
