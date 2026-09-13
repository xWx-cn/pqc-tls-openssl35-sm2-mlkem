#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/mlkem_project.h"

typedef struct {
    PROJECT_MLKEM768_KEY *key;

    unsigned char coins[
        OSSL_PROJECT_MLKEM768_ENCAP_COINS_BYTES];

    int have_coins;
    int op;
} PROJECT_MLKEM768_KEM_CTX;

static void *project_mlkem768_kem_newctx(void *provctx)
{
    PROJECT_MLKEM768_KEM_CTX *ctx;

    (void)provctx;

    ctx = OPENSSL_zalloc(sizeof(*ctx));

    return ctx;
}

static void project_mlkem768_kem_freectx(void *vctx)
{
    PROJECT_MLKEM768_KEM_CTX *ctx = vctx;

    if (ctx == NULL)
        return;

    OPENSSL_cleanse(ctx->coins, sizeof(ctx->coins));
    OPENSSL_free(ctx);
}

static int project_mlkem768_kem_set_ctx_params(
    void *vctx,
    const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEM_CTX *ctx = vctx;
    const OSSL_PARAM *p;
    const void *coins = NULL;
    size_t len = 0;

    if (ctx == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_IKME);

    if (p == NULL)
        return 1;

    if (ctx->op != EVP_PKEY_OP_ENCAPSULATE)
        return 0;

    if (!OSSL_PARAM_get_octet_string_ptr(p, &coins, &len)
        || len != sizeof(ctx->coins))
        return 0;

    memcpy(ctx->coins, coins, sizeof(ctx->coins));
    ctx->have_coins = 1;

    return 1;
}

static const OSSL_PARAM *
project_mlkem768_kem_settable_ctx_params(void *vctx,
                                         void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
        OSSL_PARAM_END
    };

    (void)vctx;
    (void)provctx;

    return params;
}

static int project_mlkem768_kem_init(void *vctx,
                                     int op,
                                     void *vkey,
                                     const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEM_CTX *ctx = vctx;

    if (!ossl_prov_is_running()
        || ctx == NULL
        || vkey == NULL)
        return 0;

    if (ctx->have_coins) {
        OPENSSL_cleanse(ctx->coins, sizeof(ctx->coins));
        ctx->have_coins = 0;
    }

    ctx->key = vkey;
    ctx->op = op;

    return project_mlkem768_kem_set_ctx_params(vctx, params);
}

static int project_mlkem768_kem_encapsulate_init(
    void *vctx,
    void *vkey,
    const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEY *key = vkey;

    if (key == NULL || !key->has_public)
        return 0;

    return project_mlkem768_kem_init(
        vctx,
        EVP_PKEY_OP_ENCAPSULATE,
        vkey,
        params);
}

static int project_mlkem768_kem_decapsulate_init(
    void *vctx,
    void *vkey,
    const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEY *key = vkey;

    if (key == NULL || !key->has_private)
        return 0;

    return project_mlkem768_kem_init(
        vctx,
        EVP_PKEY_OP_DECAPSULATE,
        vkey,
        params);
}

static int project_mlkem768_kem_encapsulate(
    void *vctx,
    unsigned char *ct,
    size_t *ctlen,
    unsigned char *ss,
    size_t *sslen)
{
    PROJECT_MLKEM768_KEM_CTX *ctx = vctx;
    int ret;

    if (ctx == NULL
        || ctx->key == NULL
        || !ctx->key->has_public)
        return 0;

    if (ct == NULL) {
        if (ctlen != NULL)
            *ctlen = OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES;

        if (sslen != NULL)
            *sslen = OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES;

        return ctlen != NULL || sslen != NULL;
    }

    if (ss == NULL || ctlen == NULL || sslen == NULL)
        return 0;

    if (*ctlen < OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES
        || *sslen < OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES)
        return 0;

    *ctlen = OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES;
    *sslen = OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES;

    if (ctx->have_coins) {
        ret = ossl_project_mlkem768_encaps_derand(
            ct,
            ss,
            ctx->key->ek,
            ctx->coins);
    } else {
        ret = ossl_project_mlkem768_encaps(
            ct,
            ss,
            ctx->key->ek);
    }

    if (ctx->have_coins) {
        OPENSSL_cleanse(ctx->coins, sizeof(ctx->coins));
        ctx->have_coins = 0;
    }

    return ret;
}

static int project_mlkem768_kem_decapsulate(
    void *vctx,
    unsigned char *ss,
    size_t *sslen,
    const unsigned char *ct,
    size_t ctlen)
{
    PROJECT_MLKEM768_KEM_CTX *ctx = vctx;

    if (ctx == NULL
        || ctx->key == NULL
        || !ctx->key->has_private)
        return 0;

    if (ss == NULL) {
        if (sslen == NULL)
            return 0;

        *sslen = OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES;
        return 1;
    }

    if (sslen == NULL
        || *sslen < OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES)
        return 0;

    if (ct == NULL
        || ctlen != OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES)
        return 0;

    *sslen = OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES;

    return ossl_project_mlkem768_decaps(
        ss,
        ct,
        ctx->key->dk);
}

const OSSL_DISPATCH ossl_project_mlkem768_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX,
      (OSSL_FUNC)project_mlkem768_kem_newctx },

    { OSSL_FUNC_KEM_FREECTX,
      (OSSL_FUNC)project_mlkem768_kem_freectx },

    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (OSSL_FUNC)project_mlkem768_kem_encapsulate_init },

    { OSSL_FUNC_KEM_ENCAPSULATE,
      (OSSL_FUNC)project_mlkem768_kem_encapsulate },

    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (OSSL_FUNC)project_mlkem768_kem_decapsulate_init },

    { OSSL_FUNC_KEM_DECAPSULATE,
      (OSSL_FUNC)project_mlkem768_kem_decapsulate },

    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (OSSL_FUNC)project_mlkem768_kem_set_ctx_params },

    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (OSSL_FUNC)project_mlkem768_kem_settable_ctx_params },

    OSSL_DISPATCH_END
};
