#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/params.h>

#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/mlkem_project.h"

/*
 * FIPS 203 ML-KEM-768 dk layout:
 *
 * DKPKE || ek || H(ek) || z
 *
 * 1152  +1184 + 32    +32 = 2400
 */
#define PROJECT_MLKEM768_PUB_IN_PRIV_OFFSET \
    (OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES \
     - OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES - 64)

typedef struct {
    void *provctx;
    int selection;
} PROJECT_MLKEM768_GEN_CTX;

static void *project_mlkem768_new(void *provctx)
{
    PROJECT_MLKEM768_KEY *key;

    if (!ossl_prov_is_running())
        return NULL;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->libctx = PROV_LIBCTX_OF(provctx);

    return key;
}

static void project_mlkem768_free(void *vkey)
{
    PROJECT_MLKEM768_KEY *key = vkey;

    if (key == NULL)
        return;

    OPENSSL_cleanse(key->dk, sizeof(key->dk));
    OPENSSL_clear_free(key, sizeof(*key));
}

static int project_mlkem768_has(const void *vkey, int selection)
{
    const PROJECT_MLKEM768_KEY *key = vkey;
    int wanted = selection & OSSL_KEYMGMT_SELECT_KEYPAIR;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if (wanted == 0)
        return 1;

    if ((wanted & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !key->has_private)
        return 0;

    if ((wanted & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && !key->has_public)
        return 0;

    return 1;
}

static int project_mlkem768_match(const void *vkey1,
                                  const void *vkey2,
                                  int selection)
{
    const PROJECT_MLKEM768_KEY *a = vkey1;
    const PROJECT_MLKEM768_KEY *b = vkey2;

    if (!ossl_prov_is_running() || a == NULL || b == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (a->has_public != b->has_public)
            return 0;

        if (a->has_public
            && memcmp(a->ek, b->ek, sizeof(a->ek)) != 0)
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (a->has_private != b->has_private)
            return 0;

        if (a->has_private
            && memcmp(a->dk, b->dk, sizeof(a->dk)) != 0)
            return 0;
    }

    return 1;
}

static int project_mlkem768_validate(const void *vkey,
                                     int selection,
                                     int check_type)
{
    const PROJECT_MLKEM768_KEY *key = vkey;

    (void)check_type;

    if (!project_mlkem768_has(vkey, selection))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && key->has_public
        && !ossl_project_mlkem768_check_public_key(key->ek))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && key->has_private) {
        if (!ossl_project_mlkem768_check_private_key(key->dk))
            return 0;

        if (memcmp(key->ek,
                   key->dk + PROJECT_MLKEM768_PUB_IN_PRIV_OFFSET,
                   sizeof(key->ek)) != 0)
            return 0;
    }

    return 1;
}

static int project_mlkem768_import(void *vkey,
                                   int selection,
                                   const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pub = NULL;
    const void *priv = NULL;
    size_t publen = 0;
    size_t privlen = 0;
    int include_private;

    if (!ossl_prov_is_running() || key == NULL || params == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    /*
     * Do not mutate populated key objects.
     */
    if (key->has_public || key->has_private)
        return 0;

    include_private =
        (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL
        && !OSSL_PARAM_get_octet_string_ptr(p, &pub, &publen))
        return 0;

    if (include_private) {
        p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

        if (p != NULL
            && !OSSL_PARAM_get_octet_string_ptr(p, &priv, &privlen))
            return 0;
    }

    if (priv != NULL) {
        if (privlen != sizeof(key->dk))
            return 0;

        if (!ossl_project_mlkem768_check_private_key(priv))
            return 0;

        memcpy(key->dk, priv, sizeof(key->dk));

        memcpy(key->ek,
               key->dk + PROJECT_MLKEM768_PUB_IN_PRIV_OFFSET,
               sizeof(key->ek));

        if (pub != NULL) {
            if (publen != sizeof(key->ek)
                || memcmp(pub, key->ek, sizeof(key->ek)) != 0) {
                OPENSSL_cleanse(key->dk, sizeof(key->dk));
                OPENSSL_cleanse(key->ek, sizeof(key->ek));
                return 0;
            }
        }

        key->has_private = 1;
        key->has_public = 1;
        return 1;
    }

    if (pub == NULL || publen != sizeof(key->ek))
        return 0;

    if (!ossl_project_mlkem768_check_public_key(pub))
        return 0;

    memcpy(key->ek, pub, sizeof(key->ek));
    key->has_public = 1;

    return 1;
}

static int project_mlkem768_export(void *vkey,
                                   int selection,
                                   OSSL_CALLBACK *param_cb,
                                   void *cbarg)
{
    PROJECT_MLKEM768_KEY *key = vkey;
    OSSL_PARAM out[3];
    size_t n = 0;

    if (!ossl_prov_is_running()
        || key == NULL
        || param_cb == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!key->has_public)
            return 0;

        out[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY,
            key->ek,
            sizeof(key->ek));
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!key->has_private)
            return 0;

        out[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PRIV_KEY,
            key->dk,
            sizeof(key->dk));
    }

    if (n == 0)
        return 0;

    out[n] = OSSL_PARAM_construct_end();

    return param_cb(out, cbarg);
}

static const OSSL_PARAM project_mlkem768_imexport_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *
project_mlkem768_imexport_types_fn(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return project_mlkem768_imexport_types;

    return NULL;
}

static int project_mlkem768_get_params(void *vkey,
                                       OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEY *key = vkey;
    OSSL_PARAM *p;

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 768))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 192))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL
        && !OSSL_PARAM_set_int(
            p, OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL && key->has_public
        && !OSSL_PARAM_set_octet_string(
            p, key->ek, sizeof(key->ek)))
        return 0;

    p = OSSL_PARAM_locate(
        params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    if (p != NULL && key->has_public
        && !OSSL_PARAM_set_octet_string(
            p, key->ek, sizeof(key->ek)))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL && key->has_private
        && !OSSL_PARAM_set_octet_string(
            p, key->dk, sizeof(key->dk)))
        return 0;

    return 1;
}

static const OSSL_PARAM *
project_mlkem768_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;

    return params;
}

static int project_mlkem768_set_params(void *vkey,
                                       const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *pub = NULL;
    size_t publen = 0;
    OSSL_PARAM iparams[2];

    if (key == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(
        params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    if (p == NULL)
        return 1;

    if (!OSSL_PARAM_get_octet_string_ptr(p, &pub, &publen)
        || publen != sizeof(key->ek))
        return 0;

    if (key->has_public)
        return 0;

    iparams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,
        (void *)pub,
        publen);

    iparams[1] = OSSL_PARAM_construct_end();

    return project_mlkem768_import(
        key,
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
        iparams);
}

static const OSSL_PARAM *
project_mlkem768_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;

    return params;
}

static void *project_mlkem768_gen_init(void *provctx,
                                       int selection,
                                       const OSSL_PARAM params[])
{
    PROJECT_MLKEM768_GEN_CTX *gctx;

    (void)params;

    if (!ossl_prov_is_running()
        || (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->provctx = provctx;
    gctx->selection = selection;

    return gctx;
}

static void *project_mlkem768_gen(void *vgctx,
                                  OSSL_CALLBACK *osslcb,
                                  void *cbarg)
{
    PROJECT_MLKEM768_GEN_CTX *gctx = vgctx;
    PROJECT_MLKEM768_KEY *key;

    (void)osslcb;
    (void)cbarg;

    if (gctx == NULL)
        return NULL;

    key = project_mlkem768_new(gctx->provctx);
    if (key == NULL)
        return NULL;

    if (!ossl_project_mlkem768_keypair(key->ek, key->dk)) {
        project_mlkem768_free(key);
        return NULL;
    }

    key->has_public = 1;
    key->has_private = 1;

    return key;
}

static void project_mlkem768_gen_cleanup(void *vgctx)
{
    OPENSSL_free(vgctx);
}

static void *project_mlkem768_dup(const void *vsrc,
                                  int selection)
{
    const PROJECT_MLKEM768_KEY *src = vsrc;
    PROJECT_MLKEM768_KEY *dst;

    if (!ossl_prov_is_running() || src == NULL)
        return NULL;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    dst->libctx = src->libctx;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && src->has_private) {
        memcpy(dst->dk, src->dk, sizeof(dst->dk));
        memcpy(dst->ek, src->ek, sizeof(dst->ek));

        dst->has_private = 1;
        dst->has_public = 1;
    } else if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
               && src->has_public) {
        memcpy(dst->ek, src->ek, sizeof(dst->ek));
        dst->has_public = 1;
    }

    return dst;
}

const OSSL_DISPATCH ossl_project_mlkem768_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW,
      (OSSL_FUNC)project_mlkem768_new },

    { OSSL_FUNC_KEYMGMT_FREE,
      (OSSL_FUNC)project_mlkem768_free },

    { OSSL_FUNC_KEYMGMT_HAS,
      (OSSL_FUNC)project_mlkem768_has },

    { OSSL_FUNC_KEYMGMT_MATCH,
      (OSSL_FUNC)project_mlkem768_match },

    { OSSL_FUNC_KEYMGMT_VALIDATE,
      (OSSL_FUNC)project_mlkem768_validate },

    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (OSSL_FUNC)project_mlkem768_get_params },

    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (OSSL_FUNC)project_mlkem768_gettable_params },

    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (OSSL_FUNC)project_mlkem768_set_params },

    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (OSSL_FUNC)project_mlkem768_settable_params },

    { OSSL_FUNC_KEYMGMT_IMPORT,
      (OSSL_FUNC)project_mlkem768_import },

    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (OSSL_FUNC)project_mlkem768_imexport_types_fn },

    { OSSL_FUNC_KEYMGMT_EXPORT,
      (OSSL_FUNC)project_mlkem768_export },

    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (OSSL_FUNC)project_mlkem768_imexport_types_fn },

    { OSSL_FUNC_KEYMGMT_GEN_INIT,
      (OSSL_FUNC)project_mlkem768_gen_init },

    { OSSL_FUNC_KEYMGMT_GEN,
      (OSSL_FUNC)project_mlkem768_gen },

    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (OSSL_FUNC)project_mlkem768_gen_cleanup },

    { OSSL_FUNC_KEYMGMT_DUP,
      (OSSL_FUNC)project_mlkem768_dup },

    OSSL_DISPATCH_END
};
