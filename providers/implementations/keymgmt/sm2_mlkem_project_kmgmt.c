/*
 * Project curveSM2 + ML-KEM-768 hybrid key management.
 *
 * Project implementation for OpenSSL 3.5.
 * Classical component first, PQ component second.
 */

#include "internal/deprecated.h"

#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>

#include "prov/provider_ctx.h"
#include "prov/providercommon.h"
#include "prov/sm2_mlkem_project.h"

typedef struct {
    OSSL_LIB_CTX *libctx;
    int selection;
} PROJECT_SM2_MLKEM_GEN_CTX;

static PROJECT_SM2_MLKEM_KEY *
project_key_new_internal(OSSL_LIB_CTX *libctx)
{
    PROJECT_SM2_MLKEM_KEY *key;

    key = OPENSSL_zalloc(sizeof(*key));
    if (key == NULL)
        return NULL;

    key->libctx = libctx;
    return key;
}

static void *project_key_new(void *provctx)
{
    OSSL_LIB_CTX *libctx = NULL;

    if (provctx != NULL)
        libctx = PROV_LIBCTX_OF(provctx);

    return project_key_new_internal(libctx);
}

static void project_key_free(void *vkey)
{
    PROJECT_SM2_MLKEM_KEY *key = vkey;

    if (key == NULL)
        return;

    EC_KEY_free(key->sm2_key);

    OPENSSL_cleanse(key->mlkem_sk, sizeof(key->mlkem_sk));
    OPENSSL_cleanse(key->mlkem_pk, sizeof(key->mlkem_pk));
    OPENSSL_clear_free(key, sizeof(*key));
}

int ossl_project_sm2_mlkem_export_sm2_public(
    const EC_KEY *key,
    unsigned char out[PROJECT_SM2_PUBLIC_BYTES])
{
    const EC_GROUP *group;
    const EC_POINT *point;
    size_t len;

    if (key == NULL || out == NULL)
        return 0;

    group = EC_KEY_get0_group(key);
    point = EC_KEY_get0_public_key(key);

    if (group == NULL || point == NULL)
        return 0;

    len = EC_POINT_point2oct(group,
                            point,
                            POINT_CONVERSION_UNCOMPRESSED,
                            out,
                            PROJECT_SM2_PUBLIC_BYTES,
                            NULL);

    return len == PROJECT_SM2_PUBLIC_BYTES;
}

EC_KEY *ossl_project_sm2_mlkem_import_sm2_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char in[PROJECT_SM2_PUBLIC_BYTES])
{
    EC_KEY *key = NULL;

    if (in == NULL || in[0] != POINT_CONVERSION_UNCOMPRESSED)
        return NULL;

    key = EC_KEY_new_by_curve_name_ex(libctx, NULL, NID_sm2);
    if (key == NULL)
        return NULL;

    if (!EC_KEY_oct2key(key, in, PROJECT_SM2_PUBLIC_BYTES, NULL)
        || EC_KEY_check_key(key) != 1) {
        EC_KEY_free(key);
        return NULL;
    }

    return key;
}

static int project_get_public(
    const PROJECT_SM2_MLKEM_KEY *key,
    unsigned char out[PROJECT_SM2_MLKEM_PUBLIC_BYTES])
{
    if (key == NULL || !key->has_public)
        return 0;

    if (!ossl_project_sm2_mlkem_export_sm2_public(key->sm2_key, out))
        return 0;

    memcpy(out + PROJECT_SM2_PUBLIC_BYTES,
           key->mlkem_pk,
           OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES);

    return 1;
}

static int project_get_private(
    const PROJECT_SM2_MLKEM_KEY *key,
    unsigned char out[PROJECT_SM2_MLKEM_PRIVATE_BYTES])
{
    const BIGNUM *sm2_priv;

    if (key == NULL
        || !key->has_private
        || key->sm2_key == NULL)
        return 0;

    sm2_priv = EC_KEY_get0_private_key(key->sm2_key);

    if (sm2_priv == NULL)
        return 0;

    /*
     * Internal Hybrid private representation:
     *
     *   SM2 private scalar || Project ML-KEM dk
     *
     *   32 + 2400 = 2432 bytes.
     */
    if (BN_bn2binpad(
            sm2_priv,
            out,
            PROJECT_SM2_PRIVATE_BYTES)
        != PROJECT_SM2_PRIVATE_BYTES)
        return 0;

    memcpy(
        out + PROJECT_SM2_PRIVATE_BYTES,
        key->mlkem_sk,
        OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES);

    return 1;
}

static int project_set_public(
    PROJECT_SM2_MLKEM_KEY *key,
    const unsigned char *in,
    size_t inlen)
{
    EC_KEY *sm2 = NULL;

    if (key == NULL || in == NULL
        || inlen != PROJECT_SM2_MLKEM_PUBLIC_BYTES)
        return 0;

    if (key->has_public)
        return 0;

    sm2 = ossl_project_sm2_mlkem_import_sm2_public(key->libctx, in);
    if (sm2 == NULL)
        return 0;

    if (!ossl_project_mlkem768_check_public_key(
            in + PROJECT_SM2_PUBLIC_BYTES)) {
        EC_KEY_free(sm2);
        return 0;
    }

    key->sm2_key = sm2;

    memcpy(key->mlkem_pk,
           in + PROJECT_SM2_PUBLIC_BYTES,
           OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES);

    key->has_public = 1;
    key->has_private = 0;

    return 1;
}

static int project_has(const void *vkey, int selection)
{
    const PROJECT_SM2_MLKEM_KEY *key = vkey;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
        && !key->has_private)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0
        && !key->has_public)
        return 0;

    return 1;
}

static int project_match(const void *vkey1,
                         const void *vkey2,
                         int selection)
{
    const PROJECT_SM2_MLKEM_KEY *key1 = vkey1;
    const PROJECT_SM2_MLKEM_KEY *key2 = vkey2;
    unsigned char pub1[PROJECT_SM2_MLKEM_PUBLIC_BYTES];
    unsigned char pub2[PROJECT_SM2_MLKEM_PUBLIC_BYTES];

    if (key1 == NULL || key2 == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1;

    if (!key1->has_public || !key2->has_public)
        return key1->has_public == key2->has_public;

    if (!project_get_public(key1, pub1)
        || !project_get_public(key2, pub2))
        return 0;

    return CRYPTO_memcmp(pub1, pub2, sizeof(pub1)) == 0;
}

static int project_validate(const void *vkey,
                            int selection,
                            int checktype)
{
    const PROJECT_SM2_MLKEM_KEY *key = vkey;

    (void)checktype;

    if (key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        if (!key->has_public
            || key->sm2_key == NULL
            || EC_KEY_check_key(key->sm2_key) != 1
            || !ossl_project_mlkem768_check_public_key(key->mlkem_pk))
            return 0;
    }

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        if (!key->has_private
            || !ossl_project_mlkem768_check_private_key(key->mlkem_sk))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM *project_gettable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return params;
}

static int project_get_params(void *vkey, OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_KEY *key = vkey;
    OSSL_PARAM *p;
    unsigned char pub[PROJECT_SM2_MLKEM_PUBLIC_BYTES];
    unsigned char priv[PROJECT_SM2_MLKEM_PRIVATE_BYTES];

    if (key == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 256))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 192))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL
        && !OSSL_PARAM_set_int(p, PROJECT_SM2_MLKEM_RESPONSE_BYTES))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && key->has_public) {
        if (!project_get_public(key, pub))
            return 0;

        p->return_size = sizeof(pub);

        if (p->data != NULL) {
            if (p->data_type != OSSL_PARAM_OCTET_STRING
                || p->data_size < sizeof(pub))
                return 0;

            memcpy(p->data, pub, sizeof(pub));
        }
    }


    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);

    if (p != NULL && key->has_private) {
        if (!project_get_private(key, priv))
            return 0;

        if (!OSSL_PARAM_set_octet_string(
                p,
                priv,
                sizeof(priv))) {
            OPENSSL_cleanse(priv, sizeof(priv));
            return 0;
        }

        OPENSSL_cleanse(priv, sizeof(priv));
    }

    return 1;
}

static const OSSL_PARAM *project_imexport_types(int selection)
{
    static const OSSL_PARAM types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return types;

    return NULL;
}

static int project_import(void *vkey,
                          int selection,
                          const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    if (key == NULL
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p == NULL)
        p = OSSL_PARAM_locate_const(params,
                                    OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    if (p == NULL
        || !OSSL_PARAM_get_octet_string_ptr(p, &data, &len))
        return 0;

    return project_set_public(key, data, len);
}

static int project_export(void *vkey,
                          int selection,
                          OSSL_CALLBACK *param_cb,
                          void *cbarg)
{
    PROJECT_SM2_MLKEM_KEY *key = vkey;
    unsigned char pub[PROJECT_SM2_MLKEM_PUBLIC_BYTES];
    OSSL_PARAM params[2];

    if (key == NULL || param_cb == NULL
        || (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
        || !project_get_public(key, pub))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY, pub, sizeof(pub));
    params[1] = OSSL_PARAM_construct_end();

    return param_cb(params, cbarg);
}

static const OSSL_PARAM *project_settable_params(void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    (void)provctx;
    return params;
}

static int project_set_params(void *vkey,
                              const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_KEY *key = vkey;
    const OSSL_PARAM *p;
    const void *data = NULL;
    size_t len = 0;

    if (key == NULL)
        return 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params,
                                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);

    if (p == NULL)
        return 1;

    if (!OSSL_PARAM_get_octet_string_ptr(p, &data, &len))
        return 0;

    return project_set_public(key, data, len);
}

static void *project_gen_init(void *provctx,
                              int selection,
                              const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_GEN_CTX *gctx;

    (void)params;

    if ((selection
             & (OSSL_KEYMGMT_SELECT_ALL_PARAMETERS
                | OSSL_KEYMGMT_SELECT_KEYPAIR)) == 0)
        return NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        return NULL;

    gctx->libctx = provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx);
    gctx->selection = selection;

    return gctx;
}

static void *project_gen(void *vgctx,
                         OSSL_CALLBACK *osslcb,
                         void *cbarg)
{
    PROJECT_SM2_MLKEM_GEN_CTX *gctx = vgctx;
    PROJECT_SM2_MLKEM_KEY *key = NULL;

    (void)osslcb;
    (void)cbarg;

    if (gctx == NULL)
        return NULL;

    key = project_key_new_internal(gctx->libctx);
    if (key == NULL)
        return NULL;

    /*
     * Gate G TLS parameter-only object.
     *
     * OpenSSL TLS server first performs EVP_PKEY_paramgen()
     * for the selected TLS group.  No private/public key
     * material must be generated in that operation.
     *
     * The received ClientShare is installed afterwards via
     * OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY.
     */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;


    key->sm2_key =
        EC_KEY_new_by_curve_name_ex(gctx->libctx, NULL, NID_sm2);

    if (key->sm2_key == NULL
        || EC_KEY_generate_key(key->sm2_key) != 1
        || !ossl_project_mlkem768_keypair(
                key->mlkem_pk, key->mlkem_sk)) {
        project_key_free(key);
        return NULL;
    }

    key->has_public = 1;
    key->has_private = 1;

    return key;
}

static void project_gen_cleanup(void *vgctx)
{
    OPENSSL_free(vgctx);
}

static int project_gen_set_params(void *vgctx,
                                  const OSSL_PARAM params[])
{
    PROJECT_SM2_MLKEM_GEN_CTX *gctx = vgctx;

    if (gctx == NULL)
        return 0;

    /*
     * The first project Hybrid milestone has no configurable
     * generation parameters.  Keep the Provider interface pair
     * complete as required by OpenSSL KeyMgmt validation.
     */
    (void)params;

    return 1;
}

static const OSSL_PARAM *project_gen_settable_params(void *gctx,
                                                     void *provctx)
{
    static const OSSL_PARAM params[] = {
        OSSL_PARAM_END
    };

    (void)gctx;
    (void)provctx;

    return params;
}

static void *project_dup(const void *vkey, int selection)
{
    const PROJECT_SM2_MLKEM_KEY *src = vkey;
    PROJECT_SM2_MLKEM_KEY *dst;

    (void)selection;

    if (src == NULL)
        return NULL;

    dst = project_key_new_internal(src->libctx);
    if (dst == NULL)
        return NULL;

    if (src->sm2_key != NULL) {
        dst->sm2_key = EC_KEY_dup(src->sm2_key);
        if (dst->sm2_key == NULL) {
            project_key_free(dst);
            return NULL;
        }
    }

    memcpy(dst->mlkem_pk, src->mlkem_pk, sizeof(dst->mlkem_pk));
    memcpy(dst->mlkem_sk, src->mlkem_sk, sizeof(dst->mlkem_sk));

    dst->has_public = src->has_public;
    dst->has_private = src->has_private;

    return dst;
}


static const char *project_query_operation_name(int operation_id)
{
    if (operation_id == OSSL_OP_KEM)
        return "curveSM2MLKEM768";

    return NULL;
}

const OSSL_DISPATCH ossl_project_sm2_mlkem_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))project_key_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))project_key_free },

    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))project_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))project_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,
      (void (*)(void))project_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,
      (void (*)(void))project_gen_set_params },

    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))project_gen_settable_params },

    { OSSL_FUNC_KEYMGMT_GET_PARAMS,
      (void (*)(void))project_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS,
      (void (*)(void))project_gettable_params },

    { OSSL_FUNC_KEYMGMT_SET_PARAMS,
      (void (*)(void))project_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS,
      (void (*)(void))project_settable_params },

    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))project_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))project_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))project_validate },

    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))project_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,
      (void (*)(void))project_imexport_types },

    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))project_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,
      (void (*)(void))project_imexport_types },

    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
      (void (*)(void))project_query_operation_name },

    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))project_dup },

    OSSL_DISPATCH_END
};
