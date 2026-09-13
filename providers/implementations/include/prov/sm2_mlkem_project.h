#ifndef OSSL_PROV_SM2_MLKEM_PROJECT_H
#define OSSL_PROV_SM2_MLKEM_PROJECT_H
#pragma once

#include "internal/deprecated.h"
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include "crypto/mlkem_project/mlkem_project.h"

#define PROJECT_SM2_PUBLIC_BYTES 65
#define PROJECT_SM2_SECRET_BYTES 32
#define PROJECT_SM2_PRIVATE_BYTES 32

#define PROJECT_SM2_MLKEM_PUBLIC_BYTES \
    (PROJECT_SM2_PUBLIC_BYTES + OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES)

#define PROJECT_SM2_MLKEM_RESPONSE_BYTES \
    (PROJECT_SM2_PUBLIC_BYTES + OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES)

#define PROJECT_SM2_MLKEM_SECRET_BYTES \
    (PROJECT_SM2_SECRET_BYTES + OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES)


#define PROJECT_SM2_MLKEM_PRIVATE_BYTES \
    (PROJECT_SM2_PRIVATE_BYTES + OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES)

typedef struct project_sm2_mlkem_key_st {
    OSSL_LIB_CTX *libctx;

    EC_KEY *sm2_key;

    unsigned char mlkem_pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES];
    unsigned char mlkem_sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES];

    int has_public;
    int has_private;
} PROJECT_SM2_MLKEM_KEY;

int ossl_project_sm2_mlkem_export_sm2_public(
    const EC_KEY *key,
    unsigned char out[PROJECT_SM2_PUBLIC_BYTES]);

EC_KEY *ossl_project_sm2_mlkem_import_sm2_public(
    OSSL_LIB_CTX *libctx,
    const unsigned char in[PROJECT_SM2_PUBLIC_BYTES]);

#endif
