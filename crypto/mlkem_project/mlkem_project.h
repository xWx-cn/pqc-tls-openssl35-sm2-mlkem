#ifndef OSSL_CRYPTO_MLKEM_PROJECT_H
#define OSSL_CRYPTO_MLKEM_PROJECT_H
#pragma once

#include <stddef.h>

#define OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES   1184
#define OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES  2400
#define OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES   1088
#define OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES 32

#define OSSL_PROJECT_MLKEM768_KEYGEN_COINS_BYTES 64
#define OSSL_PROJECT_MLKEM768_ENCAP_COINS_BYTES  32

int ossl_project_mlkem768_keypair(
    unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES]);

int ossl_project_mlkem768_keypair_derand(
    unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES],
    const unsigned char coins[OSSL_PROJECT_MLKEM768_KEYGEN_COINS_BYTES]);

int ossl_project_mlkem768_encaps(
    unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES]);

int ossl_project_mlkem768_encaps_derand(
    unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    const unsigned char coins[OSSL_PROJECT_MLKEM768_ENCAP_COINS_BYTES]);

int ossl_project_mlkem768_decaps(
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    const unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES]);

int ossl_project_mlkem768_check_public_key(
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES]);

int ossl_project_mlkem768_check_private_key(
    const unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES]);

#endif
