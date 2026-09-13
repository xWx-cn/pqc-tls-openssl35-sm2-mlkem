#ifndef OSSL_PROV_MLKEM_PROJECT_H
#define OSSL_PROV_MLKEM_PROJECT_H
#pragma once

#include <openssl/types.h>
#include "crypto/mlkem_project/mlkem_project.h"

typedef struct project_mlkem768_key_st {
    OSSL_LIB_CTX *libctx;

    unsigned char ek[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES];
    unsigned char dk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES];

    int has_public;
    int has_private;
} PROJECT_MLKEM768_KEY;

#endif
