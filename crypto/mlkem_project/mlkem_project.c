#include "mlkem_project.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

int ossl_project_mlkem768_native_keypair_derand(
    unsigned char *pk,
    unsigned char *sk,
    const unsigned char *coins);

int ossl_project_mlkem768_native_enc_derand(
    unsigned char *ct,
    unsigned char *ss,
    const unsigned char *pk,
    const unsigned char *coins);

int ossl_project_mlkem768_native_dec(
    unsigned char *ss,
    const unsigned char *ct,
    const unsigned char *sk);

int ossl_project_mlkem768_native_check_pk(
    const unsigned char *pk);

int ossl_project_mlkem768_native_check_sk(
    const unsigned char *sk);

int ossl_project_mlkem768_keypair_derand(
    unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES],
    const unsigned char coins[OSSL_PROJECT_MLKEM768_KEYGEN_COINS_BYTES])
{
    if (pk == NULL || sk == NULL || coins == NULL)
        return 0;

    return ossl_project_mlkem768_native_keypair_derand(pk, sk, coins) == 0;
}

int ossl_project_mlkem768_keypair(
    unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES])
{
    unsigned char coins[OSSL_PROJECT_MLKEM768_KEYGEN_COINS_BYTES];
    int ret = 0;

    if (pk == NULL || sk == NULL)
        return 0;

    if (RAND_priv_bytes(coins, sizeof(coins)) <= 0)
        goto end;

    ret = ossl_project_mlkem768_keypair_derand(pk, sk, coins);

end:
    OPENSSL_cleanse(coins, sizeof(coins));
    return ret;
}

int ossl_project_mlkem768_encaps_derand(
    unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES],
    const unsigned char coins[OSSL_PROJECT_MLKEM768_ENCAP_COINS_BYTES])
{
    if (ct == NULL || ss == NULL || pk == NULL || coins == NULL)
        return 0;

    return ossl_project_mlkem768_native_enc_derand(
               ct, ss, pk, coins) == 0;
}

int ossl_project_mlkem768_encaps(
    unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES])
{
    unsigned char coins[OSSL_PROJECT_MLKEM768_ENCAP_COINS_BYTES];
    int ret = 0;

    if (ct == NULL || ss == NULL || pk == NULL)
        return 0;

    if (RAND_priv_bytes(coins, sizeof(coins)) <= 0)
        goto end;

    ret = ossl_project_mlkem768_encaps_derand(ct, ss, pk, coins);

end:
    OPENSSL_cleanse(coins, sizeof(coins));
    return ret;
}

int ossl_project_mlkem768_decaps(
    unsigned char ss[OSSL_PROJECT_MLKEM768_SHARED_SECRET_BYTES],
    const unsigned char ct[OSSL_PROJECT_MLKEM768_CIPHERTEXT_BYTES],
    const unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES])
{
    if (ss == NULL || ct == NULL || sk == NULL)
        return 0;

    return ossl_project_mlkem768_native_dec(ss, ct, sk) == 0;
}

int ossl_project_mlkem768_check_public_key(
    const unsigned char pk[OSSL_PROJECT_MLKEM768_PUBLIC_KEY_BYTES])
{
    if (pk == NULL)
        return 0;

    return ossl_project_mlkem768_native_check_pk(pk) == 0;
}

int ossl_project_mlkem768_check_private_key(
    const unsigned char sk[OSSL_PROJECT_MLKEM768_PRIVATE_KEY_BYTES])
{
    if (sk == NULL)
        return 0;

    return ossl_project_mlkem768_native_check_sk(sk) == 0;
}
