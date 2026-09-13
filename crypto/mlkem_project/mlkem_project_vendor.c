/*
 * Project ML-KEM-768 portable implementation.
 *
 * The underlying source is vendored from mlkem-native v1.2.0.
 * Native/assembly backends are intentionally disabled in this milestone.
 */

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_NAMESPACE_PREFIX ossl_project_mlkem768_native
#define MLK_CONFIG_NO_RANDOMIZED_API
#define MLK_CONFIG_NO_SUPERCOP

#include "vendor/mlkem/mlkem_native.c"
