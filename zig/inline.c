/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * See FORK-LICENSE.md for what that identifier covers.
 */

#include <mbedtls/cipher.h>

/* These local entry points preserve C bitfield access and the target ABI.
 * zig/translate.h maps the public inline names to this namespace.
 */
mbedtls_cipher_type_t zig_mbedtls_cipher_info_get_type(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_type(info);
}

mbedtls_cipher_mode_t zig_mbedtls_cipher_info_get_mode(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_mode(info);
}

size_t zig_mbedtls_cipher_info_get_key_bitlen(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_key_bitlen(info);
}

const char *zig_mbedtls_cipher_info_get_name(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_name(info);
}

size_t zig_mbedtls_cipher_info_get_iv_size(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_iv_size(info);
}

size_t zig_mbedtls_cipher_info_get_block_size(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_get_block_size(info);
}

int zig_mbedtls_cipher_info_has_variable_key_bitlen(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_has_variable_key_bitlen(info);
}

int zig_mbedtls_cipher_info_has_variable_iv_size(const mbedtls_cipher_info_t *info)
{
    return mbedtls_cipher_info_has_variable_iv_size(info);
}

unsigned int zig_mbedtls_cipher_get_block_size(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_block_size(ctx);
}

mbedtls_cipher_mode_t zig_mbedtls_cipher_get_cipher_mode(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_cipher_mode(ctx);
}

int zig_mbedtls_cipher_get_iv_size(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_iv_size(ctx);
}

mbedtls_cipher_type_t zig_mbedtls_cipher_get_type(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_type(ctx);
}

const char *zig_mbedtls_cipher_get_name(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_name(ctx);
}

int zig_mbedtls_cipher_get_key_bitlen(const mbedtls_cipher_context_t *ctx)
{
    return mbedtls_cipher_get_key_bitlen(ctx);
}
