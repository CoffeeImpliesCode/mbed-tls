/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 *
 * The one header `zig translate-c` reads for this package.
 *
 * It includes no macro of its own and declares nothing of its own. Every
 * declaration the translation carries is the one the named upstream header
 * declares, byte for byte, because none of them is written here.
 *
 * ## Why this file exists
 *
 * `zig translate-c` takes exactly one root source file. The C API is spread
 * over eighty public headers, and a translation rooted at one of them would
 * miss the other seventy-nine. This is that root, and it is the single place
 * that says which headers describe the library this package builds.
 *
 * ## What it includes, and what it deliberately does not
 *
 * `mbedtls/build_info.h` comes first and alone, because it is the header that
 * reads the configuration: it pulls in `mbedtls/mbedtls_config.h` (here, the
 * per-target header `zig/config_gen.zig` generates and `build.zig` points at
 * with `MBEDTLS_CONFIG_FILE`), then `mbedtls/config_psa.h`, then the
 * `config_adjust_*` headers, then `mbedtls/check_config.h`
 * (`src/include/mbedtls/build_info.h:112-192`). Every other header below
 * depends on it and none of them may be read first.
 *
 * `check_config.h` and the four `config_adjust_*` headers are therefore *not*
 * named below. They are included by `build_info.h` already, naming them again
 * would be redundant, and `check_config.h` is a set of `#error` guards with no
 * declarations in it at all.
 *
 * `mbedtls/private_access.h` is likewise not named: upstream marks it
 * `MBEDTLS_PRIVATE`, it is a macro vocabulary for internal use, and including
 * it here would make this package's translation declare upstream's private
 * surface as though it were public. It is not part of the API a provider owes.
 *
 * `psa/crypto_config.h` is not named for a second reason. It is read only when
 * `MBEDTLS_PSA_CRYPTO_CONFIG` is defined
 * (`src/include/mbedtls/build_info.h:134-143`), and the configuration this
 * package generates does not define it: PSA's mechanisms follow the legacy
 * `MBEDTLS_*` options through `mbedtls/config_psa.h`, which is what upstream's
 * own default configuration does. Naming the file here would include a header
 * whose whole content is inside a guard that is not set.
 *
 * Everything else under `psa/` is named, including the driver and composite
 * headers, because `psa/crypto.h` reaches them and because a provider built
 * with the same configuration exports what they declare.
 *
 * ## Why the file list is explicit rather than a glob
 *
 * A glob would silently change what this package's ABI is the next time
 * upstream adds a header, and it would do so in a commit whose diff is one
 * line. These names are the API surface, so a change to them is a change to
 * what a provider must export, and it should read like one.
 */

#ifndef MBED_TLS_ZIG_TRANSLATE_H
#define MBED_TLS_ZIG_TRANSLATE_H

/* Configuration first, and on its own: every other header below reads it. */
#include <mbedtls/build_info.h>

/* libmbedcrypto: the symmetric primitives, public-key primitives, hashing,
 * random generation, ASN.1, PEM, the allocators and the version API. */
#include <mbedtls/aes.h>
#include <mbedtls/aria.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/base64.h>
#include <mbedtls/bignum.h>
#include <mbedtls/block_cipher.h>
#include <mbedtls/camellia.h>
#include <mbedtls/ccm.h>
#include <mbedtls/chacha20.h>
#include <mbedtls/chachapoly.h>
#include <mbedtls/cipher.h>
#include <mbedtls/cmac.h>
#include <mbedtls/constant_time.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/des.h>
#include <mbedtls/dhm.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecjpake.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/hmac_drbg.h>
#include <mbedtls/lms.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/memory_buffer_alloc.h>
#include <mbedtls/nist_kw.h>
#include <mbedtls/oid.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs12.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/pkcs7.h>
#include <mbedtls/platform.h>
#include <mbedtls/platform_time.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/poly1305.h>
#include <mbedtls/psa_util.h>
#include <mbedtls/ripemd160.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha3.h>
#include <mbedtls/sha512.h>
#include <mbedtls/threading.h>
#include <mbedtls/timing.h>
#include <mbedtls/version.h>

/* libmbedx509: X.509 parsing and writing. */
#include <mbedtls/x509.h>
#include <mbedtls/x509_crl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/x509_csr.h>

/* libmbedtls: the TLS stack, its transport, and its diagnostics. */
#include <mbedtls/debug.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/ssl_cookie.h>
#include <mbedtls/ssl_ticket.h>

/* The 3.x compatibility shims, which upstream ships in the public include
 * directory and which this package's translated surface therefore carries. */
#include <mbedtls/compat-2.x.h>

/* PSA Crypto: the API Mbed TLS 3.6 implements over the primitives above. */
#include <psa/crypto.h>
#include <psa/crypto_builtin_composites.h>
#include <psa/crypto_builtin_key_derivation.h>
#include <psa/crypto_builtin_primitives.h>
#include <psa/crypto_compat.h>
#include <psa/crypto_driver_common.h>
#include <psa/crypto_driver_contexts_composites.h>
#include <psa/crypto_driver_contexts_key_derivation.h>
#include <psa/crypto_extra.h>
#include <psa/crypto_legacy.h>
#include <psa/crypto_platform.h>
#include <psa/crypto_se_driver.h>
#include <psa/crypto_sizes.h>
#include <psa/crypto_struct.h>
#include <psa/crypto_types.h>
#include <psa/crypto_values.h>
#include <mbedtls/psa_util.h>

#endif /* MBED_TLS_ZIG_TRANSLATE_H */