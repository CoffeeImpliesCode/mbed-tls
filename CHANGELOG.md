# Changelog

- Port to Zig 0.17.0.
- Generate target configuration exhaustively for Zig CPU architectures and disable platform entropy where sockets are unavailable.
- Link Windows builds with `bcrypt` and `ws2_32`; expose FreeBSD's `explicit_bzero` declaration with `__BSD_VISIBLE`.
- Install `mbedtls/private_access.h`, `mbedtls/check_config.h`, and the PSA headers required by installed public headers.
- Preserve upstream-disabled options in generated per-target configuration headers.
- Correct `Certificate.subject` and `Certificate.issuer` to call `mbedtls_x509_dn_gets`; document serial numbers as uppercase hex.
- Compile `pkcs7.c` in the X.509 archive, matching upstream's source graph.
- Add explicit runtime loading with provider validation and prefixed synchronization.
- Publish one `mbedtls` Zig module over the translated public C API and the three native archives.
- Replace CMake/Make build invocation with a Zig graph that builds upstream ABI-named libraries and a target configuration header.
- Import Mbed TLS 3.6.7 release sources and handshake fixtures without modifying upstream files.
