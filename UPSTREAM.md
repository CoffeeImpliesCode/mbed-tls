# Upstream

## Source identity

| Field | Value |
|---|---|
| Project | Mbed TLS, Arm / Trusted Firmware group |
| Project site | <https://mbed-tls.readthedocs.io/> |
| Repository | <https://github.com/Mbed-TLS/mbedtls> |
| Branch | `mbedtls-3.6` (long-term support) |
| Release tag | `mbedtls-3.6.7` |
| Annotated tag object | `627361b09e6f6e3eac756297a370a591cf310ab9` |
| Commit | `068ff080b369adfac81509f9b57b2afabaf82dc5` |
| Release date | 2026-07-07 |
| Artifact | `mbedtls-3.6.7.tar.bz2` (5,473,689 bytes) |
| Release URL | <https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2> |
| SHA-256 | `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6` |
| Digest source | Matches upstream's published `mbedtls-3.6.7-sha256sum.txt` asset |

## Import

The official 3.6.7 release tarball was imported as upstream source; the tarball digest was checked against the checksum asset published with the release. There is no upstream Git history or patch series in this tree. `UPSTREAM.sha256` records the digests of all 336 imported paths, including the preserved upstream README.

| Imported path group | Files |
|---|---:|
| `src/include/` | 99 |
| `src/library/` | 177 |
| `src/3rdparty/` | 38 |
| `src/configs/` | 14 |
| `src/LICENSE` | 1 |
| `src/framework-LICENSE` | 1 |
| `src/ChangeLog` | 1 |
| `src/SECURITY.md` | 1 |
| `fixtures/` | 3 |
| `README.upstream.md` | 1 |
| **Total** | **336** |

The release's `README.md` is preserved byte-for-byte as `README.upstream.md`; the fork's `README.md` is separate. No imported path was modified. The imported set is `src/`, `fixtures/`, and `README.upstream.md`; all fork-authored paths outside that set are covered by `FORK-LICENSE.md` and listed in `NOTICE.md`.

## Files not included

No file from the recorded 336-path import set was removed. The `mbedtls-framework` Git submodule, `scripts/`, and example programs such as `programs/ssl/ssl_server2.c` are absent from the release tarball; they were not removed from this import.
