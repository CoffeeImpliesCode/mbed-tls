// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.

//! Behavioral tests for the Zig facade; vectors come from standards and fixture facts from independent inspection.
//! Mbed TLS uses libc allocation, so these tests check wrapper ownership, not leak detection.

const std = @import("std");
const builtin = @import("builtin");
const mbedtls = @import("mbedtls");
const testing = std.testing;

/// Upstream's published test CA certificate fixture.
const test_ca_pem = @embedFile("fixtures/test-ca.crt");

/// Upstream's published server certificate fixture.
const server_cert_pem = @embedFile("fixtures/server2.crt");

/// Upstream's published server private key fixture in PKCS#1 PEM.
const server_key_pem = @embedFile("fixtures/server2.key");

/// Fixture profile: add SHA-1 to upstream default, which rejects this chain.
/// Keep it alive while a TLS config borrows it.
fn legacySha1() mbedtls.CertificateProfile {
    return mbedtls.CertificateProfile.default().allowingMd(.sha1);
}

/// `MBEDTLS_X509_BADCERT_BAD_MD` flag for a disallowed certificate hash.
const badcert_bad_md: u32 = 0x4000;

/// FIPS 180-4 Appendix B, `SHA-256("abc")`.
const fips_sha256_abc = [_]u8{
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
};

/// FIPS 180-4 Appendix B, `SHA-384("abc")`.
const fips_sha384_abc = [_]u8{
    0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
    0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
    0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7,
};

/// FIPS 180-4 Appendix B, `SHA-512("abc")`.
const fips_sha512_abc = [_]u8{
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
};

/// RFC 1321 Appendix A.1, `SHA-1("abc")`.
const rfc1321_sha1_abc = [_]u8{
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d,
};

/// RFC 4231 §4.2 test case 1.
const rfc4231_case1_key: [20]u8 = @splat(0x0b);
const rfc4231_case1_message = "Hi There";
const rfc4231_case1_tag = [_]u8{
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
    0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7,
};

/// First-block AES-128-CBC vector from NIST SP 800-38A §F.2.1.
const sp800_38a_key = [_]u8{
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};
const sp800_38a_iv = [_]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
const sp800_38a_plaintext = [_]u8{ 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
const sp800_38a_ciphertext = [_]u8{ 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d };

/// NIST SP 800-38D Test Case 2 with empty AAD; ciphertext and tag are independent fixtures.
const gcm_tc2_key: [16]u8 = @splat(0);
const gcm_tc2_iv = [_]u8{ 0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88 };
const gcm_tc2_plaintext = [_]u8{
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
    0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
    0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
};
const gcm_tc2_ciphertext = [_]u8{
    0xb8, 0x53, 0xc0, 0xc0, 0x00, 0x02, 0xa2, 0x4e, 0x8b, 0x35, 0xef, 0xf3, 0xd7, 0x9c, 0x69, 0xce,
    0x24, 0x7a, 0x3a, 0x7a, 0xd8, 0x9d, 0xef, 0x8f, 0x1d, 0x30, 0x88, 0x50, 0xef, 0x5e, 0x31, 0x40,
    0x3b, 0x42, 0x58, 0x78, 0x4b, 0x9e, 0xb5, 0xe6, 0x0a, 0x5b, 0x17, 0x3f, 0x5a, 0x51, 0x28, 0x2a,
    0x92, 0x47, 0xc9, 0x8e, 0x3e, 0x92, 0xbe, 0x29, 0xda, 0x3f, 0xfb, 0x90, 0x1d, 0xd0, 0xa9, 0xa3,
};
const gcm_tc2_tag = [_]u8{
    0x59, 0xe5, 0xdf, 0xc3, 0x7c, 0xb8, 0x7a, 0x2a,
    0xfc, 0x73, 0xc4, 0xd0, 0xd5, 0x8d, 0x23, 0xa8,
};

/// RFC 8439 §2.8.2 ciphertext and tag vector.
const rfc8439_key = [_]u8{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
};
const rfc8439_nonce = [_]u8{ 0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47 };
const rfc8439_aad = [_]u8{ 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
const rfc8439_plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
const rfc8439_ciphertext = [_]u8{
    0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e, 0xc2,
    0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee, 0x62, 0xd6,
    0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b,
    0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36,
    0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58,
    0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc,
    0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
    0x61, 0x16,
};
const rfc8439_tag = [_]u8{
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
    0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
};

/// Invalid bytes used by certificate parse tests.
const not_a_certificate = [32:0]u8{
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

/// Explicit provider path from `MBED_TLS_TEST_PROVIDER`; no default is searched.
const provider_variable = "MBED_TLS_TEST_PROVIDER";

/// Load the explicit runtime provider; each test calls this independently.
/// An unset or empty provider variable returns `NoProviderConfigured`.
fn loadProvider() !void {
    if (comptime mbedtls.runtime_loaded) {
        const named = std.testing.environ.getAlloc(testing.allocator, provider_variable) catch |err| switch (err) {
            error.EnvironmentVariableMissing => return error.NoProviderConfigured,
            else => return err,
        };
        defer testing.allocator.free(named);
        if (named.len == 0) return error.NoProviderConfigured;
        try mbedtls.load(.{ .path = named });
    }
}

test "SHA-256 of abc is the digest FIPS 180-4 prints" {
    try loadProvider();
    var digest: [32]u8 = undefined;
    try mbedtls.hash(.sha256, "abc", &digest);
    try testing.expectEqualSlices(u8, &fips_sha256_abc, &digest);
}

test "SHA-384 and SHA-512 of abc are the digests FIPS 180-4 prints" {
    try loadProvider();
    var wide: [64]u8 = undefined;
    try mbedtls.hash(.sha512, "abc", &wide);
    try testing.expectEqualSlices(u8, &fips_sha512_abc, &wide);

    // SHA-384 uses its own initial value; it is not a truncation of SHA-512.
    var narrow: [48]u8 = undefined;
    try mbedtls.hash(.sha384, "abc", &narrow);
    try testing.expectEqualSlices(u8, &fips_sha384_abc, &narrow);
}

test "SHA-1 of abc is the digest RFC 1321 prints" {
    try loadProvider();
    var digest: [20]u8 = undefined;
    try mbedtls.hash(.sha1, "abc", &digest);
    try testing.expectEqualSlices(u8, &rfc1321_sha1_abc, &digest);
}

test "an empty input hashes to the published empty-message digest" {
    try loadProvider();
    // The empty-message vector catches a lost input length.
    var digest: [32]u8 = undefined;
    try mbedtls.hash(.sha256, "", &digest);
    try testing.expectEqualSlices(u8, &[_]u8{
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
        0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
        0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
        0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
    }, &digest);
}

test "a digest buffer of the wrong length is refused, not truncated" {
    try loadProvider();
    // The sentinel verifies that failure leaves the short output untouched.
    var short: [16]u8 = @splat(0xff);
    try testing.expectError(
        error.OutputLengthWrong,
        mbedtls.hash(.sha256, "abc", &short),
    );
    try testing.expect(std.mem.allEqual(u8, &short, 0xff));
}

test "HMAC-SHA-256 is RFC 4231 test case 1" {
    try loadProvider();
    var tag: [32]u8 = undefined;
    try mbedtls.hmac(.sha256, &rfc4231_case1_key, rfc4231_case1_message, &tag);
    try testing.expectEqualSlices(u8, &rfc4231_case1_tag, &tag);
}

test "AES-128-CBC is the first block NIST SP 800-38A prints" {
    try loadProvider();
    var cipher = try mbedtls.Aes128Cbc.initEncrypt(&sp800_38a_key);
    defer cipher.deinit();

    var iv = sp800_38a_iv;
    var out: [16]u8 = undefined;
    try cipher.crypt(true, &iv, &sp800_38a_plaintext, &out);
    try testing.expectEqualSlices(u8, &sp800_38a_ciphertext, &out);

    // CBC updates the IV to the last ciphertext block.
    try testing.expectEqualSlices(u8, sp800_38a_ciphertext[0..16], &iv);
}

test "AES-128-CBC round-trips through the decryption key" {
    try loadProvider();
    var cipher = try mbedtls.Aes128Cbc.initEncrypt(&sp800_38a_key);
    defer cipher.deinit();
    var iv = sp800_38a_iv;
    var out: [16]u8 = undefined;
    try cipher.crypt(true, &iv, &sp800_38a_plaintext, &out);

    var back = try mbedtls.Aes128Cbc.initDecrypt(&sp800_38a_key);
    defer back.deinit();
    var iv2 = sp800_38a_iv;
    var plain: [16]u8 = undefined;
    try back.crypt(false, &iv2, &out, &plain);
    // The NIST vector above, not this round trip, checks interoperability.
    try testing.expectEqualSlices(u8, &sp800_38a_plaintext, &plain);
}

test "AES-128-CBC refuses a length the mode cannot carry" {
    try loadProvider();
    var cipher = try mbedtls.Aes128Cbc.initEncrypt(&sp800_38a_key);
    defer cipher.deinit();
    var iv = sp800_38a_iv;
    // Seventeen bytes cannot be represented by CBC's whole-block mode.
    var long_plaintext: [17]u8 = @splat(0);
    @memcpy(long_plaintext[0..sp800_38a_plaintext.len], &sp800_38a_plaintext);
    var out: [17]u8 = undefined;
    // CBC rejects incomplete blocks before calling Mbed TLS.
    try testing.expectError(
        error.InvalidLength,
        cipher.crypt(true, &iv, &long_plaintext, &out),
    );
}

test "AES-128-GCM is Test Case 2 of the GCM specification" {
    try loadProvider();
    var gcm = try mbedtls.Aes128Gcm.init(&gcm_tc2_key);
    defer gcm.deinit();

    var out: [gcm_tc2_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try gcm.seal(&gcm_tc2_iv, "", &gcm_tc2_plaintext, &out, &tag);

    try testing.expectEqualSlices(u8, &gcm_tc2_ciphertext, &out);
    try testing.expectEqualSlices(u8, &gcm_tc2_tag, &tag);
}

test "a GCM tag that does not match is refused, and the plaintext is not usable" {
    try loadProvider();
    var gcm = try mbedtls.Aes128Gcm.init(&gcm_tc2_key);
    defer gcm.deinit();

    var out: [gcm_tc2_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try gcm.seal(&gcm_tc2_iv, "", &gcm_tc2_plaintext, &out, &tag);

    // Change only the tag to isolate authentication failure.
    tag[0] ^= 0x01;
    var plain: [gcm_tc2_plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        gcm.open(&gcm_tc2_iv, "", &out, &tag, &plain),
    );
    // Do not read plaintext after authentication failure.
}

test "a GCM nonce of the wrong length is refused rather than reinterpreted" {
    try loadProvider();
    var gcm = try mbedtls.Aes128Gcm.init(&gcm_tc2_key);
    defer gcm.deinit();
    var out: [gcm_tc2_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    // The 8-byte nonce is shorter than the required 96-bit length.
    try testing.expectError(
        error.InvalidIvLength,
        gcm.seal(gcm_tc2_iv[0..8], "", &gcm_tc2_plaintext, &out, &tag),
    );
}

test "ChaCha20-Poly1305 is the RFC 8439 section 2.8.2 example" {
    try loadProvider();
    var aead = try mbedtls.ChaCha20Poly1305.init(&rfc8439_key);
    defer aead.deinit();

    var out: [rfc8439_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try aead.seal(&rfc8439_nonce, &rfc8439_aad, rfc8439_plaintext, &out, &tag);

    // Compare the published RFC ciphertext and tag.
    try testing.expectEqualSlices(u8, rfc8439_ciphertext[0..], out[0..]);
    try testing.expectEqualSlices(u8, &rfc8439_tag, &tag);
}

test "ChaCha20-Poly1305 refuses a modified tag" {
    try loadProvider();
    var aead = try mbedtls.ChaCha20Poly1305.init(&rfc8439_key);
    defer aead.deinit();
    var out: [rfc8439_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try aead.seal(&rfc8439_nonce, &rfc8439_aad, rfc8439_plaintext, &out, &tag);

    tag[15] ^= 0x80;
    var plain: [rfc8439_plaintext.len]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        aead.open(&rfc8439_nonce, &rfc8439_aad, &out, &tag, &plain),
    );
}

test "releasing a cipher context twice is a no-op, not a double free" {
    try loadProvider();
    var cipher = try mbedtls.Aes128Cbc.initEncrypt(&sp800_38a_key);
    try testing.expect(cipher.initialized);
    cipher.deinit();
    try testing.expect(!cipher.initialized);
    // The wrapper's flag makes repeated `deinit` a no-op.
    cipher.deinit();
    try testing.expect(!cipher.initialized);
}

test "an AEAD context whose key was never accepted releases nothing twice" {
    try loadProvider();
    var gcm = try mbedtls.Aes128Gcm.init(&gcm_tc2_key);
    defer gcm.deinit();
    var out: [gcm_tc2_plaintext.len]u8 = undefined;
    var tag: [16]u8 = undefined;
    try gcm.seal(&gcm_tc2_iv, "", &gcm_tc2_plaintext, &out, &tag);

    // Each context must be independent because the build disables `MBEDTLS_THREADING_C`.
    var other = try mbedtls.Aes128Gcm.init(&gcm_tc2_key);
    var other_out: [gcm_tc2_plaintext.len]u8 = undefined;
    var other_tag: [16]u8 = undefined;
    try other.seal(&gcm_tc2_iv, "", &gcm_tc2_plaintext, &other_out, &other_tag);
    try testing.expectEqualSlices(u8, &out, &other_out);
    try testing.expectEqualSlices(u8, &tag, &other_tag);
    other.deinit();
}

test "a key of the wrong length is refused and the context is already released" {
    try loadProvider();
    try testing.expectError(
        error.BadKeyLength,
        mbedtls.Aes128Cbc.initEncrypt(&@as([15]u8, @splat(0))),
    );
    try testing.expectError(
        error.BadKeyLength,
        mbedtls.ChaCha20Poly1305.init(&@as([31]u8, @splat(0))),
    );
    // Failed initialization releases its context before returning.
}

test "the vendored test CA parses to the fields OpenSSL reads out of it" {
    try loadProvider();
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var text: [128]u8 = undefined;
    try testing.expectEqualStrings("C=NL, O=PolarSSL, CN=PolarSSL Test CA", try ca.subject(&text));
    try testing.expectEqualStrings("C=NL, O=PolarSSL, CN=PolarSSL Test CA", try ca.issuer(&text));
    try testing.expectEqualStrings("03", try ca.serial(&text));

    // The fixture's DER encoding is 840 bytes.
    try testing.expectEqual(@as(usize, 840), ca.der().len);

    // X.509 months are one-based; the fixture validity starts in February 2019.
    const from = ca.validFrom();
    try testing.expectEqual(@as(c_int, 2019), from.year);
    try testing.expectEqual(@as(c_int, 2), from.mon);
    try testing.expectEqual(@as(c_int, 10), from.day);
    const to = ca.validTo();
    try testing.expectEqual(@as(c_int, 2029), to.year);

    try testing.expect(ca.isCa());
    try testing.expectEqual(@as(c_int, 3), ca.version());
}

test "the vendored server certificate parses to the fields OpenSSL reads out of it" {
    try loadProvider();
    var server = mbedtls.Certificate.init();
    defer server.deinit();
    try server.parse(server_cert_pem);

    var text: [128]u8 = undefined;
    try testing.expectEqualStrings("C=NL, O=PolarSSL, CN=localhost", try server.subject(&text));
    try testing.expectEqualStrings("C=NL, O=PolarSSL, CN=PolarSSL Test CA", try server.issuer(&text));
    try testing.expectEqualStrings("02", try server.serial(&text));
    try testing.expectEqual(@as(usize, 827), server.der().len);

    // The leaf is not a CA and has a 2048-bit RSA key.
    try testing.expect(!server.isCa());
    try testing.expectEqual(@as(u32, 2048), server.rsaBitLength() orelse return error.NoRsaKey);
}

test "the fixture chain verifies against the fixture CA, and only against it" {
    try loadProvider();
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var server = mbedtls.Certificate.init();
    defer server.deinit();
    try server.parse(server_cert_pem);

    // Verify this SHA-1 fixture with an explicitly widened profile.
    var profile = legacySha1();
    var flags: u32 = 0;
    try server.verifyIntoWithProfile(&ca, &profile, &flags);
    try testing.expectEqual(@as(u32, 0), flags);

    // A leaf cannot verify against itself; assert a reason without pinning its bits.
    var self_flags: u32 = 0;
    try testing.expectError(
        error.Untrusted,
        server.verifyIntoWithProfile(&server, &profile, &self_flags),
    );
    try testing.expect(self_flags != 0);
}

test "the default profile refuses the fixture chain and names SHA-1 as the reason" {
    try loadProvider();
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var server = mbedtls.Certificate.init();
    defer server.deinit();
    try server.parse(server_cert_pem);

    // The SHA-1 fixture chain is rejected by the default SHA-256-and-higher policy.
    var flags: u32 = 0;
    try testing.expectError(
        error.Untrusted,
        server.verifyInto(&ca, &flags),
    );
    // The only flag should identify the disallowed digest.
    try testing.expectEqual(badcert_bad_md, flags);
}

test "bytes that are not a certificate are refused as malformed" {
    try loadProvider();
    var crt = mbedtls.Certificate.init();
    defer crt.deinit();
    // A failed parse may leave partial state; `deinit` still releases it.
    try testing.expectError(
        error.Malformed,
        crt.parse(&not_a_certificate),
    );
    try testing.expect(crt.initialized);
}

test "a truncated certificate is refused rather than half accepted" {
    try loadProvider();
    var crt = mbedtls.Certificate.init();
    defer crt.deinit();
    // The sentinel keeps the parser in PEM mode while the DER is truncated.
    // Incomplete certificate data must return `Malformed`.
    var half: [server_cert_pem.len / 2 + 1 :0]u8 = undefined;
    @memcpy(half[0 .. server_cert_pem.len / 2], server_cert_pem[0 .. server_cert_pem.len / 2]);
    half[half.len - 1] = 0;
    const truncated: [:0]const u8 = &half;
    try testing.expectError(
        error.Malformed,
        crt.parse(truncated),
    );
}

test "a distinguished name that does not fit is refused, not truncated" {
    try loadProvider();
    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var tiny: [8]u8 = undefined;
    // The formatter reports a short buffer instead of returning a truncated name.
    try testing.expectError(error.BufferTooSmall, ca.subject(&tiny));
}

test "a borrowed chain link carries the chain's lifetime, not its own" {
    try loadProvider();
    var chain = mbedtls.Certificate.init();
    defer chain.deinit();
    // Parsing another certificate appends it to the chain.
    try chain.parse(test_ca_pem);
    const before = chain.der().len;
    try chain.parse(server_cert_pem);

    // The head keeps its DER; the appended link holds the second certificate.
    try testing.expectEqual(before, chain.der().len);
    const link = chain.next() orelse return error.NoAppendedLink;
    try testing.expect(link.der().len != before);
    try testing.expectEqual(@as(usize, 827), link.der().len);

    // The link borrows the chain; deinitializing it would free the whole list.
    try testing.expect(link.next() == null);
}

// Loopback handshake tests compile everywhere and skip when `MBEDTLS_NET_C` is unavailable.

/// Whether the resolved target supports the socket transport.
/// Mirrors the `MBEDTLS_NET_C` decision in `config_gen.zig`.
const has_socket_transport = switch (builtin.os.tag) {
    .windows => true,
    .linux, .macos, .ios, .tvos, .watchos, .visionos, .freebsd, .netbsd, .openbsd,
    .dragonfly, .illumos, .hurd, .fuchsia, .haiku,
    => true,
    else => false,
};

/// Fixed high loopback port; `Socket.bindAll` listens on every interface.
/// Conflicts fail; this facade does not provide loopback-only binding.
const test_port = "39443";

/// The request sent by the client and expected from the server.
const test_request = "ping";
const test_response = "pong-from-server";

test "a TLS 1.3 handshake carries a request and an answer" {
    if (!has_socket_transport) return error.SkipZigTest;
    try loadProvider();

    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();

    var ca = mbedtls.Certificate.init();
    defer ca.deinit();
    try ca.parse(test_ca_pem);

    var server_cert = mbedtls.Certificate.init();
    defer server_cert.deinit();
    try server_cert.parse(server_cert_pem);

    var server_key = mbedtls.PrivateKey.init();
    defer server_key.deinit();
    try server_key.parsePem(server_key_pem, &entropy);

    // Open the listener before connecting the client to avoid racing the bind.
    var listener = try mbedtls.Socket.bindAll(test_port);
    defer listener.deinit();

    const Server = struct {
        fn run(
            server_listener: *mbedtls.Socket,
            ca_certificate: *mbedtls.Certificate,
            server_certificate: *mbedtls.Certificate,
            server_private_key: *mbedtls.PrivateKey,
            result: *?mbedtls.HandshakeError,
            exchanged: *?[]u8,
        ) void {
            result.* = null;
            exchanged.* = null;
            // Separate RNG contexts avoid races because `MBEDTLS_THREADING_C` is off.
            var server_entropy = mbedtls.Entropy.init();
            defer server_entropy.deinit();
            var server_drbg = mbedtls.Drbg.init();
            defer server_drbg.deinit();
            server_drbg.seed(&server_entropy) catch {
                result.* = error.InternalError;
                return;
            };

            var config = mbedtls.TlsConfig.init(.server);
            defer config.deinit();
            config.authMode(.none);
            config.rng(&server_drbg);
            config.minVersion(.tls1_3);
            config.maxVersion(.tls1_3);
            config.ownCertificate(server_certificate, server_private_key);
            // The server skips peer verification; the client profile enforces policy.
            var profile = legacySha1();
            config.certProfile(&profile);
            // The server does not verify clients, so the CA chain is unused.
            _ = ca_certificate;

            var connection = mbedtls.Socket.accept(server_listener) catch return;
            defer connection.deinit();

            var endpoint = mbedtls.Endpoint.init();
            defer endpoint.deinit();
            endpoint.setup(&config) catch {
                result.* = error.NegotiationRefused;
                return;
            };
            endpoint.setSocket(&connection);
            endpoint.handshake() catch |err| {
                result.* = err;
                return;
            };

            var request: [32]u8 = undefined;
            const got = endpoint.read(&request) catch {
                result.* = error.ProtocolError;
                return;
            };
            if (got == 0) return;
            _ = endpoint.write(test_response) catch {
                result.* = error.InternalError;
                return;
            };
            endpoint.closeNotify();
            // Report allocation failures through `result`; the thread cannot return errors.
            exchanged.* = std.testing.allocator.dupe(u8, request[0..got]) catch {
                result.* = error.InternalError;
                return;
            };
        }
    };

    var server_result: ?mbedtls.HandshakeError = null;
    var server_saw: ?[]u8 = null;
    const thread = try std.Thread.spawn(.{}, Server.run, .{
        &listener, &ca, &server_cert, &server_key, &server_result, &server_saw,
    });
    // Join before reading thread-written values; defer joins failure paths.
    var joined = false;
    defer if (!joined) thread.join();

    var drbg = mbedtls.Drbg.init();
    defer drbg.deinit();
    try drbg.seed(&entropy);

    var client_config = mbedtls.TlsConfig.init(.client);
    defer client_config.deinit();
    client_config.authMode(.required);
    client_config.rng(&drbg);
    client_config.caChain(&ca);
    client_config.minVersion(.tls1_3);
    client_config.maxVersion(.tls1_3);
    // This handshake opts into SHA-1; the default refusal has its own test.
    var profile = legacySha1();
    client_config.certProfile(&profile);

    var client_socket = try mbedtls.Socket.connect("localhost", test_port);
    defer client_socket.deinit();

    var client = mbedtls.Endpoint.init();
    defer client.deinit();
    try client.setup(&client_config);
    // Setting the hostname enables SNI and certificate hostname verification.
    try client.setHostname("localhost");
    client.setSocket(&client_socket);

    try client.handshake();
    try testing.expectEqualStrings("TLSv1.3", client.negotiatedVersion() orelse return error.NoVersion);
    // Zero verification flags means the peer chain passed the configured policy.
    try testing.expectEqual(@as(u32, 0), client.verifyFlags());

    _ = try client.write(test_request);

    var response: [64]u8 = undefined;
    const length = try client.read(&response);
    try testing.expectEqualStrings(test_response, response[0..length]);
    client.closeNotify();

    // Read thread-written results only after joining.
    thread.join();
    joined = true;
    try testing.expectEqual(@as(?mbedtls.HandshakeError, null), server_result);
    const seen = server_saw orelse return error.NoServerRequest;
    defer std.testing.allocator.free(seen);
    // The server must receive the exact request sent by the client.
    try testing.expectEqualStrings(test_request, seen);
}

test "a client with no trust anchor refuses the server's certificate" {
    if (!has_socket_transport) return error.SkipZigTest;
    try loadProvider();

    var entropy = mbedtls.Entropy.init();
    defer entropy.deinit();

    var server_cert = mbedtls.Certificate.init();
    defer server_cert.deinit();
    try server_cert.parse(server_cert_pem);

    var server_key = mbedtls.PrivateKey.init();
    defer server_key.deinit();
    try server_key.parsePem(server_key_pem, &entropy);

    var listener = try mbedtls.Socket.bindAll("39444");
    defer listener.deinit();

    const Server = struct {
        fn run(
            server_listener: *mbedtls.Socket,
            cert: *mbedtls.Certificate,
            key: *mbedtls.PrivateKey,
            refused: *?bool,
        ) void {
            refused.* = false;
            // Separate entropy contexts avoid races because `MBEDTLS_THREADING_C` is off.
            var server_entropy = mbedtls.Entropy.init();
            defer server_entropy.deinit();
            var server_drbg = mbedtls.Drbg.init();
            defer server_drbg.deinit();
            server_drbg.seed(&server_entropy) catch return;

            var config = mbedtls.TlsConfig.init(.server);
            defer config.deinit();
            config.authMode(.none);
            config.rng(&server_drbg);
            config.ownCertificate(cert, key);

            var connection = mbedtls.Socket.accept(server_listener) catch return;
            defer connection.deinit();
            var endpoint = mbedtls.Endpoint.init();
            defer endpoint.deinit();
            endpoint.setup(&config) catch return;
            endpoint.setSocket(&connection);
            if (endpoint.handshake()) |_| {
                // A successful server handshake would invalidate this refusal test.
            } else |_| {
                refused.* = true;
            }
        }
    };

    var server_saw_refusal: ?bool = null;
    const thread = try std.Thread.spawn(.{}, Server.run, .{
        &listener, &server_cert, &server_key, &server_saw_refusal,
    });
    defer thread.join();

    // Required verification with no CA chain must reject the server certificate.
    var drbg = mbedtls.Drbg.init();
    defer drbg.deinit();
    try drbg.seed(&entropy);

    var client_config = mbedtls.TlsConfig.init(.client);
    defer client_config.deinit();
    client_config.authMode(.required);
    client_config.rng(&drbg);
    client_config.minVersion(.tls1_3);
    client_config.maxVersion(.tls1_3);

    var client_socket = try mbedtls.Socket.connect("localhost", "39444");
    defer client_socket.deinit();

    var client = mbedtls.Endpoint.init();
    defer client.deinit();
    try client.setup(&client_config);
    try client.setHostname("localhost");
    client.setSocket(&client_socket);

    // Required verification without CA anchors returns `NegotiationRefused`.
    // Verification flags separately record that the peer chain is untrusted.
    try testing.expectError(
        mbedtls.HandshakeError.NegotiationRefused,
        client.handshake(),
    );
    // `verifyFlags` still records `NOT_TRUSTED` for the peer certificate.
    try testing.expect(client.verifyFlags() & 0x08 != 0);
}

test "a socket closes once and closing twice does not close it again" {
    if (!has_socket_transport) return error.SkipZigTest;
    try loadProvider();
    var socket = try mbedtls.Socket.bindAll("39445");
    try testing.expect((try socket.descriptor()) >= 0);
    socket.deinit();
    // After close, the descriptor is invalid and a repeat `deinit` is a no-op.
    try testing.expectError(error.InvalidContext, socket.descriptor());
    socket.deinit();
}
