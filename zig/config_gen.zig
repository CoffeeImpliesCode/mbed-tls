// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! The per-target Mbed TLS configuration header generator.
//!
//! `build.zig` runs this on the *build machine* and gives it the facts of the
//! *target being built*. It reads this package's own copy of upstream's
//! `src/include/mbedtls/mbedtls_config.h` and writes one complete
//! configuration header for that target, which `build.zig` then reaches with
//! `-DMBEDTLS_CONFIG_FILE='"mbed_tls_target_config.h"'` and the generated
//! directory on the include path.
//!
//! ## Why a generator and not a checked-in header
//!
//! Mbed TLS's configuration is the whole feature set *and* several struct
//! layouts, buffer sizes and preconditions. Some of it genuinely depends on
//! which target is being built, and upstream's own answer to that is its
//! `Configure` script. A checked-in header is the wrong shape for it in three
//! ways, and each of them is a defect this generator is here to avoid:
//!
//!   * It would be one header for every target. The target-dependent decisions
//!     below are not cosmetic: `src/library/aes.c:33-45` `#error`s if
//!     `MBEDTLS_PADLOCK_C` is set on a target that is not 32-bit x86, and
//!     `src/library/net_sockets.c:22-24` `#error`s if `MBEDTLS_NET_C` is set
//!     anywhere that is not unix-like or Windows.
//!   * Copying host macros onto a cross target is the failure this workspace
//!     rules out by name. A header generated on this machine from this
//!     machine's answers is exactly that. So this program never asks what
//!     machine it is on: `builtin.target` appears nowhere below, and every
//!     fact arrives as an argument from `build.zig`, which knows the resolved
//!     target.
//!   * Upstream's file is 4 446 lines, most of it documentation, and it is
//!     regenerated on every upstream release. Reading it and re-emitting the
//!     *options* - rather than hand-maintaining a second copy of them - is what
//!     makes a re-sync a diff of one generated file instead of a re-audit of
//!     four hundred lines.
//!
//! ## What it preserves and what it drops
//!
//! It preserves every option name, every option's value, upstream's
//! enabled-or-disabled decision, and the order they appear in, so the generated
//! file can be read beside upstream's and a changed decision is visible as a
//! changed line. It drops upstream's documentation comments, because the
//! generated header is an input to a C compiler rather than a document, and
//! because carrying 4 000 lines of prose into every build's output would bury
//! the four decisions that actually differ between targets.
//!
//! Every dropped comment is upstream's own text in upstream's own file, which
//! `README.upstream.md` and `src/` still carry byte for byte, so nothing is
//! lost - only moved.
//!
//! ## What it refuses to do
//!
//! It does not guess. A line that looks like a configuration directive but does
//! not parse, an upstream file with no directives in it, an architecture or
//! operating system this generator has never been told about, a target-derived
//! decision that would leave an option undefined that the compiler will reject
//! for its absence: each of those stops the build with a message naming the
//! input, rather than producing a header that is quietly wrong for a target
//! nobody looked at.

const std = @import("std");
const Io = std.Io;

/// The name of the header this program writes.
///
/// It is deliberately *not* `mbedtls_config.h`. Upstream's `build_info.h`
/// reaches that name with a quoted include, which resolves relative to the
/// directory `build_info.h` itself is in before any `-I` directory is
/// consulted (`src/include/mbedtls/build_info.h:112-116`), so a file of that
/// name placed on the include path would never be found. This name is reached
/// through `-DMBEDTLS_CONFIG_FILE`, which upstream documents for exactly this
/// purpose, and it cannot shadow anything.
pub const output_basename = "mbed_tls_target_config.h";

/// What this program was told about the target.
const Params = struct {
    /// `std.Target.Cpu.Arch` tag name, as `-Dtarget=` would spell it: `x86_64`,
    /// `aarch64`, `riscv64`, `wasm32`, and so on.
    arch: []const u8 = "",
    /// `std.Target.Os.Tag` tag name: `linux`, `macos`, `windows`, `wasi`, ...
    os: []const u8 = "",
    /// `std.Target.Abi` tag name: `gnu`, `none`, `musl`, ...
    abi: []const u8 = "",
    /// The target's Zig triple, for the banner and for diagnostics only.
    triple: []const u8 = "",
    /// `"little"` or `"big"`.
    endian: []const u8 = "",
    /// Pointer width in bits: 32 or 64.
    ptr_bits: u32 = 0,

    /// Resolves `--arch` to the architecture `Arch.of` decides on.
    ///
    /// `Arch.Name` is the published 53-platform matrix's set of
    /// `std.Target.Cpu.Arch` tags, all 21 of them. An architecture outside it
    /// resolves to null here and is refused by name in `Options.parse`, so the
    /// matrix is covered exhaustively and nothing beyond it is guessed at.
    fn archName(self: Params) ?Arch.Name {
        return Arch.Name.parse(self.arch);
    }

    /// The architectural facts the target-derived decisions below are written
    /// against, one architecture at a time.
    const Arch = struct {
        /// One architecture `build.zig` passes, as a comptime value.
        ///
        /// The name is spelled here once and resolved here, so `Arch.of` below
        /// can be an ordinary exhaustive `switch` over an enum - which Zig
        /// checks at compile time, with no `else`. A string cannot be switched
        /// on at runtime, so the enum is also what makes the exhaustiveness
        /// checkable rather than merely intended.
        const Name = enum {
            // x86.
            x86_64,
            x86,
            // Arm.
            aarch64,
            aarch64_be,
            arm,
            armeb,
            thumb,
            thumbeb,
            // RISC-V.
            riscv64,
            riscv32,
            // PowerPC.
            powerpc64,
            powerpc64le,
            powerpc,
            // MIPS.
            mips64,
            mips64el,
            mips,
            mipsel,
            // The rest of the published matrix.
            s390x,
            wasm32,
            wasm64,
            loongarch64,
            hexagon,

            /// Resolves one `std.Target.Cpu.Arch` tag name.
            ///
            /// Returns null for a name outside the matrix; `Options.parse`
            /// refuses it by name. This is a lookup, not a decision: it adds no
            /// architectural knowledge of its own.
            fn parse(name: []const u8) ?Name {
                inline for (@typeInfo(Name).@"enum".fields) |field| {
                    if (std.mem.eql(u8, name, field.name)) return @enumFromInt(field.value);
                }
                return null;
            }
        };

        /// `MBEDTLS_ARCH_IS_X64`, from `__x86_64__`.
        x86_64: bool,
        /// `MBEDTLS_ARCH_IS_X86`, from `__i386__`. 32-bit x86 only.
        x86_32: bool,
        /// `MBEDTLS_ARCH_IS_ARM32`, from `__arm__`/`__thumb__`/`__thumb2__`.
        arm32: bool,
        /// `MBEDTLS_ARCH_IS_ARM64`, from `__aarch64__`.
        arm64: bool,

        /// The exhaustive decision, one architecture at a time.
        ///
        /// Every branch names what the pinned compiler *predefines* for that
        /// target, read out of it rather than assumed from the family, and
        /// every branch is listed even where the answer repeats: `hexagon`
        /// and `loongarch64` are as visible here as `x86_64` is. There is no
        /// `else`, so adding an architecture to `Name` without deciding it
        /// here is a compile error naming the architecture that was left
        /// undecided - which is the whole point of not falling through to a
        /// default.
        ///
        /// Only x86 and Arm turn a hardware option on, and each for upstream's
        /// own stated reason: `aesni.h:23-24` compiles AES-NI under
        /// `MBEDTLS_ARCH_IS_X64 || MBEDTLS_ARCH_IS_X86`, `aesce.h:23-26`
        /// under `MBEDTLS_ARCH_IS_ARMV8_A`, and `padlock.h:33-36` under
        /// `MBEDTLS_ARCH_IS_X86`. Every other architecture gets an empty
        /// object from those units, so an option left on for it would be dead
        /// configuration a reader cannot tell from a live one.
        fn of(name: Name) Arch {
            return switch (name) {
                .x86_64 => .{ .x86_64 = true, .x86_32 = false, .arm32 = false, .arm64 = false },
                .x86 => .{ .x86_64 = false, .x86_32 = true, .arm32 = false, .arm64 = false },

                // `aarch64_be` is 64-bit Arm in the other byte order and still
                // predefines `__aarch64__`, so it is `arm64`; verified against
                // the pinned compiler. `thumb`/`thumbeb` predefine `__thumb__`
                // and `__thumb2__`, which `build_info.h:47-51` counts as
                // `MBEDTLS_ARCH_IS_ARM32`; also verified.
                .aarch64, .aarch64_be => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = true },
                .arm, .armeb, .thumb, .thumbeb => .{ .x86_64 = false, .x86_32 = false, .arm32 = true, .arm64 = false },

                .riscv64, .riscv32 => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .powerpc64, .powerpc64le, .powerpc => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .mips64, .mips64el, .mips, .mipsel => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .s390x => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .wasm32, .wasm64 => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .loongarch64 => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
                .hexagon => .{ .x86_64 = false, .x86_32 = false, .arm32 = false, .arm64 = false },
            };
        }
    };

    /// Whether the target has the platform interfaces `MBEDTLS_NET_C` needs.
    ///
    /// This is upstream's own rule, read out of
    /// `src/library/common.h:34-46` and enforced by
    /// `src/library/net_sockets.c:22-24`: `MBEDTLS_PLATFORM_IS_UNIXLIKE` is
    /// defined from `unix`, `__unix`, `__unix__`, `__APPLE__` with `__MACH__`,
    /// `__HAIKU__` or `__midipix__`, and `_WIN32` takes priority over all of
    /// them. The list below is the set of Zig OS tags for which a C compiler
    /// defines at least one of those, written out rather than derived from a
    /// heuristic because the whole point of this function is that the rule is
    /// upstream's and must be traceable to a line.
    fn sockets(self: Params) bool {
        const unix_like = [_][]const u8{
            "linux",   "macos",  "ios",     "tvos",      "watchos", "visionos",
            "freebsd", "netbsd", "openbsd", "dragonfly", "illumos", "hurd",
            "fuchsia", "haiku",
        };
        for (unix_like) |name| {
            if (std.mem.eql(u8, self.os, name)) return true;
        }
        // Windows, including MinGW: `_WIN32` is defined either way.
        return std.mem.eql(u8, self.os, "windows");
    }
};

/// One option as it appears in the generated header.
const Option = struct {
    name: []const u8,
    /// The value upstream wrote, empty for a bare `#define`. A trailing
    /// `/**< ... */` is stripped; see `stripTrailingDoc`.
    value: []const u8,
    /// What upstream's own file decided: a `#define` is true, a `//#define` is
    /// false.
    upstream_enabled: bool,
    /// What the generated header says. Equal to `upstream_enabled` unless a
    /// target-derived adjustment below changed it.
    enabled: bool,
    /// Why it changed, or empty when it did not. Only ever non-empty for one of
    /// the four adjustments, and every adjustment carries an upstream line.
    reason: []const u8 = "",
};

fn usage() void {
    std.debug.print(
        \\usage: config-gen --upstream <mbedtls_config.h> --output <path>
        \\                 --arch <name> --os <name> --abi <name>
        \\                 [--triple <t>] [--endian little|big] [--ptr-bits N]
        \\
        \\Every target fact arrives as an argument. This program never asks what
        \\machine it is running on, because the header it writes describes the
        \\target it is told about, not the machine that happens to run it.
        \\
    , .{});
}

const Failure = error{
    UnknownArgument,
    MissingArgument,
    MissingUpstream,
    MissingOutput,
    MissingTargetFacts,
    UnknownArchitecture,
    UnknownOperatingSystem,
    UnparseableDirective,
    EmptyUpstreamConfig,
} || std.mem.Allocator.Error || Io.Writer.Error;

const Options = struct {
    upstream: []const u8 = "",
    output: []const u8 = "",
    params: Params = .{},
    endian_given: bool = false,
    ptr_given: bool = false,

    fn parse(args: []const [:0]const u8) Failure!Options {
        var self: Options = .{};
        var index: usize = 1;
        while (index < args.len) : (index += 1) {
            const flag = args[index];
            const value = take(args, &index);
            if (std.mem.eql(u8, flag, "--upstream")) {
                self.upstream = value;
            } else if (std.mem.eql(u8, flag, "--output")) {
                self.output = value;
            } else if (std.mem.eql(u8, flag, "--arch")) {
                self.params.arch = value;
            } else if (std.mem.eql(u8, flag, "--os")) {
                self.params.os = value;
            } else if (std.mem.eql(u8, flag, "--abi")) {
                self.params.abi = value;
            } else if (std.mem.eql(u8, flag, "--triple")) {
                self.params.triple = value;
            } else if (std.mem.eql(u8, flag, "--endian")) {
                self.params.endian = value;
                self.endian_given = true;
            } else if (std.mem.eql(u8, flag, "--ptr-bits")) {
                self.params.ptr_bits = std.fmt.parseInt(u32, value, 10) catch
                    return error.MissingArgument;
                self.ptr_given = true;
            } else {
                std.debug.print("zig/config_gen.zig: unknown argument '{s}'\n", .{flag});
                return error.UnknownArgument;
            }
        }
        if (self.upstream.len == 0) return error.MissingUpstream;
        if (self.output.len == 0) return error.MissingOutput;
        if (self.params.arch.len == 0 or self.params.os.len == 0) return error.MissingTargetFacts;
        if (self.params.archName() == null) {
            std.debug.print(
                "zig/config_gen.zig: this generator has no rule for architecture " ++
                    "'{s}'. It is outside the published 53-platform matrix; add " ++
                    "it to `Arch.Name` and decide it in `Arch.of` from what the " ++
                    "compiler predefines for it, rather than falling " ++
                    "through to a default.\n",
                .{self.params.arch},
            );
            return error.UnknownArchitecture;
        }
        if (!self.endian_given or !self.ptr_given) {
            std.debug.print(
                "zig/config_gen.zig: --endian and --ptr-bits are required so that a " ++
                    "header's banner names every fact it was written from.\n",
                .{},
            );
            return error.MissingTargetFacts;
        }
        return self;
    }
};

fn take(args: []const [:0]const u8, index: *usize) []const u8 {
    if (index.* + 1 >= args.len) return "";
    index.* += 1;
    return args[index.*];
}

pub fn main(init: std.process.Init) !void {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    const options = Options.parse(args) catch |err| {
        usage();
        return err;
    };

    const upstream = try Io.Dir.cwd().readFileAlloc(
        init.io,
        options.upstream,
        arena,
        .limited(8 * 1024 * 1024),
    );

    const text = try render(arena, upstream, options.params);
    try Io.Dir.cwd().writeFile(init.io, .{
        .sub_path = options.output,
        .data = text,
    });
}

/// Renders the whole configuration header for `params`.
///
/// Exposed as a function rather than only through `main` so that the shape of
/// the output can be read, reviewed and reasoned about without running
/// anything.
pub fn render(
    arena: std.mem.Allocator,
    upstream: []const u8,
    params: Params,
) Failure![]u8 {
    var options = std.ArrayList(Option).empty;
    defer options.deinit(arena);
    try parseUpstream(arena, upstream, &options);

    var adjusted: usize = 0;
    try applyTargetDecisions(arena, &options, params, &adjusted);

    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;
    try writeBanner(w, params, options.items, adjusted);
    try w.writeAll("\n#ifndef MBED_TLS_TARGET_CONFIG_H\n#define MBED_TLS_TARGET_CONFIG_H\n");
    try w.writeAll(
        \\
        \\/* Upstream's own option set, in upstream's own order, with upstream's own
        \\ * enabled/disabled decision. Each line below is a `#define` that
        \\ * src/include/mbedtls/mbedtls_config.h has, or a `#undef` where it
        \\ * has a commented-out one. The documentation above each option in that
        \\ * file is not repeated here; src/include/mbedtls/mbedtls_config.h still
        \\ * carries it, byte for byte.
        \\ */
        \\
    );
    for (options.items) |option| {
        try writeOption(w, option);
    }
    try w.writeAll("\n#endif /* MBED_TLS_TARGET_CONFIG_H */\n");
    return out.written();
}

fn writeOption(w: *std.Io.Writer, option: Option) !void {
    if (!option.enabled) {
        try w.print("/* #undef {s} */", .{option.name});
        if (option.reason.len != 0) {
            try w.print(" /* {s} */", .{option.reason});
        }
        try w.writeAll("\n");
        return;
    }
    if (option.value.len == 0) {
        try w.print("#define {s}", .{option.name});
    } else {
        try w.print("#define {s} {s}", .{ option.name, option.value });
    }
    if (option.reason.len != 0) {
        try w.print(" /* {s} */", .{option.reason});
    }
    try w.writeAll("\n");
}

fn writeBanner(
    w: *std.Io.Writer,
    params: Params,
    options: []const Option,
    adjusted: usize,
) !void {
    var enabled: usize = 0;
    for (options) |option| {
        if (option.upstream_enabled) enabled += 1;
    }
    try w.writeAll(
        \\/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
        \\ * Copyright The Mbed TLS Contributors
        \\ *
        \\ * GENERATED FILE - DO NOT EDIT.
        \\ *
        \\ * Written by zig/config_gen.zig, run by build.zig on the build machine
        \\ * for the target named below. Every fact in this banner arrived as a
        \\ * command-line argument; nothing here describes the machine that ran
        \\ * the generator. Delete this file and build again to regenerate it.
        \\ *
        \\ * The source is this package's own copy of upstream's configuration
        \\ * header, src/include/mbedtls/mbedtls_config.h. It is reached through
        \\ * -DMBEDTLS_CONFIG_FILE, which src/include/mbedtls/build_info.h:112-116
        \\ * documents for exactly this purpose; upstream's own name cannot be
        \\ * overridden by an include path, because the include that would reach
        \\ * it is quoted and therefore resolves beside build_info.h first.
        \\ *
        \\ * Installed as include/mbedtls/mbedtls_config.h, because the
        \\ * configuration a dependent compiles against has to be the
        \\ * configuration this library was built with.
        \\
        \\
    );
    try w.print(" * Target          : {s}\n", .{if (params.triple.len != 0) params.triple else "(no triple given)"});
    try w.print(" * Architecture    : {s}\n", .{params.arch});
    try w.print(" * Operating system: {s}\n", .{params.os});
    try w.print(" * ABI             : {s}\n", .{params.abi});
    try w.print(" * Endianness      : {s}\n", .{params.endian});
    try w.print(" * Pointer width   : {d} bits\n", .{params.ptr_bits});
    try w.print(" * Upstream options: {d} parsed, {d} enabled upstream\n", .{ options.len, enabled });
    try w.print(" * Target-adjusted : {d}\n */\n\n", .{adjusted});
    try w.writeAll(
        \\/* The four decisions below are the whole of what varies by target.
        \\ * Each carries the upstream line that makes it required, so the reason
        \\ * travels with the option instead of living only in the generator.
        \\ */
        \\
    );
}

// ---------------------------------------------------------------------------
// Reading upstream's options
// ---------------------------------------------------------------------------

/// Reads every configuration directive out of upstream's header.
///
/// The file's shape is regular and this parser depends on that: 142 `#define`
/// directives, 202 `//#define` directives and one `// #define`, with no
/// `#if`, no `#undef` and no macro-expanded value anywhere in it. A line that
/// looks like a directive and does not parse is an error rather than a skip,
/// because a silently skipped directive is a silently dropped feature.
fn parseUpstream(
    arena: std.mem.Allocator,
    upstream: []const u8,
    into: *std.ArrayList(Option),
) Failure!void {
    var lines = std.mem.splitScalar(u8, upstream, '\n');
    var number: usize = 0;
    while (lines.next()) |raw| {
        number += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        // A documentation line, or a block comment. Upstream writes its
        // per-option prose as ` *      MBEDTLS_AESCE_C`, which mentions
        // option names and never a directive, and both its block-comment
        // opener (`/**`, `/*`) and its closer (` * /`) can start a line with
        // `*` or `/`. A `//#define` line is *not* one of those: it is the
        // directive that records an option upstream leaves disabled, so it has
        // to reach the block below and become a `#undef`. Skipping every line
        // that merely began with `/` dropped all 199 of them, which is why no
        // `/* #undef ... */` appeared in the generated header and why a
        // `decide` call naming a disabled option stopped with "upstream's
        // configuration has no option named ...".
        if (line[0] == '*') continue;
        if (line[0] == '/' and line.len > 1 and line[1] == '*') continue;

        // `commented` is what makes an option disabled: it is upstream's own
        // record of an option it leaves off, and this generator re-emits that
        // as a `#undef`. It has to be tested on the *line*, not on a copy of it
        // with the slashes trimmed away. Trimming `/` here and then asking
        // whether the result still starts with `//` can never be true, so every
        // `//#define` option was read as *enabled*; the drop above is what hid
        // that. Upstream writes `//#define` with no space and, once at
        // `mbedtls_config.h:3258`, `// #define` with one, so both spellings are
        // accepted here.
        const commented = std.mem.startsWith(u8, line, "//");
        const body = if (commented)
            std.mem.trim(u8, line[2..], " \t")
        else
            line;

        const keyword = "#define";
        if (!std.mem.startsWith(u8, body, keyword)) continue;
        const after = std.mem.trim(u8, body[keyword.len..], " \t");
        if (after.len == 0 or after[0] == '(') continue;

        const split = std.mem.indexOfAny(u8, after, " \t") orelse after.len;
        const name = after[0..split];
        if (!std.mem.startsWith(u8, name, "MBEDTLS_") and !std.mem.startsWith(u8, name, "PSA_")) {
            return error.UnparseableDirective;
        }
        var value = std.mem.trim(u8, after[split..], " \t");
        value = stripTrailingDoc(value);

        try into.append(arena, .{
            .name = name,
            .value = value,
            .upstream_enabled = !commented,
            .enabled = !commented,
        });
    }
    if (into.items.len == 0) return error.EmptyUpstreamConfig;
}

/// Removes the `/**< ... */` upstream puts at the end of a defaulted value.
///
/// `mbedtls_config.h` writes `//#define MBEDTLS_PLATFORM_STD_TIME time /**<
/// Default time to use, can be undefined. ... */`, where the documentation is
/// not part of the value. Emitting it would change the macro.
fn stripTrailingDoc(value: []const u8) []const u8 {
    const marker = std.mem.indexOf(u8, value, "/**<") orelse return value;
    return std.mem.trim(u8, value[0..marker], " \t");
}

// ---------------------------------------------------------------------------
// The target-derived decisions
// ---------------------------------------------------------------------------

/// Applies the target-derived decisions, each anchored to an upstream line.
///
/// Every decision here is one upstream *requires* rather than one this package
/// prefers. Upstream's committed default enables all three hardware
/// acceleration options on every architecture, enables `MBEDTLS_NET_C`
/// everywhere, and enables the clock and the signal-based timing module;
/// upstream's own headers then `#error` when the target cannot support the
/// option. Turning an option off for a target that cannot have it is what makes
/// the same configuration header valid on all six cross targets.
fn applyTargetDecisions(
    arena: std.mem.Allocator,
    options: *std.ArrayList(Option),
    params: Params,
    adjusted: *usize,
) Failure!void {
    const arch = Params.Arch.of(params.archName().?);

    // `src/library/aesni.h:23-24` compiles AES-NI only under
    // `MBEDTLS_ARCH_IS_X64 || MBEDTLS_ARCH_IS_X86`, and `library/aesni.c` is
    // otherwise an empty object. Enabling it elsewhere is dead configuration,
    // and a dead option is one a reader cannot tell from a live one.
    try decide(arena, options, adjusted, "MBEDTLS_AESNI_C", arch.x86_64 or arch.x86_32,
        \\on for x86 and x86-64 only: library/aesni.h:23-24 compiles it under
        \\MBEDTLS_ARCH_IS_X64 or MBEDTLS_ARCH_IS_X86 and nowhere else
    );

    // `src/library/aesce.h:23-26` requires `MBEDTLS_ARCH_IS_ARMV8_A` as well as
    // `MBEDTLS_AESCE_C`, so Arm's own AES instructions are the only place it
    // has code. The NEON-intrinsic and compiler conditions beside it are
    // properties of the compiler command line, not of the target, and this
    // build does not choose them.
    try decide(arena, options, adjusted, "MBEDTLS_AESCE_C", arch.arm64 or arch.arm32,
        \\on for Arm only: library/aesce.h:23-26 also requires
        \\MBEDTLS_ARCH_IS_ARMV8_A
    );

    // `src/library/padlock.h:33-36` requires `MBEDTLS_ARCH_IS_X86` -
    // 32-bit x86, not x86-64 - plus `MBEDTLS_HAVE_ASM` and no ASan, and
    // `library/aes.c:33-45` `#error`s if PADLOCK is set on anything else.
    try decide(arena, options, adjusted, "MBEDTLS_PADLOCK_C", arch.x86_32,
        \\on for 32-bit x86 only: library/padlock.h:33-36 requires
        \\MBEDTLS_ARCH_IS_X86, and library/aes.c:33-45 rejects it elsewhere
    );

    // `src/library/net_sockets.c:22-24` is the upstream `#error` this
    // configuration has to avoid: it fires on any target that is neither
    // unix-like nor Windows, as `src/library/common.h:34-46` defines those.
    try decide(arena, options, adjusted, "MBEDTLS_NET_C", params.sockets(),
        \\on where the platform has the sockets library: net_sockets.c:22-24
        \\rejects it outside MBEDTLS_PLATFORM_IS_UNIXLIKE and _WIN32, and
        \\common.h:34-46 defines that
    );

    // The same upstream condition as `MBEDTLS_NET_C` decides these three, and
    // they fail for the same reason on the one target that has neither unix nor
    // Windows. `library/entropy_poll.c:32-37` `#error`s because it has no
    // platform source to open, `library/platform_util.c:250-256` `#error`s
    // because `mbedtls_ms_time` has no implementation behind it, and
    // `library/timing.c:17` `#error`s because there are no signals to time.
    try decide(arena, options, adjusted, "MBEDTLS_HAVE_TIME", params.sockets(),
        \\on where the platform has a clock: platform_util.c:250-256 errors out
        \\without one, and common.h:34-46 defines where that is
    );
    try decide(arena, options, adjusted, "MBEDTLS_HAVE_TIME_DATE", params.sockets(),
        \\on with MBEDTLS_HAVE_TIME: config_adjust_time.h keeps the date
        \\helpers in step with the clock they call
    );
    try decide(arena, options, adjusted, "MBEDTLS_TIMING_C", params.sockets(),
        \\on where the platform has signals: timing.c:17 rejects it elsewhere
    );

    // `library/entropy_poll.c:32-37` is the fourth `#error` the condition
    // above decides, and it is upstream's own documented answer rather than
    // one this package invents: its own message names the macro, and
    // `mbedtls_config.h:1201-1223` documents `MBEDTLS_NO_PLATFORM_ENTROPY` as
    // "useful if your platform does not support standards like the
    // /dev/urandom or Windows CryptoAPI". With it defined, `entropy_poll.c`
    // compiles no platform source at all and `entropy.c:43-47` stops
    // registering one, so the library still builds and links; a caller that
    // wants entropy supplies `mbedtls_hardware_poll` through
    // `MBEDTLS_ENTROPY_HARDWARE_ALT`, which is upstream's stated route.
    //
    // Without this decision the one target with neither unix nor Windows
    // failed to compile `library/entropy_poll.c` with
    // `"Platform entropy sources only work on Unix and Windows, see
    // MBEDTLS_NO_PLATFORM_ENTROPY in mbedtls_config.h"`, even though the
    // comment above already named that `#error` as one this function exists to
    // avoid. The comment listed it; no decision implemented it.
    try decide(arena, options, adjusted, "MBEDTLS_NO_PLATFORM_ENTROPY", !params.sockets(),
        \\on where the platform has no entropy source at all: entropy_poll.c:32-37
        \\errors out without one and names this macro as the way out
    );
}

/// Sets one option from the target, recording why it changed.
fn decide(
    arena: std.mem.Allocator,
    options: *std.ArrayList(Option),
    adjusted: *usize,
    name: []const u8,
    enabled: bool,
    reason: []const u8,
) Failure!void {
    for (options.items) |*option| {
        if (!std.mem.eql(u8, option.name, name)) continue;
        if (option.upstream_enabled == enabled) return;
        option.enabled = enabled;
        option.reason = if (enabled)
            try std.mem.concat(arena, u8, &.{ "enabled for this target - ", reason })
        else
            try std.mem.concat(arena, u8, &.{ "disabled for this target - ", reason });
        adjusted.* += 1;
        return;
    }
    // Upstream renamed or removed the option. That is a fact about the vendored
    // release, not something to work around: emitting a header that silently
    // omitted it would hide a change in upstream's default configuration.
    std.debug.print(
        "zig/config_gen.zig: upstream's configuration has no option named {s}, " ++
            "so the target-derived decision for it cannot be applied.\n",
        .{name},
    );
    return error.UnparseableDirective;
}
