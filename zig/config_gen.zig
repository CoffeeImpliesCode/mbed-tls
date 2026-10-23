// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
// See FORK-LICENSE.md for what that identifier covers.
//
//! Generate Mbed TLS configuration for the requested target.
//! `build.zig` supplies resolved target facts; the generator does not inspect the build host.
//! It preserves upstream options and states, changing only target-incompatible settings.
//! Malformed directives or unsupported targets fail instead of guessing.

const std = @import("std");
const Io = std.Io;

/// Name of the generated header.
/// `MBEDTLS_CONFIG_FILE` selects it without shadowing upstream's quoted include.
pub const output_basename = "mbed_tls_target_config.h";

/// What this program was told about the target.
const Params = struct {
    /// Zig CPU architecture tag.
    arch: []const u8 = "",
    /// Zig operating-system tag.
    os: []const u8 = "",
    /// Zig ABI tag.
    abi: []const u8 = "",
    /// Target triple for the generated banner.
    triple: []const u8 = "",
    /// Target byte order.
    endian: []const u8 = "",
    /// Target pointer width in bits.
    ptr_bits: u32 = 0,

    /// Resolve `arch` to a supported tag; reject unknown architectures.
    fn archName(self: Params) ?Arch.Name {
        return Arch.Name.parse(self.arch);
    }

    /// Architecture facts used by target-specific option decisions.
    const Arch = struct {
        /// Supported architecture tags, matched exhaustively in `Arch.of`.
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

            /// Parse a supported architecture tag; unknown names return null.
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

        /// Map each supported architecture to upstream's compiler macros.
        /// Enable hardware options only where upstream implements them.
        fn of(name: Name) Arch {
            return switch (name) {
                .x86_64 => .{ .x86_64 = true, .x86_32 = false, .arm32 = false, .arm64 = false },
                .x86 => .{ .x86_64 = false, .x86_32 = true, .arm32 = false, .arm64 = false },

                // Big-endian AArch64 defines `__aarch64__`; Thumb variants define
                // macros that `build_info.h` maps to 32-bit Arm.
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

    /// Whether the target provides the Unix-like or Windows interfaces required by `MBEDTLS_NET_C`.
    /// Matches upstream's platform checks in `src/library/common.h` and `net_sockets.c`.
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
    /// Upstream's macro value; empty for a bare `#define`.
    value: []const u8,
    /// Whether upstream enables this option.
    upstream_enabled: bool,
    /// Whether the generated header enables this option.
    enabled: bool,
    /// Reason for a target-specific change, or empty.
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

/// Render the complete configuration header for a target.
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

/// Parse enabled and commented-out options from upstream's configuration header.
/// Reject malformed directives rather than silently dropping options.
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
        // Skip prose and block comments, but retain commented `#define` options.
        if (line[0] == '*') continue;
        if (line[0] == '/' and line.len > 1 and line[1] == '*') continue;

        // A leading `//` marks an upstream-disabled option.
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

/// Strip trailing upstream documentation from a defaulted macro value.
fn stripTrailingDoc(value: []const u8) []const u8 {
    const marker = std.mem.indexOf(u8, value, "/**<") orelse return value;
    return std.mem.trim(u8, value[0..marker], " \t");
}

/// Apply target-specific options required by upstream's platform and architecture checks.
/// Each change records its upstream basis in the generated header.
fn applyTargetDecisions(
    arena: std.mem.Allocator,
    options: *std.ArrayList(Option),
    params: Params,
    adjusted: *usize,
) Failure!void {
    const arch = Params.Arch.of(params.archName().?);

    // AES-NI has code only on x86 and x86-64.
    try decide(arena, options, adjusted, "MBEDTLS_AESNI_C", arch.x86_64 or arch.x86_32,
        \\on for x86 and x86-64 only: library/aesni.h:23-24 compiles it under
        \\MBEDTLS_ARCH_IS_X64 or MBEDTLS_ARCH_IS_X86 and nowhere else
    );

    // AESCE also requires ARMv8-A; compiler intrinsic settings remain separate.
    try decide(arena, options, adjusted, "MBEDTLS_AESCE_C", arch.arm64 or arch.arm32,
        \\on for Arm only: library/aesce.h:23-26 also requires
        \\MBEDTLS_ARCH_IS_ARMV8_A
    );

    // PADLOCK is limited to 32-bit x86; upstream rejects other architectures.
    try decide(arena, options, adjusted, "MBEDTLS_PADLOCK_C", arch.x86_32,
        \\on for 32-bit x86 only: library/padlock.h:33-36 requires
        \\MBEDTLS_ARCH_IS_X86, and library/aes.c:33-45 rejects it elsewhere
    );

    // Upstream rejects `MBEDTLS_NET_C` outside Unix-like and Windows targets.
    try decide(arena, options, adjusted, "MBEDTLS_NET_C", params.sockets(),
        \\on where the platform has the sockets library: net_sockets.c:22-24
        \\rejects it outside MBEDTLS_PLATFORM_IS_UNIXLIKE and _WIN32, and
        \\common.h:34-46 defines that
    );

    // Clock, date and signal-timing support share the same platform boundary.
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

    // Disable built-in platform entropy where Unix/Windows sources are absent.
    // Callers may supply hardware entropy with `MBEDTLS_ENTROPY_HARDWARE_ALT`.
    try decide(arena, options, adjusted, "MBEDTLS_NO_PLATFORM_ENTROPY", !params.sockets(),
        \\on where the platform has no entropy source at all: entropy_poll.c:32-37
        \\errors out without one and names this macro as the way out
    );
}

/// Set one target-derived option and record its reason.
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
    // Missing upstream options reject the build rather than emit a partial header.
    std.debug.print(
        "zig/config_gen.zig: upstream's configuration has no option named {s}, " ++
            "so the target-derived decision for it cannot be applied.\n",
        .{name},
    );
    return error.UnparseableDirective;
}
