// SPDX-License-Identifier: MIT
//
//! Generic process-global dynamic-library loader.
//! Publishes a table only after required symbols and validation succeed.
//! Success retains the provider; there is no unload.

const std = @import("std");
const builtin = @import("builtin");

/// Names a provider by absolute path or bare platform-search name; no fallback.
pub const LoadSource = union(enum) {
    /// Absolute library path.
    path: []const u8,
    /// Basename or SONAME without path separators.
    system: []const u8,
};

/// Errors returned by `load`.
pub const LoadError = error{
    /// Empty path or system name.
    EmptySource,
    /// Request exceeds `max_source_len`; it is never truncated.
    SourceTooLong,
    /// Invalid path/name form or embedded NUL.
    InvalidSource,
    /// Target has no dynamic loader.
    UnsupportedTarget,
    /// Platform loader could not open the provider.
    OpenFailed,
    /// Provider lacks a required symbol; the candidate is closed.
    MissingSymbol,
    /// Provider validation failed; the candidate is closed.
    ValidationFailed,
    /// A different provider is loaded or in flight.
    ProviderMismatch,
    /// The current loader thread attempted a recursive load.
    ReentrantLoad,
};

/// Maximum request size in bytes.
pub const max_source_len = 32768;

/// Stores a bounded source copy for idempotence checks.
const SourceRecord = struct {
    tag: enum(u8) { none = 0, path, system } = .none,
    len: u32 = 0,
    bytes: [max_source_len]u8 = undefined,

    fn set(self: *SourceRecord, request: LoadSource) void {
        const text = switch (request) {
            .path => |p| p,
            .system => |s| s,
        };
        @memcpy(self.bytes[0..text.len], text);
        self.len = @intCast(text.len);
        self.tag = switch (request) {
            .path => .path,
            .system => .system,
        };
    }

    /// Returns a slice backed by this record.
    pub fn source(self: *const SourceRecord) ?LoadSource {
        const text = self.bytes[0..self.len];
        return switch (self.tag) {
            .none => null,
            .path => .{ .path = text },
            .system => .{ .system = text },
        };
    }
};

/// Compare source kind and bytes without path normalization.
pub fn eqlSource(a: LoadSource, b: LoadSource) bool {
    return switch (a) {
        .path => |pa| switch (b) {
            .path => |pb| std.mem.eql(u8, pa, pb),
            .system => false,
        },
        .system => |sa| switch (b) {
            .system => |sb| std.mem.eql(u8, sa, sb),
            .path => false,
        },
    };
}

fn validateSource(source: LoadSource) LoadError!void {
    const text = switch (source) {
        .path => |p| p,
        .system => |s| s,
    };
    if (text.len == 0) return error.EmptySource;
    if (text.len > max_source_len) return error.SourceTooLong;
    if (std.mem.indexOfScalar(u8, text, 0) != null) return error.InvalidSource;
    switch (source) {
        .path => {
            const absolute = if (builtin.os.tag == .windows)
                switch (std.fs.path.getWin32PathType(u8, text)) {
                    .drive_absolute, .unc_absolute, .local_device, .root_local_device => true,
                    .relative, .rooted, .drive_relative => false,
                }
            else
                std.fs.path.isAbsolutePosix(text);
            if (!absolute) return error.InvalidSource;
        },
        .system => {
            for (text) |byte| {
                if (std.fs.path.isSep(byte)) return error.InvalidSource;
                if (builtin.os.tag == .windows and byte == ':') return error.InvalidSource;
            }
        },
    }
}

/// States of the table publication lifecycle.
pub const Phase = enum(u8) {
    not_loaded = 0,
    loading = 1,
    ready = 2,
};

/// Acquire/release flag for table publication.
/// Readers that see `ready` observe all writes before the release store.
pub const Ready = struct {
    phase: std.atomic.Value(u8) = .init(@intFromEnum(Phase.not_loaded)),

    /// True after publication.
    pub fn isReady(self: *const Ready) bool {
        return self.phase.load(.acquire) == @intFromEnum(Phase.ready);
    }

    /// Current publication state.
    pub fn state(self: *const Ready) Phase {
        return @enumFromInt(self.phase.load(.acquire));
    }

    /// Set the publication state.
    pub fn set(self: *Ready, value: Phase) void {
        self.phase.store(@intFromEnum(value), .release);
    }
};

/// Kind of exported symbol represented by a table field.
pub const SymbolKind = enum {
    /// Function address stored as the translated function-pointer type.
    function,
    /// Data address, not a copy, so C writes reach provider storage.
    data,
};

/// Required export name and kind.
pub const Symbol = struct {
    /// NUL-terminated provider symbol name.
    name: [:0]const u8,
    /// Function or data.
    kind: SymbolKind,
};

/// Panics with library and symbol names when a routed call precedes successful load.
pub fn panicNotReady(library: []const u8, comptime symbol: []const u8) noreturn {
    std.debug.panic(
        "{s}: {s} was called before this module was loaded; call " ++
            "load({{ .path = \"...\" }}) or load({{ .system = \"...\" }}) first",
        .{ library, symbol },
    );
}

/// False on WASI, Emscripten, and freestanding targets.
pub const supported_target: bool = switch (builtin.os.tag) {
    .wasi, .emscripten, .freestanding => false,
    else => true,
};

/// Process-global loader for one dispatch configuration.
/// Config supplies symbols, table operations, synchronization, and optional checks.
pub fn Loader(comptime Config: type) type {
    return struct {
        const LoaderType = @This();

        /// Dispatch table type.
        pub const table_type = Config.table;

        /// In-flight attempt or undrained result.
        attempt: ?Attempt = null,

        /// Request copied for the active attempt and read under the lock.
        request: SourceRecord = .{},

        /// Resolves and publishes a provider, or returns a checked error.
        /// Safe for concurrent calls; a published provider is not unloaded.
        pub fn load(self: *LoaderType, source: LoadSource) LoadError!void {
            try validateSource(source);
            if (Config.ready().isReady()) return self.accept(source);

            Config.sync.lock();
            while (true) {
                switch (Config.ready().state()) {
                    .ready => {
                        Config.sync.unlock();
                        return self.accept(source);
                    },
                    .loading => {
                        const attempt = &self.attempt.?;
                        if (attempt.owner == Config.sync.threadSelf()) {
                            Config.sync.unlock();
                            return error.ReentrantLoad;
                        }
                        if (!eqlSource(self.request.source().?, source)) {
                            Config.sync.unlock();
                            return error.ProviderMismatch;
                        }
                        // Wait for this attempt rather than starting a competing load.
                        attempt.waiters += 1;
                        while (Config.ready().state() == .loading) Config.sync.wait();
                        const result = attempt.result;
                        attempt.waiters -= 1;
                        // Keep the attempt record until each waiter reads its result.
                        Config.sync.broadcast();
                        Config.sync.unlock();
                        return result;
                    },
                    .not_loaded => {
                        // Drain attached callers before starting a retry.
                        if (self.attempt != null) {
                            Config.sync.wait();
                            continue;
                        }
                        break;
                    },
                }
            }

            self.request.set(source);
            self.attempt = .{ .owner = Config.sync.threadSelf() };
            Config.ready().set(.loading);
            Config.sync.unlock();

            // Run provider constructors without the loader lock; other callers wait.
            const outcome = runAttempt(self.request.source().?);
            const succeeded = if (outcome) |_| true else |_| false;

            Config.sync.lock();
            self.attempt.?.result = outcome;
            Config.ready().set(if (succeeded) .ready else .not_loaded);
            // Wake every waiter attached to this result.
            Config.sync.broadcast();
            // Keep the record until every waiter has read the result.
            while (self.attempt.?.waiters > 0) Config.sync.wait();
            self.attempt = null;
            // Wake callers waiting to start a retry.
            Config.sync.broadcast();
            Config.sync.unlock();

            return outcome;
        }

        /// Returns the successful request, or null before a successful load.
        /// The loader retains its bytes for the process lifetime.
        pub fn loadedSource(self: *const LoaderType) ?LoadSource {
            if (!Config.ready().isReady()) return null;
            return self.request.source();
        }

        fn accept(self: *const LoaderType, source: LoadSource) LoadError!void {
            // `accept` is called only after an acquire load sees readiness.
            const published = self.request.source() orelse unreachable;
            if (eqlSource(published, source)) return;
            return error.ProviderMismatch;
        }

        /// Opens, resolves, and validates a provider without the loader lock.
        fn runAttempt(source: LoadSource) LoadError!void {
            // Provider constructors must not wait on a caller blocked in `load`.
            const handle = platform.open(source) catch |err| return err;

            var retain = false;
            defer if (!retain) platform.close(handle);

            if (@hasDecl(Config, "optional_symbols")) {
                inline for (Config.optional_symbols, 0..) |_, index| {
                    Config.assignMissing(index, Config.tablePtr());
                }
            }

            inline for (Config.symbols, 0..) |symbol, index| {
                const address = platform.lookup(handle, symbol.name) orelse
                    return error.MissingSymbol;
                Config.assign(index, Config.tablePtr(), address);
            }

            if (@hasDecl(Config, "optional_symbols")) {
                inline for (Config.optional_symbols, 0..) |symbol, index| {
                    if (platform.lookup(handle, symbol.name)) |address| {
                        Config.assignOptional(index, Config.tablePtr(), address);
                    }
                }
            }

            if (@hasDecl(Config, "validate")) {
                if (Config.validate(Config.tablePtr())) |refusal| {
                    // The refusal text identifies why validation failed.
                    std.debug.print("{s}: refusing this provider: {s}\n", .{
                        Config.library_name,
                        refusal,
                    });
                    return error.ValidationFailed;
                }
            }

            // Success. The handle is not closed: the table points into it for
            // the rest of the process.
            retain = true;
        }
    };
}

/// Shared state for one load attempt.
const Attempt = struct {
    /// Thread identity used to detect recursive loads.
    owner: u64,
    /// Waiters read this result after the attempt leaves `loading`.
    result: LoadError!void = error.OpenFailed,
    /// Keeps the record alive until every waiter reads the result.
    waiters: usize = 0,
};

/// Maximum UTF-8 input size for Windows path conversion.
const windows_path_units = 32768;

const platform = if (builtin.os.tag == .windows)
    Windows
else if (supported_target)
    Unix
else
    NoLoader;

/// Loader stub for targets without dynamic loading.
const NoLoader = struct {
    const OpenError = error{ OpenFailed, UnsupportedTarget };

    fn open(source: LoadSource) OpenError!*anyopaque {
        _ = source;
        return error.UnsupportedTarget;
    }
    fn lookup(handle: *anyopaque, name: [:0]const u8) ?*const anyopaque {
        _ = handle;
        _ = name;
        return null;
    }
    fn close(handle: *anyopaque) void {
        _ = handle;
    }
};

/// Unix `dlopen` adapter.
const Unix = struct {
    const OpenError = error{ OpenFailed, UnsupportedTarget };

    fn open(source: LoadSource) OpenError!*anyopaque {
        const text = switch (source) {
            .path => |p| p,
            .system => |s| s,
        };
        var buffer: [max_source_len + 1]u8 = undefined;
        @memcpy(buffer[0..text.len], text);
        buffer[text.len] = 0;
        // NOW reports missing dependencies at open; LOCAL isolates provider symbols.
        return std.c.dlopen(
            // `dlopen` requires a sentinel-terminated path.
            buffer[0..text.len :0].ptr,
            .{ .NOW = true, .GLOBAL = false },
        ) orelse error.OpenFailed;
    }

    fn lookup(handle: *anyopaque, name: [:0]const u8) ?*const anyopaque {
        return std.c.dlsym(handle, name.ptr);
    }

    fn close(handle: *anyopaque) void {
        _ = std.c.dlclose(handle);
    }
};

const kernel32 = struct {
    extern "kernel32" fn LoadLibraryExW(
        file_name: [*:0]const u16,
        file: ?*anyopaque,
        flags: u32,
    ) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn GetProcAddress(module: *anyopaque, name: [*:0]const u8) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn FreeLibrary(module: *anyopaque) callconv(.winapi) i32;
};

/// Windows loader adapter.
const Windows = struct {
    const OpenError = error{ OpenFailed, UnsupportedTarget, SourceTooLong };

    /// Search standard directories for bare names, not the current directory.
    /// Paths with separators are resolved from the supplied path.
    const load_library_search_default_dirs: u32 = 0x0000_1000;
    const load_library_search_dll_load_dir: u32 = 0x0000_0100;

    fn open(source: LoadSource) OpenError!*anyopaque {
        const text = switch (source) {
            .path => |p| p,
            .system => |s| s,
        };
        if (text.len > windows_path_units) return error.SourceTooLong;
        var buffer: [windows_path_units + 1]u16 = undefined;
        const units = std.unicode.utf8ToUtf16Le(buffer[0..text.len], text) catch
            return error.OpenFailed;
        buffer[units] = 0;
        return kernel32.LoadLibraryExW(
            buffer[0..units :0],
            null,
            load_library_search_default_dirs | switch (source) {
                .path => load_library_search_dll_load_dir,
                .system => @as(u32, 0),
            },
        ) orelse error.OpenFailed;
    }

    fn lookup(handle: *anyopaque, name: [:0]const u8) ?*const anyopaque {
        return kernel32.GetProcAddress(handle, name.ptr);
    }

    fn close(handle: *anyopaque) void {
        _ = kernel32.FreeLibrary(handle);
    }
};
