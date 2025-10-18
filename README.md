# Cellwall

A Rust reimplementation of [bubblewrap](https://github.com/containers/bubblewrap), a sandboxing tool that uses Linux namespaces to create isolated environments.

## Status

🚧 **Early Development** - Basic structure implemented, core functionality in progress.

### Completed

- ✅ Project structure and build system (using Cargo)
- ✅ Error handling with `eyre` and `color-eyre` for beautiful error messages
- ✅ Command-line argument parsing with `argh`
- ✅ Core utility functions
- ✅ Namespace management (user, pid, net, ipc, uts, cgroup)
- ✅ Bind mount operations
- ✅ Network setup (loopback interface)
- ✅ Capability management
- ✅ Basic CLI interface

### In Progress / TODO

- ⏳ Seccomp filter support
- ⏳ Filesystem operations (proc, dev, tmpfs mounting)
- ⏳ Process monitoring and lifecycle management
- ⏳ Complete sandbox execution flow
- ⏳ Overlay filesystem support
- ⏳ Comprehensive testing
- ⏳ Documentation

## Building

```bash
cargo build --release
```

## Running

```bash
# Show version
cargo run -- --version

# Show help
cargo run -- --help

# Example (placeholder - full functionality not yet implemented)
cargo run -- --unshare-pid --unshare-net /bin/bash
```

## Architecture

The project is organized into modules:

- `cli.rs` - Command-line argument parsing and validation
- `utils.rs` - File operations and utility functions
- `namespace.rs` - Linux namespace management
- `bind_mount.rs` - Bind mount operations with various flags
- `network.rs` - Network namespace setup (loopback interface)
- `capabilities.rs` - Linux capability management
- `main.rs` - Main entry point and orchestration

## Design Philosophy

- **Idiomatic Rust**: Using Rust's type system and ownership model for safety
- **Beautiful Errors**: Using `eyre` and `color-eyre` for helpful, colorful error messages
- **Logging**: Using the `log` crate for structured logging
- **Modern CLI**: Using `argh` for a clean command-line interface
- **Safety**: Leveraging Rust's memory safety guarantees to avoid common C pitfalls

## Differences from Original Bubblewrap

- Written in Rust instead of C
- Uses modern Rust crates for common functionality
- Simplified some internal implementations while maintaining compatibility
- Color-coded error messages for better user experience

## Contributing

This is an early-stage reimplementation. The core functionality is being built to match bubblewrap's feature set while taking advantage of Rust's safety and modern tooling.

## License

LGPL-2.0-or-later (same as original bubblewrap)
