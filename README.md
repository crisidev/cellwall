# Cellwall

**Cellwall** is a Rust reimplementation of [bubblewrap](https://github.com/containers/bubblewrap), a powerful sandboxing tool for Linux. Just as the cell membrane protects biological cells by controlling what enters and exits while maintaining the cell's integrity, Cellwall creates secure, isolated environments that protect your system from potentially harmful applications while allowing controlled interaction with the host.

The name "Cellwall" pays homage to nature's most sophisticated security mechanism - the cell membrane - which has been protecting cellular life for billions of years through selective permeability and robust isolation.

**Please don't use Cellwall in production, bubblewrap is more complete, better tested and powers the awesome Flatpak project.**

## What is Cellwall?

Cellwall leverages Linux namespaces and capabilities to run untrusted applications in isolated containers without requiring root privileges. It's designed for:

- Running untrusted applications safely
- Creating reproducible build environments
- Isolating desktop applications
- Testing software in clean environments
- Building container-like sandboxes without Docker

Unlike heavyweight containerization solutions, Cellwall is lightweight, fast, and integrates seamlessly with your existing filesystem and processes.

## Why reimplement bubblewrap?

I wanted to dive deep into how namespaces, bind and recursive mounts and sharing / unsharing resources works on Linux and reimplementing some of the features bubblewarp offers in Rust helped a lot.
I also made fair use of LLMs into this project, to learn how to use them as an helper for my workflow, while still reviewing the code by hand.

## Feature Compatibility

The following table shows all bubblewrap features and their implementation status in Cellwall:

| Feature | Flag | Status | Notes |
|---------|------|--------|-------|
| **Help & Version** |
| Print help | `--help` | ✅ Implemented | |
| Print version | `--version` | ✅ Implemented | |
| Parse args from FD | `--args FD` | ❌ Not implemented | |
| Set argv[0] | `--argv0 VALUE` | ❌ Not implemented | |
| Level prefix | `--level-prefix` | ❌ Not implemented | |
| **Namespace Management** |
| Unshare all namespaces | `--unshare-all` | ✅ Implemented | |
| Share network | `--share-net` | ✅ Implemented | |
| Unshare user namespace | `--unshare-user` | ✅ Implemented | |
| Try unshare user | `--unshare-user-try` | ✅ Implemented | |
| Unshare IPC namespace | `--unshare-ipc` | ✅ Implemented | |
| Unshare PID namespace | `--unshare-pid` | ✅ Implemented | |
| Unshare network namespace | `--unshare-net` | ✅ Implemented | |
| Unshare UTS namespace | `--unshare-uts` | ✅ Implemented | |
| Unshare cgroup namespace | `--unshare-cgroup` | ✅ Implemented | |
| Try unshare cgroup | `--unshare-cgroup-try` | ✅ Implemented | |
| Use existing userns | `--userns FD` | ❌ Not implemented | |
| Switch to userns2 | `--userns2 FD` | ❌ Not implemented | |
| Disable further userns | `--disable-userns` | ✅ Implemented | |
| Assert userns disabled | `--assert-userns-disabled` | ❌ Not implemented | |
| Use existing pidns | `--pidns FD` | ❌ Not implemented | |
| **User/Group Management** |
| Custom UID | `--uid UID` | ✅ Implemented | |
| Custom GID | `--gid GID` | ✅ Implemented | |
| Custom hostname | `--hostname NAME` | ✅ Implemented | |
| **Environment** |
| Change directory | `--chdir DIR` | ✅ Implemented | |
| Clear environment | `--clearenv` | ✅ Implemented | |
| Set environment variable | `--setenv VAR VALUE` | ✅ Implemented | |
| Unset environment variable | `--unsetenv VAR` | ✅ Implemented | |
| **Synchronization** |
| Lock file | `--lock-file DEST` | ❌ Not implemented | |
| Sync FD | `--sync-fd FD` | ❌ Not implemented | |
| Block on FD | `--block-fd FD` | ❌ Not implemented | |
| Userns block FD | `--userns-block-fd FD` | ❌ Not implemented | |
| **Bind Mounts** |
| Bind mount | `--bind SRC DEST` | ✅ Implemented | |
| Bind mount (try) | `--bind-try SRC DEST` | ✅ Implemented | |
| Device bind mount | `--dev-bind SRC DEST` | ✅ Implemented | |
| Device bind mount (try) | `--dev-bind-try SRC DEST` | ✅ Implemented | |
| Read-only bind mount | `--ro-bind SRC DEST` | ✅ Implemented | |
| Read-only bind mount (try) | `--ro-bind-try SRC DEST` | ✅ Implemented | |
| Bind from FD | `--bind-fd FD DEST` | ✅ Implemented | |
| Read-only bind from FD | `--ro-bind-fd FD DEST` | ✅ Implemented | |
| Remount read-only | `--remount-ro DEST` | ✅ Implemented | |
| **Overlay Filesystems** |
| Overlay source | `--overlay-src SRC` | ❌ Not implemented | |
| Overlay mount | `--overlay RWSRC WORKDIR DEST` | ❌ Not implemented | |
| Tmpfs overlay | `--tmp-overlay DEST` | ❌ Not implemented | |
| Read-only overlay | `--ro-overlay DEST` | ❌ Not implemented | |
| **SELinux** |
| Exec label | `--exec-label LABEL` | ❌ Not implemented | |
| File label | `--file-label LABEL` | ❌ Not implemented | |
| **Filesystem Operations** |
| Mount proc | `--proc DEST` | ✅ Implemented | |
| Mount dev | `--dev DEST` | ✅ Implemented | |
| Mount tmpfs | `--tmpfs DEST` | ✅ Implemented | |
| Mount mqueue | `--mqueue DEST` | ❌ Not implemented | |
| Create directory | `--dir DEST` | ✅ Implemented | |
| Copy file from FD | `--file FD DEST` | ❌ Not implemented | |
| Bind data from FD | `--bind-data FD DEST` | ❌ Not implemented | |
| Read-only bind data | `--ro-bind-data FD DEST` | ❌ Not implemented | |
| Create symlink | `--symlink SRC DEST` | ✅ Implemented | |
| Change permissions | `--chmod OCTAL PATH` | ✅ Implemented | |
| Set permissions | `--perms OCTAL` | ❌ Not implemented | |
| Set size | `--size BYTES` | ❌ Not implemented | |
| **Security** |
| Seccomp filter | `--seccomp FD` | ✅ Implemented | |
| Add seccomp filter | `--add-seccomp-fd FD` | ❌ Not implemented | |
| Add capability | `--cap-add CAP` | ✅ Implemented | |
| Drop capability | `--cap-drop CAP` | ✅ Implemented | |
| **Process Management** |
| New session | `--new-session` | ✅ Implemented | |
| Die with parent | `--die-with-parent` | ✅ Implemented | |
| Run as PID 1 | `--as-pid-1` | ✅ Implemented | |
| **Information/Status** |
| Info FD | `--info-fd FD` | ❌ Not implemented | |
| JSON status FD | `--json-status-fd FD` | ❌ Not implemented | |


## Building

```bash
# Build debug version
cargo build

# Run tests
cargo test

# Run integration tests
./tests/test-compat.sh --with-sudo
```

## Acknowledgments

- Original [bubblewrap](https://github.com/containers/bubblewrap) by Alexander Larsson and contributors

## See Also

- [bubblewrap](https://github.com/containers/bubblewrap) - The original C implementation
- [firejail](https://firejail.wordpress.com/) - Another Linux sandboxing tool
- [flatpak](https://flatpak.org/) - Uses bubblewrap for application sandboxing
