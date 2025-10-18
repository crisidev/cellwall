#!/usr/bin/env bash
# Test suite for cellwrap
# Based on bubblewrap's test-run.sh
#
# Usage: ./test-compat.sh [--with-sudo]
#   --with-sudo: Run tests that require root privileges with sudo

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
CELLWALL="${CELLWALL:-$PROJECT_DIR/target/debug/cw}"

# Parse command line arguments
RUN_ROOT_TESTS=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --with-sudo)
            RUN_ROOT_TESTS=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--with-sudo]"
            exit 1
            ;;
    esac
done

echo "Building cellwrap..."
cd "$PROJECT_DIR"
cargo build

passes=0
fails=0
skips=0

pass() {
    passes=$((passes + 1))
    printf "  \033[32m✓\033[0m %s\n" "$*"
}

fail() {
    fails=$((fails + 1))
    printf "  \033[31m✗\033[0m %s\n" "$*"
}

skip() {
    skips=$((skips + 1))
    printf "  \033[33m-\033[0m %s (skipped)\n" "$*"
}

assert_file_has_content() {
    if ! grep -q "$2" "$1"; then
        echo "File $1 doesn't contain: $2"
        echo "Contents:"
        cat "$1"
        return 1
    fi
}

assert_not_file_has_content() {
    if grep -q "$2" "$1"; then
        echo "File $1 shouldn't contain: $2"
        return 1
    fi
}

TESTDIR=$(mktemp -d /tmp/cellwall-test.XXXXXX)
cd "$TESTDIR"

# Disable logging noise
export RUST_LOG=error

echo "Testing cellwall..."
echo

# Basic functionality
if $CELLWALL echo "hello" > out 2>&1 && assert_file_has_content out "hello"; then
    pass "basic command execution"
else
    fail "basic command execution"
fi

# Proc mounting
mkdir -p proc-test
if $CELLWALL --proc ./proc-test ls ./proc-test > out 2>&1 && assert_file_has_content out "self"; then
    pass "mount /proc (auto PID namespace)"
else
    fail "mount /proc"
fi

if $CELLWALL --unshare-pid --proc ./proc-test ls ./proc-test > out 2>&1 && assert_file_has_content out "self"; then
    pass "mount /proc with explicit --unshare-pid"
else
    fail "mount /proc with explicit --unshare-pid"
fi

# Dev filesystem
mkdir -p dev-test
if $CELLWALL --dev ./dev-test ls -1 ./dev-test > out 2>&1 && \
   assert_file_has_content out "null" && \
   assert_file_has_content out "zero" && \
   assert_file_has_content out "random"; then
    pass "mount /dev"
else
    fail "mount /dev"
fi

# Bind mounts
mkdir -p bind-src bind-dst
echo "test-data" > bind-src/file.txt
if $CELLWALL --bind ./bind-src ./bind-dst cat ./bind-dst/file.txt > out 2>&1 && \
   assert_file_has_content out "test-data"; then
    pass "bind mount"
else
    fail "bind mount"
fi

if $CELLWALL --ro-bind ./bind-src ./bind-dst cat ./bind-dst/file.txt > out 2>&1 && \
   assert_file_has_content out "test-data"; then
    pass "read-only bind mount"
else
    fail "read-only bind mount"
fi

# File bind mounts
echo "file-test" > test-file
if $CELLWALL --bind ./test-file ./mounted-file cat ./mounted-file > out 2>&1 && \
   assert_file_has_content out "file-test"; then
    pass "bind mount file"
else
    fail "bind mount file"
fi

# Tmpfs
mkdir -p tmpfs-test
if $CELLWALL --tmpfs ./tmpfs-test sh -c 'echo data > ./tmpfs-test/f && cat ./tmpfs-test/f' > out 2>&1 && \
   assert_file_has_content out "data"; then
    pass "tmpfs"
else
    fail "tmpfs"
fi

# Directory creation
if $CELLWALL --dir ./new-dir test -d ./new-dir 2>&1; then
    pass "create directory"
else
    fail "create directory"
fi

# Symlinks
if $CELLWALL --symlink /dev/null ./link readlink ./link > out 2>&1 && \
   assert_file_has_content out "/dev/null"; then
    pass "create symlink"
else
    fail "create symlink"
fi

# Remount read-only
mkdir -p ro-test
echo "before" > ro-test/file
if $CELLWALL --bind ./ro-test ./ro-test --remount-ro ./ro-test \
   sh -c '! echo write > ./ro-test/file 2>/dev/null' 2>/dev/null; then
    pass "remount read-only"
else
    fail "remount read-only"
fi

# Change directory
if $CELLWALL --chdir / pwd > out 2>&1 && assert_file_has_content out "^/$"; then
    pass "chdir"
else
    fail "chdir"
fi

# Environment variables
if FOO=bar $CELLWALL --setenv BAZ qux sh -c 'echo "$FOO $BAZ"' > out 2>&1 && \
   assert_file_has_content out "bar qux"; then
    pass "setenv"
else
    fail "setenv"
fi

if FOO=bar $CELLWALL --unsetenv FOO sh -c 'echo "x${FOO}x"' > out 2>&1 && \
   assert_file_has_content out "^xx$"; then
    pass "unsetenv"
else
    fail "unsetenv"
fi

if $CELLWALL --clearenv sh -c 'env | wc -l' > out 2>&1 && [ "$(cat out)" -lt 5 ]; then
    pass "clearenv"
else
    fail "clearenv"
fi

# New session
if $CELLWALL --new-session true 2>&1; then
    pass "new session"
else
    fail "new session"
fi

# Die with parent
if $CELLWALL --die-with-parent true 2>&1; then
    pass "die with parent"
else
    fail "die with parent"
fi

# Multiple namespaces
if $CELLWALL --unshare-ipc --unshare-uts --unshare-net true 2>&1; then
    pass "multiple namespaces"
else
    fail "multiple namespaces"
fi

# Hostname in UTS namespace
if $CELLWALL --unshare-uts --hostname "sandbox-test" hostname > out 2>&1 && \
   assert_file_has_content out "sandbox-test"; then
    pass "set hostname"
else
    fail "set hostname"
fi

# Unshare all
if $CELLWALL --unshare-all --share-net true 2>&1; then
    pass "unshare all with share-net"
else
    fail "unshare all"
fi

# PID 1
if $CELLWALL --unshare-pid --as-pid-1 sh -c 'echo $$' > out 2>&1 && \
   assert_file_has_content out "^1$"; then
    pass "run as PID 1"
else
    fail "run as PID 1"
fi

# Complex sandbox
mkdir -p sandbox/{usr,lib,lib64,bin,proc,dev,tmp}
if $CELLWALL \
    --bind /usr ./sandbox/usr \
    --bind /bin ./sandbox/bin \
    --ro-bind /lib ./sandbox/lib \
    --ro-bind /lib64 ./sandbox/lib64 \
    --proc ./sandbox/proc \
    --dev ./sandbox/dev \
    --tmpfs ./sandbox/tmp \
    --chdir ./sandbox \
    ls > out 2>&1 && \
   assert_file_has_content out "usr" && \
   assert_file_has_content out "proc"; then
    pass "complex sandbox"
else
    fail "complex sandbox"
fi

# Symlink to directory bind
if $CELLWALL --dir /tmp/dir --symlink dir /tmp/link --bind /etc /tmp/link true 2>&1; then
    pass "bind over symlink"
else
    fail "bind over symlink"
fi

# bind-try with existing file
mkdir -p try-src
echo "exists" > try-src/file
if $CELLWALL --bind-try ./try-src ./try-dst cat ./try-dst/file > out 2>&1 && \
   assert_file_has_content out "exists"; then
    pass "bind-try with existing source"
else
    fail "bind-try with existing source"
fi

# bind-try with missing file
if $CELLWALL --bind-try ./missing-dir ./try-dst2 true 2>&1; then
    pass "bind-try with missing source"
else
    fail "bind-try with missing source"
fi

# ro-bind-try with missing file
if $CELLWALL --ro-bind-try ./missing-file ./try-dst3 true 2>&1; then
    pass "ro-bind-try with missing source"
else
    fail "ro-bind-try with missing source"
fi

# chmod
mkdir -p chmod-test
chmod 600 chmod-test
if $CELLWALL --bind ./chmod-test ./chmod-test --chmod 0755 ./chmod-test \
   stat -c '%a' ./chmod-test > out 2>&1 && \
   assert_file_has_content out "^755$"; then
    pass "chmod"
else
    fail "chmod"
fi

# dev-bind (needs actual device)
if [ -c /dev/null ]; then
    if $CELLWALL --dev-bind /dev/null ./dev-null-test test -c ./dev-null-test 2>&1; then
        pass "dev-bind"
    else
        fail "dev-bind"
    fi
else
    skip "dev-bind (no /dev/null)"
fi

# Capability management (only works as root)
if [ "$RUN_ROOT_TESTS" = "true" ]; then
    # Test dropping single capability
    if sudo $CELLWALL --cap-drop CAP_SYS_ADMIN true 2>&1; then
        pass "cap-drop single capability"
    else
        fail "cap-drop single capability"
    fi

    # Test dropping multiple capabilities
    if sudo $CELLWALL --cap-drop CAP_SYS_ADMIN --cap-drop CAP_NET_ADMIN true 2>&1; then
        pass "cap-drop multiple capabilities"
    else
        fail "cap-drop multiple capabilities"
    fi

    # Test adding single capability
    if sudo $CELLWALL --cap-add CAP_NET_ADMIN true 2>&1; then
        pass "cap-add single capability"
    else
        fail "cap-add single capability"
    fi

    # Test adding multiple capabilities
    if sudo $CELLWALL --cap-add CAP_NET_ADMIN --cap-add CAP_SYS_PTRACE true 2>&1; then
        pass "cap-add multiple capabilities"
    else
        fail "cap-add multiple capabilities"
    fi

    # Test capability name without CAP_ prefix
    if sudo $CELLWALL --cap-drop SYS_ADMIN true 2>&1; then
        pass "cap-drop without CAP_ prefix"
    else
        fail "cap-drop without CAP_ prefix"
    fi

    # Test combining cap-add and cap-drop
    if sudo $CELLWALL --cap-add CAP_NET_ADMIN --cap-drop CAP_SYS_ADMIN true 2>&1; then
        pass "combine cap-add and cap-drop"
    else
        fail "combine cap-add and cap-drop"
    fi

    # Test various capability names
    if sudo $CELLWALL --cap-drop CAP_CHOWN --cap-drop CAP_FOWNER --cap-drop CAP_SETUID true 2>&1; then
        pass "cap-drop various capabilities"
    else
        fail "cap-drop various capabilities"
    fi
else
    skip "cap-drop single capability (requires --with-sudo)"
    skip "cap-drop multiple capabilities (requires --with-sudo)"
    skip "cap-add single capability (requires --with-sudo)"
    skip "cap-add multiple capabilities (requires --with-sudo)"
    skip "cap-drop without CAP_ prefix (requires --with-sudo)"
    skip "combine cap-add and cap-drop (requires --with-sudo)"
    skip "cap-drop various capabilities (requires --with-sudo)"
fi

# Seccomp tests
# Create a simple seccomp filter that allows all syscalls (passthrough filter)
"$SCRIPT_DIR/create-seccomp-filter.py" > seccomp-allow.bpf

if $CELLWALL --seccomp 3 echo "seccomp-test" 3< seccomp-allow.bpf > out 2>&1 && \
   assert_file_has_content out "seccomp-test"; then
    pass "seccomp filter loading"
else
    fail "seccomp filter loading"
fi

# Test seccomp with other sandbox features
if $CELLWALL --unshare-all --share-net --seccomp 3 echo "seccomp-sandbox" 3< seccomp-allow.bpf > out 2>&1 && \
   assert_file_has_content out "seccomp-sandbox"; then
    pass "seccomp with namespaces"
else
    fail "seccomp with namespaces"
fi

# Combined security features test (requires root)
if [ "$RUN_ROOT_TESTS" = "true" ]; then
    # Use sh -c to ensure FD redirection works with sudo
    if sudo sh -c "$CELLWALL --cap-add CAP_NET_ADMIN --seccomp 3 echo 'combined-security' 3< seccomp-allow.bpf" > out 2>&1 && \
       assert_file_has_content out "combined-security"; then
        pass "combined security features (caps + seccomp)"
    else
        fail "combined security features (caps + seccomp)"
    fi

    # Test with namespaces + security
    if sudo sh -c "$CELLWALL --unshare-pid --cap-add CAP_NET_ADMIN --seccomp 3 echo 'full-security-sandbox' 3< seccomp-allow.bpf" > out 2>&1 && \
       assert_file_has_content out "full-security-sandbox"; then
        pass "full sandbox with security features"
    else
        fail "full sandbox with security features"
    fi
else
    skip "combined security features (caps + seccomp) (requires --with-sudo)"
    skip "full sandbox with security features (requires --with-sudo)"
fi

# Cleanup seccomp test file
rm -f seccomp-allow.bpf

# Cleanup
cd /
rm -rf "$TESTDIR"

echo
echo "========================================="
echo "Test Results:"
echo "  Passed:  $passes"
echo "  Failed:  $fails"
echo "  Skipped: $skips"
echo "========================================="

if [ $fails -eq 0 ]; then
    if [ $skips -gt 0 ]; then
        echo "All $passes tests passed ($skips skipped)"
        echo "Tip: Run with --with-sudo to enable root-required tests"
    else
        echo "All $passes tests passed"
    fi
    exit 0
else
    echo "FAILED: $passes passed, $fails failed, $skips skipped"
    exit 1
fi
