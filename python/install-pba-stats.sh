#!/bin/bash
#
# Install pba-stats on a F5 BIG-IP
#
# Usage:
#   ./install-pba-stats.sh <bigip_host> [--user USERNAME] [--password] [--port PORT] [--insecure]
#
# Examples:
#   ./install-pba-stats.sh 10.0.0.1 --password                # admin user, prompts for password
#   ./install-pba-stats.sh 10.0.0.1                           # admin user, SSH key auth
#   ./install-pba-stats.sh 10.0.0.1 --user root --port 47001 --password
#   ./install-pba-stats.sh 10.0.0.1 --insecure                # skip host key verification

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_SCRIPT="$SCRIPT_DIR/cgnat_pba_stats_bigip_compatible.py"
REMOTE_PATH="/shared/scripts/pba-stats"
PATH_DIR="/shared/scripts"

usage() {
    echo "Usage: $0 <bigip_host> [--user USERNAME] [--password] [--port PORT]"
    echo ""
    echo "Options:"
    echo "  --user USERNAME   SSH username (default: admin)"
    echo "  --password        Prompt for SSH password (otherwise uses key auth)"
    echo "  --port PORT       SSH port (default: 22)"
    echo "  --insecure        Skip SSH host key verification"
    exit 1
}

if [ $# -lt 1 ]; then
    usage
fi

BIGIP_HOST="$1"
shift

SSH_USER="admin"
SSH_PORT="22"
USE_PASSWORD=false
INSECURE=false

while [ $# -gt 0 ]; do
    case "$1" in
        --user)
            SSH_USER="$2"
            shift 2
            ;;
        --password)
            USE_PASSWORD=true
            shift
            ;;
        --port)
            SSH_PORT="$2"
            shift 2
            ;;
        --insecure)
            INSECURE=true
            shift
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            usage
            ;;
    esac
done

SSH_OPTS="-o ConnectTimeout=10"
if [ "$INSECURE" = true ]; then
    SSH_OPTS="$SSH_OPTS -o StrictHostKeyChecking=no"
fi

if [ -n "$SSH_USER" ]; then
    SSH_TARGET="$SSH_USER@$BIGIP_HOST"
else
    SSH_TARGET="$BIGIP_HOST"
fi

# When --password is used, disable key auth so SSH prompts for the password
if [ "$USE_PASSWORD" = true ]; then
    SSH_OPTS="$SSH_OPTS -o PubkeyAuthentication=no -o PreferredAuthentications=keyboard-interactive,password"
fi

SSH_CMD="ssh -p $SSH_PORT $SSH_OPTS"
SCP_CMD="scp -P $SSH_PORT $SSH_OPTS"

run_ssh() {
    # Note: BIG-IP SSH always returns exit code 255, so we cannot rely on
    # exit codes for error detection. Critical steps use output validation.
    $SSH_CMD "$SSH_TARGET" "$@" 2>&1 || true
}

# Strip BIG-IP login/auth banner lines from captured output so they do not
# contaminate grep-based validation of command results.
strip_banner() {
    grep -v -E "private system|unauthorized access|Disconnect immediately" || true
}

# Test whether a remote directory is writable by attempting to create and
# remove a marker file. Returns 0 if writable, 1 otherwise.
remote_dir_writable() {
    local target_dir="$1"
    local result
    result=$(run_ssh "touch ${target_dir}/.pba_install_probe 2>/dev/null && rm -f ${target_dir}/.pba_install_probe && echo PBA_DIR_WRITABLE" | strip_banner)
    echo "$result" | grep -q "^PBA_DIR_WRITABLE$"
}

# Test whether a remote file is writable by us. Returns 0 if writable, 1 otherwise.
# Considers a non-existent file writable iff its parent directory is writable.
remote_file_writable() {
    local target_file="$1"
    local result
    result=$(run_ssh "if [ ! -e ${target_file} ]; then [ -w \$(dirname ${target_file}) ] && echo PBA_FILE_WRITABLE; elif [ -w ${target_file} ]; then echo PBA_FILE_WRITABLE; fi" | strip_banner)
    echo "$result" | grep -q "^PBA_FILE_WRITABLE$"
}

if [ ! -f "$LOCAL_SCRIPT" ]; then
    echo "ERROR: $LOCAL_SCRIPT not found"
    exit 1
fi

echo "==> Connecting to $BIGIP_HOST ..."
PLATFORM_INFO=$(run_ssh "cat /VERSION 2>/dev/null || echo ''")

if ! echo "$PLATFORM_INFO" | grep -qi "BIG-IP"; then
    echo "ERROR: $BIGIP_HOST does not appear to be a F5 BIG-IP (or cannot connect)"
    echo "       /VERSION contents:"
    echo "$PLATFORM_INFO" | sed 's/^/         /'
    exit 1
fi

BIGIP_VERSION=$(echo "$PLATFORM_INFO" | grep -i "^Product:" | head -1 || true)
BIGIP_BUILD=$(echo "$PLATFORM_INFO" | grep -i "^Version:" | head -1 || true)
echo "    $BIGIP_VERSION"
echo "    $BIGIP_BUILD"

echo "==> Checking for Python 3 ..."
run_ssh "python3 --version"

echo "==> Copying pba-stats to $BIGIP_HOST:$REMOTE_PATH ..."
run_ssh "mkdir -p /shared/scripts"

# Try SCP first, fall back to base64 chunked transfer over SSH
if $SCP_CMD "$LOCAL_SCRIPT" "$SSH_TARGET:$REMOTE_PATH" 2>/dev/null; then
    echo "    Copied via scp"
else
    echo "    SCP not available, using base64 transfer ..."
    run_ssh "rm -f $REMOTE_PATH.b64"
    ENCODED=$(base64 < "$LOCAL_SCRIPT")
    CHUNK_SIZE=4000
    while [ -n "$ENCODED" ]; do
        CHUNK="${ENCODED:0:$CHUNK_SIZE}"
        ENCODED="${ENCODED:$CHUNK_SIZE}"
        # Retry each chunk up to 3 times to handle transient connection failures
        for attempt in 1 2 3; do
            RESULT=$($SSH_CMD "$SSH_TARGET" "echo '$CHUNK' >> $REMOTE_PATH.b64 && echo OK" 2>&1 || true)
            if echo "$RESULT" | grep -q "OK"; then
                break
            fi
            sleep 1
        done
    done
    run_ssh "base64 -d $REMOTE_PATH.b64 > $REMOTE_PATH && rm -f $REMOTE_PATH.b64"
fi

# Verify the file was copied using md5 checksum
LOCAL_MD5=$(md5 -q "$LOCAL_SCRIPT" 2>/dev/null || md5sum "$LOCAL_SCRIPT" | awk '{print $1}')
REMOTE_MD5=$(run_ssh "md5sum $REMOTE_PATH" | grep -oE '^[a-f0-9]{32}')
if [ "$LOCAL_MD5" != "$REMOTE_MD5" ]; then
    echo "ERROR: File copy verification failed (md5 mismatch)"
    echo "    Local:  $LOCAL_MD5"
    echo "    Remote: $REMOTE_MD5"
    exit 1
fi
echo "    Verified: md5 $LOCAL_MD5"

echo "==> Setting up ..."
run_ssh "chmod +x $REMOTE_PATH"

echo "==> Configuring PATH ..."
PROFILE="/etc/profile.d/pba-stats.sh"
PATH_LINE="export PATH=$PATH_DIR:\$PATH"
PROFILE_INSTALLED=false

# /etc/profile.d/ is read-only on some BIG-IPs (e.g. Appliance Mode or images
# where /etc lives on a RO mount). Test writability before attempting to write
# rather than failing the whole install.
if remote_dir_writable /etc/profile.d; then
    run_ssh "echo '$PATH_LINE' > $PROFILE"
    PROFILE_CHECK=$(run_ssh "cat $PROFILE 2>/dev/null" | strip_banner)
    if echo "$PROFILE_CHECK" | grep -qF "$PATH_DIR"; then
        echo "    Created $PROFILE"
        PROFILE_INSTALLED=true
    else
        echo "    WARNING: Wrote to $PROFILE but content did not verify"
    fi
else
    echo "    /etc/profile.d/ is not writable on this BIG-IP - skipping PATH setup"
    echo "    Invoke pba-stats by absolute path instead: $REMOTE_PATH"
fi

echo "==> Configuring startup persistence ..."
# /etc/profile.d does not persist across BIG-IP upgrades; recreate it on boot
# from /config/startup. NEVER overwrite /config/startup - it may contain other
# user/system commands that must be preserved. Always append (idempotently).
STARTUP_FILE="/config/startup"
STARTUP_INSTALLED=false
STARTUP_MARKER="# pba-stats: ensure /shared/scripts is in PATH after upgrade"
STARTUP_LINE="echo 'export PATH=$PATH_DIR:\$PATH' > $PROFILE"

if [ "$PROFILE_INSTALLED" = false ]; then
    echo "    PATH setup was skipped, so startup persistence is also skipped"
elif ! remote_file_writable "$STARTUP_FILE"; then
    # File exists but is not writable. Try to chmod it (admin user on most
    # BIG-IPs has effective write access via group membership / sudo wrapper).
    if run_ssh "chmod u+w $STARTUP_FILE 2>&1 && echo PBA_CHMOD_OK" | strip_banner | grep -q PBA_CHMOD_OK; then
        echo "    Made $STARTUP_FILE writable (chmod u+w)"
    else
        echo "    $STARTUP_FILE is not writable - skipping startup persistence"
        echo "    After a BIG-IP upgrade, re-run this installer to restore PATH"
        STARTUP_FILE=""
    fi
fi

if [ -n "$STARTUP_FILE" ] && [ "$PROFILE_INSTALLED" = true ]; then
    STARTUP_CHECK=$(run_ssh "cat $STARTUP_FILE 2>/dev/null" | strip_banner)
    if echo "$STARTUP_CHECK" | grep -qF "$STARTUP_MARKER"; then
        echo "    $STARTUP_FILE already contains pba-stats entry (idempotent)"
        STARTUP_INSTALLED=true
    else
        # Always append, never overwrite. If the file is empty or missing a
        # shebang, prepend one before appending our block.
        if [ -z "$(echo "$STARTUP_CHECK" | tr -d '[:space:]')" ]; then
            run_ssh "echo '#!/bin/bash' > $STARTUP_FILE && chmod +x $STARTUP_FILE"
        elif ! echo "$STARTUP_CHECK" | head -1 | grep -q "^#!"; then
            # Existing file has content but no shebang on line 1; leave it alone
            # and just append. /config/startup is invoked by /etc/rc.local so
            # the shebang is not strictly required.
            :
        fi
        run_ssh "cat >> $STARTUP_FILE << 'STARTUP_EOF'
$STARTUP_MARKER
$STARTUP_LINE
STARTUP_EOF"
        # Verify the marker was actually appended
        STARTUP_RECHECK=$(run_ssh "cat $STARTUP_FILE 2>/dev/null" | strip_banner)
        if echo "$STARTUP_RECHECK" | grep -qF "$STARTUP_MARKER"; then
            echo "    Appended pba-stats setup to $STARTUP_FILE"
            STARTUP_INSTALLED=true
        else
            echo "    WARNING: Failed to append to $STARTUP_FILE"
        fi
    fi
fi

echo "==> Verifying installation ..."
# Always invoke by absolute path - PATH may not be set up yet in this session.
HELP_OUT=$(run_ssh "$REMOTE_PATH --help 2>&1" | strip_banner | head -5)
if echo "$HELP_OUT" | grep -q "usage:"; then
    echo "$HELP_OUT" | sed 's/^/    /'
else
    echo "    WARNING: $REMOTE_PATH --help did not produce expected output:"
    echo "$HELP_OUT" | sed 's/^/      /'
fi

echo ""
if [ "$PROFILE_INSTALLED" = true ] && [ "$STARTUP_INSTALLED" = true ]; then
    echo "Done. Run 'pba-stats --summary' on the BIG-IP to test."
elif [ "$PROFILE_INSTALLED" = true ]; then
    echo "Partial install: pba-stats works in new shells but will not survive a TMOS upgrade."
    echo "Re-run this installer after upgrading."
else
    echo "Partial install: pba-stats deployed to $REMOTE_PATH but PATH was not configured."
    echo "Invoke it by absolute path, or add '$PATH_LINE' to your shell rc."
fi
