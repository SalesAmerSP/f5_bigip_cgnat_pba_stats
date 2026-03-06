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
        run_ssh "echo '$CHUNK' >> $REMOTE_PATH.b64"
    done
    run_ssh "base64 -d $REMOTE_PATH.b64 > $REMOTE_PATH && rm -f $REMOTE_PATH.b64"
fi

# Verify the file was copied
REMOTE_LINES=$(run_ssh "wc -l < $REMOTE_PATH" | grep -o '[0-9]*' | head -1)
LOCAL_LINES=$(wc -l < "$LOCAL_SCRIPT" | tr -d '[:space:]')
if [ -z "$REMOTE_LINES" ] || [ "$REMOTE_LINES" -lt 10 ]; then
    echo "ERROR: File copy verification failed (expected $LOCAL_LINES lines, got ${REMOTE_LINES:-0})"
    exit 1
fi
echo "    Verified: $REMOTE_LINES lines"

echo "==> Setting up ..."
run_ssh "chmod +x $REMOTE_PATH"

echo "==> Configuring PATH ..."
PROFILE="/etc/profile.d/pba-stats.sh"
PATH_LINE="export PATH=$PATH_DIR:\$PATH"
run_ssh "echo '$PATH_LINE' > $PROFILE"
PROFILE_CHECK=$(run_ssh "cat $PROFILE 2>/dev/null")
if ! echo "$PROFILE_CHECK" | grep -qF "$PATH_DIR"; then
    echo "ERROR: Failed to write $PROFILE"
    exit 1
fi
echo "    Created $PROFILE"

echo "==> Configuring startup persistence ..."
# /etc/profile.d doesn't persist across BIG-IP upgrades; recreate it on boot
STARTUP_CMD="echo '$PATH_LINE' > $PROFILE"
STARTUP_CHECK=$(run_ssh "cat /config/startup 2>/dev/null || echo ''")
if echo "$STARTUP_CHECK" | grep -qF "pba-stats"; then
    echo "    /config/startup already contains pba-stats entry"
elif echo "$STARTUP_CHECK" | grep -q "#!/bin/bash"; then
    run_ssh "echo '$STARTUP_CMD' >> /config/startup"
    echo "    Added PATH setup to /config/startup"
else
    run_ssh "printf '#!/bin/bash\n$STARTUP_CMD\n' > /config/startup"
    run_ssh "chmod +x /config/startup"
    echo "    Created /config/startup"
fi

echo "==> Verifying installation ..."
run_ssh "pba-stats --help" | head -5

echo ""
echo "Done. Run 'pba-stats --summary' on the BIG-IP to test."
