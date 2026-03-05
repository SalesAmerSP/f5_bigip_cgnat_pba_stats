#!/bin/bash
#
# Install pba-stats on a F5 BIG-IP
#
# Usage:
#   ./install-pba-stats.sh <bigip_host> [username] [ssh_port]
#
# Examples:
#   ./install-pba-stats.sh 10.0.0.1
#   ./install-pba-stats.sh bigip.example.com admin
#   ./install-pba-stats.sh bigip.example.com admin 47001

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOCAL_SCRIPT="$SCRIPT_DIR/cgnat_pba_stats_bigip_compatible.py"
REMOTE_PATH="/shared/scripts/pba-stats"
SYMLINK_PATH="/usr/local/bin/pba-stats"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <bigip_host> [username] [ssh_port]"
    exit 1
fi

BIGIP_HOST="$1"
SSH_USER="${2:-}"
SSH_PORT="${3:-22}"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10"

if [ -n "$SSH_USER" ]; then
    SSH_CMD="ssh -p $SSH_PORT $SSH_OPTS -l $SSH_USER"
    SCP_CMD="scp -P $SSH_PORT $SSH_OPTS"
    SSH_TARGET="$BIGIP_HOST"
    SCP_TARGET="$SSH_USER@$BIGIP_HOST"
else
    SSH_CMD="ssh -p $SSH_PORT $SSH_OPTS"
    SCP_CMD="scp -P $SSH_PORT $SSH_OPTS"
    SSH_TARGET="$BIGIP_HOST"
    SCP_TARGET="$BIGIP_HOST"
fi

if [ ! -f "$LOCAL_SCRIPT" ]; then
    echo "ERROR: $LOCAL_SCRIPT not found"
    exit 1
fi

echo "==> Verifying $BIGIP_HOST is a BIG-IP ..."
PLATFORM_INFO=$($SSH_CMD "$SSH_TARGET" \
    "cat /VERSION 2>/dev/null || echo ''" 2>/dev/null) || {
    echo "ERROR: Cannot connect to $BIGIP_HOST:$SSH_PORT"
    exit 1
}

if ! echo "$PLATFORM_INFO" | grep -qi "BIG-IP"; then
    echo "ERROR: $BIGIP_HOST does not appear to be a F5 BIG-IP"
    echo "       /VERSION contents:"
    echo "$PLATFORM_INFO" | sed 's/^/         /'
    exit 1
fi

BIGIP_VERSION=$(echo "$PLATFORM_INFO" | grep -i "^Product:" | head -1 || true)
BIGIP_BUILD=$(echo "$PLATFORM_INFO" | grep -i "^Version:" | head -1 || true)
echo "    $BIGIP_VERSION"
echo "    $BIGIP_BUILD"

echo "==> Checking for Python 3 ..."
$SSH_CMD "$SSH_TARGET" "python3 --version" 2>&1 || {
    echo "ERROR: python3 not found on $BIGIP_HOST"
    exit 1
}

echo "==> Copying pba-stats to $BIGIP_HOST:$REMOTE_PATH ..."
$SSH_CMD "$SSH_TARGET" "mkdir -p /shared/scripts"
$SCP_CMD "$LOCAL_SCRIPT" "$SCP_TARGET:$REMOTE_PATH"

echo "==> Making executable ..."
$SSH_CMD "$SSH_TARGET" "chmod +x $REMOTE_PATH"

echo "==> Creating symlink $SYMLINK_PATH ..."
$SSH_CMD "$SSH_TARGET" "ln -sf $REMOTE_PATH $SYMLINK_PATH"

echo "==> Configuring startup persistence ..."
$SSH_CMD "$SSH_TARGET" bash -s <<'REMOTE_EOF'
STARTUP="/config/startup"
LINK_CMD="ln -sf /shared/scripts/pba-stats /usr/local/bin/pba-stats"

if [ ! -f "$STARTUP" ]; then
    printf '#!/bin/bash\n%s\n' "$LINK_CMD" > "$STARTUP"
    chmod +x "$STARTUP"
    echo "    Created $STARTUP"
elif ! grep -qF "pba-stats" "$STARTUP"; then
    printf '\n%s\n' "$LINK_CMD" >> "$STARTUP"
    echo "    Added symlink recreation to $STARTUP"
else
    echo "    $STARTUP already contains pba-stats entry"
fi
REMOTE_EOF

echo "==> Verifying installation ..."
$SSH_CMD "$SSH_TARGET" "pba-stats --help" 2>&1 | head -5

echo ""
echo "Done. Run 'pba-stats --summary' on the BIG-IP to test."
