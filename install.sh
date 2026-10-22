#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/syedshahriyarahmad/TraceNox.git"
INSTALL_DIR="${HOME}/.local/share/tracenox"
BIN_DIR="${HOME}/.local/bin"

if ! command -v git >/dev/null 2>&1; then
    echo "Error: Git is required. Install it with: sudo apt install git"
    exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3 is required."
    exit 1
fi

mkdir -p "$BIN_DIR" "$(dirname "$INSTALL_DIR")"

if [ -e "$INSTALL_DIR" ]; then
    echo "Error: $INSTALL_DIR already exists."
    echo "Back it up or remove it intentionally before reinstalling."
    exit 1
fi

git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
cd "$INSTALL_DIR"

python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install .

cat > "$BIN_DIR/tracenox" <<'LAUNCHER'
#!/usr/bin/env bash
exec "$HOME/.local/share/tracenox/.venv/bin/tracenox" "$@"
LAUNCHER

chmod +x "$BIN_DIR/tracenox"

echo
echo "TraceNox installed successfully."
echo "Run: ~/.local/bin/tracenox --help"
echo "Optional: add ~/.local/bin to PATH for the shorter 'tracenox' command."
