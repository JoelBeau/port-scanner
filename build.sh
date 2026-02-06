#!/bin/bash

# SocketScout Build and Install Script for Users
set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

determine-package-manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt-get"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v brew &> /dev/null; then
        echo "brew"
    else
        echo "none"
    fi
}

# -----------------------------
# Persistent Progress Bar (Pinned to Bottom)
# -----------------------------
TOTAL_STEPS=8
PROGRESS_ENABLED=0
CURRENT_STEP=0
TERM_LINES=0
SCROLL_TOP=0
SCROLL_BOTTOM=0  # bottom of scroll region (excludes bar line)

reserve_progress_line() {
    TERM_LINES=$(tput lines 2>/dev/null || echo 0)
    local last=$((TERM_LINES - 1))
    local bottom=$((TERM_LINES - 2))   # reserve last line for progress bar

    # If terminal is too small, disable
    if (( bottom < 1 )); then
        PROGRESS_ENABLED=0
        return
    fi

    SCROLL_TOP=0
    SCROLL_BOTTOM=$bottom

    # Set scrolling region to exclude the last line
    tput csr "$SCROLL_TOP" "$SCROLL_BOTTOM"
}

reset_scroll_region() {
    local last=$(( $(tput lines) - 1 ))
    tput csr 0 "$last"
}

init_progress() {
    if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
        PROGRESS_ENABLED=1
        tput civis
        reserve_progress_line
        # Ensure we have a dedicated bar line at the bottom
        printf "\n"
        trap 'finish_progress' EXIT
    fi
}

update_progress() {
    local step=$1
    local suffix=${2:-""}
    local bar_width=30
    local filled=$((step * bar_width / TOTAL_STEPS))
    local empty=$((bar_width - filled))
    local bar_fill="##############################"
    local filled_bar="${bar_fill:0:$filled}"
    local empty_bar
    empty_bar=$(printf '%*s' "$empty" "")

    local extra=""
    [[ -n "$suffix" ]] && extra=" ${suffix}"

    if [[ "$PROGRESS_ENABLED" -eq 1 ]]; then
        local bar_line=$(( $(tput lines) - 1 ))
        tput sc
        tput cup "$bar_line" 0
        printf "[%s%s] %d/%d%s" "$filled_bar" "$empty_bar" "$step" "$TOTAL_STEPS" "$extra"
        tput el
        tput rc
    else
        printf "\r[%s%s] %d/%d%s" "$filled_bar" "$empty_bar" "$step" "$TOTAL_STEPS" "$extra"
    fi
}

set_progress_step() {
    CURRENT_STEP=$1
    update_progress "$CURRENT_STEP"
}

run_with_spinner() {
    local message=$1
    shift
    local frames='|/-\\'
    local i=0
    local spinner_pid=""

    (
        while true; do
            local frame=${frames:i%4:1}
            update_progress "$CURRENT_STEP" "$message $frame"
            i=$((i + 1))
            sleep 0.1
        done
    ) &
    spinner_pid=$!

    "$@"
    local status=$?
    kill "$spinner_pid" >/dev/null 2>&1 || true
    wait "$spinner_pid" 2>/dev/null || true
    update_progress "$CURRENT_STEP"
    return $status
}

# Optional: quiet wrapper (prevents command output from interleaving with spinner redraw)
run_with_spinner_quiet() {
    local message=$1
    shift

    local tmp
    tmp=$(mktemp)

    # Run the command with output redirected
    run_with_spinner "$message" bash -c '"$@" >"'"$tmp"'" 2>&1' _ "$@"
    local status=$?

    if (( status != 0 )); then
        echo -e "${RED}✗ Command failed. Output:${NC}"
        cat "$tmp"
    fi

    rm -f "$tmp"
    return $status
}

finish_progress() {
    if [[ "$PROGRESS_ENABLED" -eq 1 ]]; then
        reset_scroll_region
        tput cnorm
        # Move cursor below the bar so the shell prompt doesn't land on it
        tput cup $(( $(tput lines) - 1 )) 0
        tput el
        printf "\n"
    fi
}

# -----------------------------
# Dependency install helpers
# -----------------------------
install-build-tools() {
    build_tools=( 'build' 'venv' 'pipx' )
    pkg_manager=$1

    for tool in "${build_tools[@]}"; do
        if ! python3 -c "import $tool" 2>/dev/null; then
            echo -e "${RED}✗ '$tool' package not found${NC}"
            echo "Installing $tool..."
            echo ""

            # Use quiet so apt/dnf output doesn't interleave with spinner redraw
            run_with_spinner_quiet "Updating packages..." sudo "$pkg_manager" update -y

            if [[ "$tool" == "pipx" ]]; then
                run_with_spinner_quiet "Installing pipx..." sudo "$pkg_manager" install -y pipx
                pipx ensurepath

                # Reload PATH (best-effort; won't always affect non-interactive shells)
                [[ -f ~/.bashrc ]] && source ~/.bashrc || true
            else
                run_with_spinner_quiet "Installing $tool..." sudo "$pkg_manager" install -y "python3-$tool"
            fi

            if ! python3 -c "import $tool" 2>/dev/null; then
                echo -e "${RED}✗ Failed to install '$tool'${NC}"
                exit 1
            fi

            echo -e "${GREEN}✓ '$tool' installed successfully${NC}"
        else
            echo -e "${GREEN}✓ '$tool' is installed${NC}"
        fi
    done
}

build-package() {
    python3 -m venv --system-site-packages build-env
    # shellcheck disable=SC1091
    source build-env/bin/activate
    python3 -m build
    deactivate
    sudo rm -rf build-env
}

# -----------------------------
# Main
# -----------------------------
echo "SocketScout - Build from Source"
echo "=========================================="
echo "This script will build and install SocketScout locally."
echo ""

PKG_MANAGER=$(determine-package-manager)

# Step 1: Clean previous builds
init_progress
set_progress_step 1
echo -e "${YELLOW}Step 1: Cleaning previous builds...${NC}"
rm -rf dist/ *.egg-info port_scanner.egg-info 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Check required Python version & dependency of libpcap-dev (for Linux)
set_progress_step 2
echo -e "${YELLOW}Step 2: Checking Python version and dependencies...${NC}"

# Proper Python version check (3.10+)
python3 - <<'PY'
import sys
sys.exit(0 if sys.version_info >= (3,10) else 1)
PY

if [[ $? -ne 0 ]]; then
    echo -e "${RED}✗ Python 3.10 or higher is required${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Python version is sufficient${NC}"
fi

if [[ "$PKG_MANAGER" == "none" ]]; then
    echo -e "${RED}✗ No supported package manager found (apt-get/dnf/brew)${NC}"
    echo "Please install 'build', 'venv', and 'pipx' manually and re-run this script."
    exit 1
else
    echo -e "${GREEN}✓ Detected package manager: $PKG_MANAGER${NC}"
fi

# Linux-only libpcap-dev (apt) / libpcap-devel (dnf)
if [[ "$(uname)" == "Linux" ]]; then
    if [[ "$PKG_MANAGER" == "apt-get" ]]; then
        PCAP_PKG="libpcap-dev"
        PCAP_CHECK_CMD='dpkg -s libpcap-dev'
    elif [[ "$PKG_MANAGER" == "dnf" ]]; then
        PCAP_PKG="libpcap-devel"
        PCAP_CHECK_CMD='rpm -q libpcap-devel'
    else
        PCAP_PKG=""
        PCAP_CHECK_CMD=""
    fi

    if [[ -n "$PCAP_PKG" ]]; then
        if ! bash -c "$PCAP_CHECK_CMD" &>/dev/null; then
            echo -e "${RED}✗ '$PCAP_PKG' package not found${NC}"
            echo "Installing '$PCAP_PKG'..."
            echo ""

            run_with_spinner_quiet "Updating packages..." sudo "$PKG_MANAGER" update -y
            run_with_spinner_quiet "Installing $PCAP_PKG..." sudo "$PKG_MANAGER" install -y "$PCAP_PKG"

            echo ""
            if ! bash -c "$PCAP_CHECK_CMD" &>/dev/null; then
                echo -e "${RED}✗ Failed to install '$PCAP_PKG'${NC}"
                exit 1
            fi
            echo -e "${GREEN}✓ '$PCAP_PKG' installed successfully${NC}"
        else
            echo -e "${GREEN}✓ '$PCAP_PKG' is installed${NC}"
        fi
    else
        echo -e "${YELLOW}⚠ Skipping libpcap dependency check for package manager: $PKG_MANAGER${NC}"
    fi
fi
echo ""

# Step 3: Check if build tools are installed
set_progress_step 3
echo -e "${YELLOW}Step 3: Checking build tools...${NC}"
run_with_spinner "installing build tools" install-build-tools "$PKG_MANAGER"
echo ""

# Step 4: Build the package
set_progress_step 4
echo -e "${YELLOW}Step 4: Building package...${NC}"
run_with_spinner_quiet "building package" build-package
echo -e "${GREEN}✓ Package built successfully${NC}"
echo ""

# Step 5: List created files
set_progress_step 5
echo -e "${YELLOW}Step 5: Generated files:${NC}"
ls -l dist/
echo ""

# Step 6: Install the package
set_progress_step 6
echo -e "${YELLOW}Step 6: Installing SocketScout...${NC}"
WHEEL_FILE=$(ls dist/*.whl | head -n 1)
run_with_spinner_quiet "Installing SocketScout..." pipx install "$WHEEL_FILE"
echo ""

# Step 7: Check command availability
set_progress_step 7
echo -e "${YELLOW}Step 7: Verifying installation...${NC}"
if command -v socketscout &> /dev/null; then
    echo -e "${GREEN}✓ 'socketscout' command is available${NC}"
else
    echo -e "${RED}✗ 'socketscout' command not found${NC}"
    echo "Please ensure ~/.local/bin is in your PATH (or run: pipx ensurepath)."
    exit 1
fi
echo ""

# Step 8: Done
set_progress_step 8
echo -e "${GREEN}=========================================="
echo -e "✓ Installation complete!${NC}"
echo ""
echo "You can now run:"
echo "  sudo socketscout --help"
echo "  sudo socketscout -t localhost"
echo ""
echo "For documentation, see README.md"