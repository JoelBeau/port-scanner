#!/bin/bash

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

install-build-tools() {

    build_tools=( 'build' 'venv' 'pipx' )

    pkg_manager=$1

    for tool in "${build_tools[@]}"; do
        if ! python -c "import $tool" 2>/dev/null; then
            echo -e "${RED}✗ '$tool' package not found${NC}"
            echo "Installing $tool..."
            echo ""
            run_with_spinner "Updating packages..." sudo $pkg_manager update -y
            if [[ "$tool" == "pipx" ]]; then
                # Ensure pipx is on the PATH
                run_with_spinner "Installing pipx..." sudo $pkg_manager install -y pipx
                pipx ensurepath
                
                # Reload the shell to update PATH for pipx without requiring a new terminal session
                source ~/.bashrc
            else
                run_with_spinner "Installing $tool..." sudo $pkg_manager install -y python3-$tool
            fi

            if ! python -c "import $tool" 2>/dev/null; then
                echo -e "${RED}✗ Failed to install '$tool'${NC}"
                exit 1
            fi


            echo -e "${GREEN}✓ '$tool' installed successfully${NC}"
        else
            echo -e "${GREEN}✓ '$tool' is installed${NC}"
        fi
    done
}


# SocketScout Build and Install Script for Users

set -e  # Exit on any error

echo "SocketScout - Build from Source"
echo "=========================================="
echo "This script will build and install SocketScout locally."
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
PKG_MANAGER=$(determine-package-manager)

# Persistent progress bar for major steps
TOTAL_STEPS=8
PROGRESS_ENABLED=0
CURRENT_STEP=0
init_progress() {
    if command -v tput >/dev/null 2>&1; then
        PROGRESS_ENABLED=1
        tput civis
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
    if [[ -n "$suffix" ]]; then
        extra=" ${suffix}"
    fi

    if [[ "$PROGRESS_ENABLED" -eq 1 ]]; then
        local line=$(( $(tput lines) - 1 ))
        tput sc
        tput cup "$line" 0
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

finish_progress() {
    if [[ "$PROGRESS_ENABLED" -eq 1 ]]; then
        tput cnorm
    fi
}



# Step 1: Clean previous builds
init_progress
set_progress_step 1
echo -e "${YELLOW}Step 1: Cleaning previous builds...${NC}"
rm -rf dist/ *.egg-info port_scanner.egg-info 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Check required Python version & dependency of lipcap-dev (for Linux)
set_progress_step 2
echo -e "${YELLOW}Step 2: Checking Python version and dependencies...${NC}"
PYTHON_VERSION=$(python3 -c "import sys; print(sys.version_info >= (3, 10))")
if [[ $PYTHON_VERSION -eq 1 ]]; then
    echo -e "${RED}✗ Python 3.10 or higher is required ${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Python version is sufficient${NC}"
fi

if [[ "$PKG_MANAGER" == "none" ]]; then
    echo -e "${RED}✗ No supported package manager found (apt-get/dnf)${NC}"
    echo "Please install 'build', 'venv', and 'pipx' packages manually and re-run this script."
    exit 1
else
    echo -e "${GREEN}✓ Detected package manager: $PKG_MANAGER${NC}"
fi

if [[ "$(uname)" == "Linux" ]]; then
    if ! dpkg -s libpcap-dev &> /dev/null; then
        echo -e "${RED}✗ 'libpcap-dev' package not found${NC}"
        echo "Installing 'libpcap-dev'..."
        echo ""

        run_with_spinner "Updating packages..." sudo $PKG_MANAGER update -y
        run_with_spinner "Installing libpcap-dev..." sudo $PKG_MANAGER install -y libpcap-dev

        echo ""
        if ! dpkg -s libpcap-dev &> /dev/null; then
            echo -e "${RED}✗ Failed to install 'libpcap-dev'${NC}"
            exit 1
        fi
        echo -e "${GREEN}✓ 'libpcap-dev' installed successfully${NC}"
    else
        echo -e "${GREEN}✓ 'libpcap-dev' is installed${NC}"
    fi
fi
echo ""

# Step 3: Check if build tools are installed
set_progress_step 3
echo -e "${YELLOW}Step 3: Checking build tools...${NC}"
install-build-tools "$PKG_MANAGER"
echo ""

# Step 4: Build the package
set_progress_step 4
echo -e "${YELLOW}Step 4: Building package...${NC}"
python -m venv --system-site-packages build-env
source build-env/bin/activate
python -m build
deactivate
sudo rm -rf build-env
echo -e "${GREEN}✓ Package built successfully${NC}"
echo ""

# Step 5: List created files
set_progress_step 5
echo -e "${YELLOW}Step 5: Generated files:${NC}"
ls -lh dist/
echo ""

# Step 6: Install the package
set_progress_step 6
echo -e "${YELLOW}Step 6: Installing SocketScout...${NC}"
WHEEL_FILE=$(ls dist/*.whl | head -n 1)
run_with_spinner "Installing SocketScout..." pipx install "$WHEEL_FILE"
echo ""


# Step 7: Check command availability
set_progress_step 7
echo -e "${YELLOW}Step 7: Verifying installation...${NC}"
if command -v socketscout &> /dev/null; then
    echo -e "${GREEN}✓ 'socketscout' command is available${NC}"
else
    echo -e "${RED}✗ 'socketscout' command not found${NC}"
    echo "Please check the alias setup and ensure ~/.local/bin is in your PATH."
    exit 1
fi
echo ""

set_progress_step 8
echo -e "${GREEN}=========================================="
echo -e "✓ Installation complete!${NC}"
echo ""
echo "You can now run:"
echo "  sudo socketscout --help"
echo "  sudo socketscout -t localhost"
echo ""
echo "For documentation, see README.md"
