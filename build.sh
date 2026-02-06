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
            set_progress_message "Updating packages... "
            sudo $pkg_manager update -y
            if [[ "$tool" == "pipx" ]]; then
                # Ensure pipx is on the PATH
                set_progress_message "Installing pipx... "
                sudo $pkg_manager install -y pipx
                pipx ensurepath
                
                # Reload the shell to update PATH for pipx without requiring a new terminal session
                source ~/.bashrc
            else
                set_progress_message "Installing $tool... "
                sudo $pkg_manager install -y python3-$tool
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
SPINNER_PID=0
SPINNER_RUNNING=0
CURRENT_MESSAGE=""
PROGRESS_LINE=0
PROGRESS_TTY="/dev/tty"
init_progress() {
    if command -v tput >/dev/null 2>&1 && [[ -w "$PROGRESS_TTY" ]]; then
        PROGRESS_ENABLED=1
        local lines
        lines=$(tput lines)
        if [[ "$lines" -lt 3 ]]; then
            PROGRESS_ENABLED=0
            return
        fi
        tput civis > "$PROGRESS_TTY"
        PROGRESS_LINE=$((lines - 1))
        tput csr 0 $((PROGRESS_LINE - 1)) > "$PROGRESS_TTY"
        tput cup 0 0 > "$PROGRESS_TTY"
        tput el > "$PROGRESS_TTY"
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
        tput sc > "$PROGRESS_TTY"
        tput cup "$PROGRESS_LINE" 0 > "$PROGRESS_TTY"
        printf "[%s%s] %d/%d%s" "$filled_bar" "$empty_bar" "$step" "$TOTAL_STEPS" "$extra" > "$PROGRESS_TTY"
        tput el > "$PROGRESS_TTY"
        tput rc > "$PROGRESS_TTY"
    else
        printf "\r[%s%s] %d/%d%s" "$filled_bar" "$empty_bar" "$step" "$TOTAL_STEPS" "$extra"
    fi
}

set_progress_step() {
    CURRENT_STEP=$1
    update_progress "$CURRENT_STEP"
    restart_spinner
}

set_progress_message() {
    CURRENT_MESSAGE=$1
    restart_spinner
}

start_spinner() {
    if [[ "$PROGRESS_ENABLED" -eq 1 && "$SPINNER_RUNNING" -eq 0 ]]; then
        SPINNER_RUNNING=1
        (
            local frames='|/-\\'
            local i=0
            while true; do
                local frame=${frames:i%4:1}
                update_progress "$CURRENT_STEP" "${CURRENT_MESSAGE}${frame}"
                i=$((i + 1))
                sleep 0.1
            done
        ) &
        SPINNER_PID=$!
    fi
}

stop_spinner() {
    if [[ "$SPINNER_RUNNING" -eq 1 ]]; then
        kill "$SPINNER_PID" >/dev/null 2>&1 || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_RUNNING=0
        update_progress "$CURRENT_STEP"
    fi
}

run_without_spinner() {
    stop_spinner
    "$@"
    local status=$?
    start_spinner
    update_progress "$CURRENT_STEP"
    return $status
}

restart_spinner() {
    if [[ "$SPINNER_RUNNING" -eq 1 ]]; then
        stop_spinner
        start_spinner
    fi
}

finish_progress() {
    stop_spinner
    if [[ "$PROGRESS_ENABLED" -eq 1 ]]; then
        local lines
        lines=$(tput lines)
        tput csr 0 $((lines - 1)) > "$PROGRESS_TTY"
        tput cup "$PROGRESS_LINE" 0 > "$PROGRESS_TTY"
        tput el > "$PROGRESS_TTY"
        tput cnorm > "$PROGRESS_TTY"
    fi
}



# Step 1: Clean previous builds
init_progress
start_spinner
set_progress_step 1
set_progress_message "Cleaning... "
echo -e "${YELLOW}Step 1: Cleaning previous builds...${NC}"
rm -rf dist/ *.egg-info port_scanner.egg-info 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Check required Python version & dependency of lipcap-dev (for Linux)
set_progress_step 2
set_progress_message "Checking dependencies... "
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

        set_progress_message "Updating packages... "
        sudo $PKG_MANAGER update -y
        set_progress_message "Installing libpcap-dev... "
        sudo $PKG_MANAGER install -y libpcap-dev

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
set_progress_message "Checking build tools... "
echo -e "${YELLOW}Step 3: Checking build tools...${NC}"
install-build-tools "$PKG_MANAGER"
echo ""

# Step 4: Build the package
set_progress_step 4
set_progress_message "Building package... "
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
set_progress_message "Listing files... "
echo -e "${YELLOW}Step 5: Generated files:${NC}"
ls -lh dist/
echo ""

# Step 6: Install the package
set_progress_step 6
set_progress_message "Installing SocketScout... "
echo -e "${YELLOW}Step 6: Installing SocketScout...${NC}"
WHEEL_FILE=$(ls dist/*.whl | head -n 1)
run_without_spinner pipx install "$WHEEL_FILE"
echo ""


# Step 7: Check command availability
set_progress_step 7
set_progress_message "Verifying installation... "
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
set_progress_message "Finishing... "
echo -e "${GREEN}=========================================="
echo -e "✓ Installation complete!${NC}"
echo ""
echo "You can now run:"
echo "  sudo socketscout --help"
echo "  sudo socketscout -t localhost"
echo ""
echo "For documentation, see README.md"
