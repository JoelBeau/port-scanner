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
            sudo $pkg_manager update -y
            sudo $pkg_manager install -y python3-$tool

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



# Step 1: Clean previous builds
echo -e "${YELLOW}Step 1: Cleaning previous builds...${NC}"
rm -rf dist/ *.egg-info port_scanner.egg-info 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Check required Python version & dependency of lipcap-dev (for Linux)
echo -e "${YELLOW}Step 2: Checking Python version and dependencies...${NC}"
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
if [[ "$PYTHON_VERSION" -gt "3.8" ]]; then
    echo -e "${RED}✗ Python 3.8 or higher is required (found $PYTHON_VERSION)${NC}"
    exit 1
else
    echo -e "${GREEN}✓ Python version $PYTHON_VERSION is sufficient${NC}"
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

        sudo $PKG_MANAGER update -y
        sudo $PKG_MANAGER install -y libpcap-dev
    else
        echo -e "${GREEN}✓ 'libpcap-dev' is installed${NC}"
    fi
fi
echo ""

# Step 3: Check if build tools are installed
echo -e "${YELLOW}Step 3: Checking build tools...${NC}"
install-build-tools "$PKG_MANAGER"
echo ""

# Step 4: Build the package
echo -e "${YELLOW}Step 4: Building package...${NC}"
python -m venv build-env
source build-env/bin/activate
python -m build
deactivate
sudo rm -rf build-env
echo -e "${GREEN}✓ Package built successfully${NC}"
echo ""

# Step 4: List created files
echo -e "${YELLOW}Step 5: Generated files:${NC}"
ls -lh dist/
echo ""

# Step 5: Install the package
echo -e "${YELLOW}Step 6: Installing SocketScout...${NC}"
WHEEL_FILE=$(ls dist/*.whl | head -n 1)
pipx install --no-cache-dir "$WHEEL_FILE"
echo ""

# Step 6: Create alias for easy access
echo -e "${YELLOW}Step 7: Setting up alias...${NC}"
if [[ -f ~/.bash_aliases ]]; then
    if ! grep -q "alias socketscout=" ~/.bash_aliases; then
        echo "alias socketscout='sudo ~/.local/bin/socketscout'" >> ~/.bash_aliases
        echo -e "${GREEN}✓ Alias added to ~/.bash_aliases${NC}"
    else
        echo -e "${YELLOW}✓ Alias already exists in ~/.bash_aliases${NC}"
    fi
else
    echo "alias socketscout='sudo ~/.local/bin/socketscout'" >> ~/.bash_aliases
    echo -e "${GREEN}✓ Alias created in ~/.bash_aliases${NC}"
fi

source ~/.bashrc

echo -e "${GREEN}=========================================="
echo "✓ Installation complete!${NC}"
echo ""
echo "You can now run:"
echo "  sudo socketscout --help"
echo "  sudo socketscout -t localhost"
echo ""
echo "For documentation, see README.md"
