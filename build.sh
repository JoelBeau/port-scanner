#!/bin/bash
# SocketScout Build and Install Script for End Users

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

# Step 1: Clean previous builds
echo -e "${YELLOW}Step 1: Cleaning previous builds...${NC}"
rm -rf dist/ build/ *.egg-info port_scanner.egg-info 2>/dev/null || true
find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
find . -type f -name "*.pyc" -delete 2>/dev/null || true
echo -e "${GREEN}✓ Cleaned${NC}"
echo ""

# Step 2: Check if build tools are installed
echo -e "${YELLOW}Step 2: Checking build tools...${NC}"
if ! python -c "import build" 2>/dev/null; then
    echo -e "${RED}✗ 'build' package not found${NC}"
    echo "Installing build tools..."
    echo ""
    
    # Check if we can install (venv or user install)
    if [ -n "$VIRTUAL_ENV" ]; then
        pip install --upgrade build
    else
        echo "Installing with --user flag (no virtual environment detected)"
        pip install --user --upgrade build
    fi
    echo ""
else
    echo -e "${GREEN}✓ Build tools installed${NC}"
fi
echo ""

# Step 3: Build the package
echo -e "${YELLOW}Step 3: Building package...${NC}"
python -m build
echo -e "${GREEN}✓ Package built successfully${NC}"
echo ""

# Step 4: List created files
echo -e "${YELLOW}Step 4: Generated files:${NC}"
ls -lh dist/
echo ""

# Step 5: Install the package
echo -e "${YELLOW}Step 5: Installing SocketScout...${NC}"
WHEEL_FILE=$(ls dist/*.whl | head -n 1)

if [ -n "$VIRTUAL_ENV" ]; then
    echo "Installing to current virtual environment..."
    pip install --force-reinstall "$WHEEL_FILE"
else
    echo "Installing with --user flag (no virtual environment detected)..."
    pip install --user --force-reinstall "$WHEEL_FILE"
fi
echo ""

echo -e "${GREEN}=========================================="
echo "✓ Installation complete!${NC}"
echo ""
echo "You can now run:"
echo "  sudo socketscout --help"
echo "  sudo socketscout -t localhost"
echo ""
echo "For documentation, see README.md"
