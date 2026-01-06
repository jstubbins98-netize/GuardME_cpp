#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}"
echo "   ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ███╗   ███╗███████╗"
echo "  ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗████╗ ████║██╔════╝"
echo "  ██║  ███╗██║   ██║███████║██████╔╝██║  ██║██╔████╔██║█████╗  "
echo "  ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║██║╚██╔╝██║██╔══╝  "
echo "  ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝██║ ╚═╝ ██║███████╗"
echo "   ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚══════╝"
echo -e "${NC}"
echo "          Setup Script - Automated Build System"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BUILD_VERSION=""

show_menu() {
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}              SELECT VERSION TO INSTALL${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Console Version (Terminal-based)"
    echo -e "     - Lightweight, works in any terminal"
    echo -e "     - Ideal for servers, cloud, SSH access"
    echo -e "     - No GUI dependencies required"
    echo ""
    echo -e "  ${GREEN}2)${NC} GUI Version (Graphical Desktop App)"
    echo -e "     - Full graphical interface with tabs"
    echo -e "     - Requires Qt6 and OpenGL support"
    echo -e "     - Best for local desktop use"
    echo ""
    echo -e "  ${GREEN}3)${NC} Both Versions"
    echo -e "     - Install console and GUI versions"
    echo ""
    echo -e "  ${GREEN}0)${NC} Exit"
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
}

if [ -z "$1" ]; then
    show_menu
    read -p "Enter your choice [1-3, 0 to exit]: " choice
else
    choice=$1
fi

case $choice in
    1) BUILD_VERSION="console" ;;
    2) BUILD_VERSION="gui" ;;
    3) BUILD_VERSION="both" ;;
    0) echo "Exiting..."; exit 0 ;;
    *) echo -e "${RED}Invalid choice. Exiting.${NC}"; exit 1 ;;
esac

echo ""
echo -e "Selected: ${GREEN}$BUILD_VERSION${NC} version"
echo ""

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        echo "apt"
    elif command -v dnf &> /dev/null; then
        echo "dnf"
    elif command -v yum &> /dev/null; then
        echo "yum"
    elif command -v pacman &> /dev/null; then
        echo "pacman"
    elif command -v brew &> /dev/null; then
        echo "brew"
    elif command -v nix-env &> /dev/null; then
        echo "nix"
    else
        echo "unknown"
    fi
}

check_command() {
    if command -v "$1" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

echo -e "${BLUE}[1/6]${NC} Detecting system..."
PKG_MANAGER=$(detect_package_manager)

if [[ "$OSTYPE" == "darwin"* ]] && [ "$PKG_MANAGER" == "unknown" ]; then
    echo -e "       macOS detected but Homebrew not found"
    echo -e "       ${YELLOW}Installing Homebrew...${NC}"
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    if [[ -f /opt/homebrew/bin/brew ]]; then
        eval "$(/opt/homebrew/bin/brew shellenv)"
    elif [[ -f /usr/local/bin/brew ]]; then
        eval "$(/usr/local/bin/brew shellenv)"
    fi
    
    PKG_MANAGER="brew"
    echo -e "       ${GREEN}✓${NC} Homebrew installed successfully"
fi

echo -e "       Package manager: ${GREEN}$PKG_MANAGER${NC}"
echo -e "       Build target: ${GREEN}$BUILD_VERSION${NC}"

MISSING_DEPS=()

echo -e "${BLUE}[2/6]${NC} Checking core dependencies..."

if check_command g++; then
    GXX_VERSION=$(g++ --version | head -n1)
    echo -e "       ${GREEN}✓${NC} g++ found: $GXX_VERSION"
else
    echo -e "       ${RED}✗${NC} g++ not found"
    MISSING_DEPS+=("g++")
fi

if check_command pkg-config; then
    echo -e "       ${GREEN}✓${NC} pkg-config found"
else
    echo -e "       ${RED}✗${NC} pkg-config not found"
    MISSING_DEPS+=("pkg-config")
fi

if pkg-config --exists libcurl 2>/dev/null; then
    CURL_VERSION=$(pkg-config --modversion libcurl)
    echo -e "       ${GREEN}✓${NC} libcurl found: $CURL_VERSION"
else
    echo -e "       ${RED}✗${NC} libcurl development files not found"
    MISSING_DEPS+=("libcurl")
fi

if pkg-config --exists openssl 2>/dev/null; then
    SSL_VERSION=$(pkg-config --modversion openssl)
    echo -e "       ${GREEN}✓${NC} openssl found: $SSL_VERSION"
else
    echo -e "       ${RED}✗${NC} openssl development files not found"
    MISSING_DEPS+=("openssl")
fi

if check_command whois; then
    echo -e "       ${GREEN}✓${NC} whois found"
else
    echo -e "       ${YELLOW}○${NC} whois not found (needed for WHOIS lookup)"
    MISSING_DEPS+=("whois")
fi

INSTALL_ESPEAK=false
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    if check_command espeak; then
        echo -e "       ${GREEN}✓${NC} espeak found (text-to-speech)"
    else
        echo -e "       ${YELLOW}○${NC} espeak not found (optional, for Guardi voice)"
        echo ""
        read -p "       Would you like to install espeak for text-to-speech? (y/n): " install_espeak
        if [[ "$install_espeak" =~ ^[Yy]$ ]]; then
            INSTALL_ESPEAK=true
            MISSING_DEPS+=("espeak")
            echo -e "       ${CYAN}→${NC} espeak will be installed"
        else
            echo -e "       ${YELLOW}→${NC} Skipping espeak installation (text-to-speech will be disabled)"
        fi
    fi
else
    echo -e "       ${CYAN}○${NC} espeak not needed on this platform (macOS uses built-in 'say')"
fi

INSTALL_CLAMAV=false
if check_command clamscan; then
    CLAM_VERSION=$(clamscan --version 2>/dev/null | head -n1)
    echo -e "       ${GREEN}✓${NC} ClamAV found: $CLAM_VERSION"
else
    echo -e "       ${YELLOW}○${NC} ClamAV not found (optional, for virus scanning)"
    echo ""
    read -p "       Would you like to install ClamAV for virus scanning? (y/n): " install_clam
    if [[ "$install_clam" =~ ^[Yy]$ ]]; then
        INSTALL_CLAMAV=true
        MISSING_DEPS+=("clamav")
        echo -e "       ${CYAN}→${NC} ClamAV will be installed"
    else
        echo -e "       ${YELLOW}→${NC} Skipping ClamAV installation (virus scanning will be disabled)"
    fi
fi

if [ "$BUILD_VERSION" == "gui" ] || [ "$BUILD_VERSION" == "both" ]; then
    echo -e "${BLUE}[3/6]${NC} Checking GUI dependencies..."
    
    if check_command cmake; then
        CMAKE_VERSION=$(cmake --version | head -n1)
        echo -e "       ${GREEN}✓${NC} CMake found: $CMAKE_VERSION"
    else
        echo -e "       ${RED}✗${NC} CMake not found"
        MISSING_DEPS+=("cmake")
    fi
    
    if pkg-config --exists Qt6Core 2>/dev/null || check_command qmake6; then
        echo -e "       ${GREEN}✓${NC} Qt6 found"
    else
        echo -e "       ${RED}✗${NC} Qt6 not found"
        MISSING_DEPS+=("qt6")
    fi
    
    if [ -f /usr/include/nlohmann/json.hpp ] || pkg-config --exists nlohmann_json 2>/dev/null || [ -d /opt/homebrew/include/nlohmann ] || [ -d /usr/local/include/nlohmann ]; then
        echo -e "       ${GREEN}✓${NC} nlohmann-json found"
    else
        echo -e "       ${YELLOW}○${NC} nlohmann-json not found"
        MISSING_DEPS+=("nlohmann-json")
    fi
else
    echo -e "${BLUE}[3/6]${NC} GUI dependencies not required for console build ${GREEN}✓${NC}"
fi

if [ ${#MISSING_DEPS[@]} -gt 0 ]; then
    echo ""
    echo -e "${BLUE}[4/6]${NC} Installing missing dependencies..."
    
    case $PKG_MANAGER in
        apt)
            PACKAGES=""
            for dep in "${MISSING_DEPS[@]}"; do
                case $dep in
                    "g++") PACKAGES="$PACKAGES g++" ;;
                    "pkg-config") PACKAGES="$PACKAGES pkg-config" ;;
                    "libcurl") PACKAGES="$PACKAGES libcurl4-openssl-dev" ;;
                    "openssl") PACKAGES="$PACKAGES libssl-dev" ;;
                    "clamav") PACKAGES="$PACKAGES clamav clamav-daemon" ;;
                    "whois") PACKAGES="$PACKAGES whois" ;;
                    "espeak") PACKAGES="$PACKAGES espeak" ;;
                    "cmake") PACKAGES="$PACKAGES cmake" ;;
                    "qt6") PACKAGES="$PACKAGES qt6-base-dev qt6-tools-dev libgl1-mesa-dev" ;;
                    "nlohmann-json") PACKAGES="$PACKAGES nlohmann-json3-dev" ;;
                esac
            done
            echo -e "       Running: sudo apt-get install -y $PACKAGES"
            sudo apt-get update -qq
            sudo apt-get install -y $PACKAGES
            ;;
        dnf|yum)
            PACKAGES=""
            for dep in "${MISSING_DEPS[@]}"; do
                case $dep in
                    "g++") PACKAGES="$PACKAGES gcc-c++" ;;
                    "pkg-config") PACKAGES="$PACKAGES pkgconfig" ;;
                    "libcurl") PACKAGES="$PACKAGES libcurl-devel" ;;
                    "openssl") PACKAGES="$PACKAGES openssl-devel" ;;
                    "clamav") PACKAGES="$PACKAGES clamav clamav-update" ;;
                    "whois") PACKAGES="$PACKAGES whois" ;;
                    "espeak") PACKAGES="$PACKAGES espeak" ;;
                    "cmake") PACKAGES="$PACKAGES cmake" ;;
                    "qt6") PACKAGES="$PACKAGES qt6-qtbase-devel mesa-libGL-devel" ;;
                    "nlohmann-json") PACKAGES="$PACKAGES json-devel" ;;
                esac
            done
            echo -e "       Running: sudo $PKG_MANAGER install -y $PACKAGES"
            sudo $PKG_MANAGER install -y $PACKAGES
            ;;
        pacman)
            PACKAGES=""
            for dep in "${MISSING_DEPS[@]}"; do
                case $dep in
                    "g++") PACKAGES="$PACKAGES gcc" ;;
                    "pkg-config") PACKAGES="$PACKAGES pkgconf" ;;
                    "libcurl") PACKAGES="$PACKAGES curl" ;;
                    "openssl") PACKAGES="$PACKAGES openssl" ;;
                    "clamav") PACKAGES="$PACKAGES clamav" ;;
                    "whois") PACKAGES="$PACKAGES whois" ;;
                    "espeak") PACKAGES="$PACKAGES espeak" ;;
                    "cmake") PACKAGES="$PACKAGES cmake" ;;
                    "qt6") PACKAGES="$PACKAGES qt6-base" ;;
                    "nlohmann-json") PACKAGES="$PACKAGES nlohmann-json" ;;
                esac
            done
            echo -e "       Running: sudo pacman -S --noconfirm $PACKAGES"
            sudo pacman -S --noconfirm $PACKAGES
            ;;
        brew)
            for dep in "${MISSING_DEPS[@]}"; do
                case $dep in
                    "g++") brew install gcc ;;
                    "pkg-config") brew install pkg-config ;;
                    "libcurl") brew install curl ;;
                    "openssl") brew install openssl ;;
                    "clamav") brew install clamav ;;
                    "whois") brew install whois ;;
                    "espeak") brew install espeak ;;
                    "cmake") brew install cmake ;;
                    "qt6") brew install qt@6 ;;
                    "nlohmann-json") brew install nlohmann-json ;;
                esac
            done
            if [[ " ${MISSING_DEPS[*]} " =~ " qt6 " ]]; then
                echo -e "       ${YELLOW}Note:${NC} Add Qt6 to PATH: export PATH=\"/opt/homebrew/opt/qt@6/bin:\$PATH\""
            fi
            ;;
        nix)
            echo -e "       ${YELLOW}Nix detected - dependencies should be available via nix-shell${NC}"
            echo -e "       Attempting to use existing nix environment..."
            ;;
        *)
            echo -e "${RED}Error: Unknown package manager. Please install manually:${NC}"
            echo "  - g++ (C++ compiler)"
            echo "  - pkg-config"
            echo "  - libcurl development files"
            echo "  - openssl development files"
            echo "  - clamav (optional)"
            if [ "$BUILD_VERSION" == "gui" ] || [ "$BUILD_VERSION" == "both" ]; then
                echo "  - cmake"
                echo "  - Qt6 development files"
                echo "  - nlohmann-json"
            fi
            exit 1
            ;;
    esac
    
    echo -e "       ${GREEN}✓${NC} Dependencies installed"
else
    echo -e "${BLUE}[4/6]${NC} All dependencies already installed ${GREEN}✓${NC}"
fi

echo -e "${BLUE}[5/6]${NC} Checking build directory..."
if [ -d "build" ]; then
    echo -e "       ${GREEN}✓${NC} Build directory already exists"
else
    echo -e "       Creating build directory..."
    mkdir -p build
    echo -e "       ${GREEN}✓${NC} Build directory created"
fi

echo -e "${BLUE}[6/6]${NC} Compiling GuardME..."
echo ""

CONSOLE_SUCCESS=false
GUI_SUCCESS=false

if [ "$BUILD_VERSION" == "console" ] || [ "$BUILD_VERSION" == "both" ]; then
    echo -e "       ${CYAN}Building Console Version...${NC}"
    
    CFLAGS=$(pkg-config --cflags libcurl openssl 2>/dev/null || echo "")
    LIBS=$(pkg-config --libs libcurl openssl 2>/dev/null || echo "-lcurl -lssl -lcrypto")
    
    COMPILE_CMD="g++ -std=c++17 -Wall -O2 $CFLAGS -o build/guardme_console src/console_main.cpp $LIBS"
    echo -e "       Command: ${YELLOW}$COMPILE_CMD${NC}"
    echo ""
    
    if $COMPILE_CMD; then
        CONSOLE_SUCCESS=true
        echo -e "       ${GREEN}✓${NC} Console version built successfully"
    else
        echo -e "       ${RED}✗${NC} Console build failed"
    fi
    echo ""
fi

if [ "$BUILD_VERSION" == "gui" ] || [ "$BUILD_VERSION" == "both" ]; then
    echo -e "       ${CYAN}Building GUI Version...${NC}"
    
    # macOS: Ensure CMake is up to date to avoid parse errors with Qt6
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "       ${CYAN}Updating CMake for Qt6 compatibility...${NC}"
        brew upgrade cmake 2>/dev/null || brew install cmake
        echo -e "       ${GREEN}✓${NC} CMake is up to date"
    fi
    
    # Clean build directory to avoid stale cache issues
    rm -rf build/*
    mkdir -p build
    cd build
    
    if [[ "$OSTYPE" == "darwin"* ]]; then
        CMAKE_CMD="cmake .. -DCMAKE_PREFIX_PATH=$(brew --prefix qt@6 2>/dev/null || echo '/opt/homebrew/opt/qt@6')"
    else
        CMAKE_CMD="cmake .."
    fi
    
    echo -e "       Command: ${YELLOW}$CMAKE_CMD${NC}"
    
    if $CMAKE_CMD 2>&1; then
        echo -e "       ${GREEN}✓${NC} CMake configuration successful"
        
        NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "2")
        echo -e "       Command: ${YELLOW}make -j$NPROC${NC}"
        
        if make -j$NPROC 2>&1; then
            GUI_SUCCESS=true
            echo -e "       ${GREEN}✓${NC} GUI version built successfully"
        else
            echo -e "       ${RED}✗${NC} GUI build failed (make error)"
            echo -e "       ${YELLOW}Note:${NC} GUI requires OpenGL support. Cloud environments may not support this."
        fi
    else
        echo -e "       ${RED}✗${NC} CMake configuration failed"
        echo -e "       ${YELLOW}Note:${NC} Ensure Qt6 is installed with OpenGL support"
    fi
    
    cd "$SCRIPT_DIR"
    echo ""
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}                     BUILD SUMMARY${NC}"
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$BUILD_VERSION" == "console" ] || [ "$BUILD_VERSION" == "both" ]; then
    if [ "$CONSOLE_SUCCESS" = true ]; then
        echo -e "  Console Version: ${GREEN}SUCCESS${NC}"
        echo -e "    Location: ${BLUE}$SCRIPT_DIR/build/guardme_console${NC}"
        echo -e "    Run with: ${YELLOW}./build/guardme_console${NC}"
    else
        echo -e "  Console Version: ${RED}FAILED${NC}"
    fi
    echo ""
fi

if [ "$BUILD_VERSION" == "gui" ] || [ "$BUILD_VERSION" == "both" ]; then
    if [ "$GUI_SUCCESS" = true ]; then
        echo -e "  GUI Version: ${GREEN}SUCCESS${NC}"
        echo -e "    Location: ${BLUE}$SCRIPT_DIR/build/GuardME${NC}"
        echo -e "    Run with: ${YELLOW}./build/GuardME${NC}"
    else
        echo -e "  GUI Version: ${RED}FAILED${NC}"
        echo -e "    ${YELLOW}Tip:${NC} GUI requires Qt6 with OpenGL. Try console version instead."
    fi
    echo ""
fi

if check_command clamscan; then
    echo -e "  ClamAV: ${GREEN}Available${NC} - Virus scanning enabled"
    echo -e "  ${YELLOW}Note:${NC} Run 'sudo freshclam' to update virus definitions"
else
    echo -e "  ClamAV: ${YELLOW}Not available${NC} - Virus scanning disabled"
fi

echo ""
echo -e "${CYAN}════════════════════════════════════════════════════════════${NC}"
echo ""

if [ "$CONSOLE_SUCCESS" = true ] || [ "$GUI_SUCCESS" = true ]; then
    read -p "Would you like to run GuardME now? (y/n): " run_now
    
    if [[ "$run_now" =~ ^[Yy]$ ]]; then
        echo ""
        if [ "$CONSOLE_SUCCESS" = true ] && [ "$GUI_SUCCESS" = true ]; then
            echo -e "Which version would you like to run?"
            echo -e "  ${GREEN}1)${NC} Console Version"
            echo -e "  ${GREEN}2)${NC} GUI Version"
            read -p "Enter choice [1-2]: " version_choice
            
            if [ "$version_choice" == "1" ]; then
                echo -e "${CYAN}Launching Console Version...${NC}"
                echo ""
                ./build/guardme_console
            elif [ "$version_choice" == "2" ]; then
                echo -e "${CYAN}Launching GUI Version...${NC}"
                echo ""
                ./build/GuardME
            else
                echo -e "${YELLOW}Invalid choice. Exiting.${NC}"
            fi
        elif [ "$CONSOLE_SUCCESS" = true ]; then
            echo -e "${CYAN}Launching Console Version...${NC}"
            echo ""
            ./build/guardme_console
        elif [ "$GUI_SUCCESS" = true ]; then
            echo -e "${CYAN}Launching GUI Version...${NC}"
            echo ""
            ./build/GuardME
        fi
    else
        echo -e "${GREEN}Setup complete!${NC} Run the application when you're ready."
    fi
fi
