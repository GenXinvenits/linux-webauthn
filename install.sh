#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Linux WebAuthn - Production Installer
#
# Supported operations:
#
#   ./install.sh
#   ./install.sh install
#   ./install.sh repair
#   ./install.sh uninstall
#   ./install.sh status
#
# Production prefix:
#   /usr/local
#
# Installed components currently belonging to this project:
#   /usr/local/bin/linux-webauthn
#   /usr/local/share/dbus-1/services/org.linux.WebAuthn.service
#   /usr/local/lib/udev/rules.d/70-linux-webauthn.rules
# ============================================================

PROJECT_NAME="linux-webauthn"
PREFIX="/usr/local"
BUILD_DIR="build"

BIN_FILE="${PREFIX}/bin/linux-webauthn"
DBUS_SERVICE="${PREFIX}/share/dbus-1/services/org.linux.WebAuthn.service"
UDEV_RULE="${PREFIX}/lib/udev/rules.d/70-linux-webauthn.rules"

INSTALL_FILES=(
    "$BIN_FILE"
    "$DBUS_SERVICE"
    "$UDEV_RULE"
)

# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------

if [[ -t 1 ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    BOLD=''
    RESET=''
fi

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

info()
{
    echo -e "${BLUE}[INFO]${RESET} $*"
}

success()
{
    echo -e "${GREEN}[ OK ]${RESET} $*"
}

warning()
{
    echo -e "${YELLOW}[WARN]${RESET} $*"
}

error()
{
    echo -e "${RED}[ERROR]${RESET} $*" >&2
}

die()
{
    error "$*"
    exit 1
}

run_root()
{
    if [[ "${EUID}" -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

require_root()
{
    if [[ "${EUID}" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
        die "This operation requires root privileges and sudo is not available."
    fi
}

# ------------------------------------------------------------
# Project checks
# ------------------------------------------------------------

check_source_tree()
{
    [[ -f "meson.build" ]] ||
        die "meson.build was not found.

Run this script from the linux-webauthn source directory."

    [[ -d "data" ]] ||
        warning "data/ directory was not found."

    command -v meson >/dev/null 2>&1 ||
        die "Meson is not installed."

    command -v ninja >/dev/null 2>&1 ||
        die "Ninja is not installed."
}

# ------------------------------------------------------------
# Installation state
# ------------------------------------------------------------

count_installed_files()
{
    local count=0
    local file

    for file in "${INSTALL_FILES[@]}"; do
        if [[ -e "$file" ]]; then
            ((count+=1))
        fi
    done

    echo "$count"
}

is_fully_installed()
{
    [[ "$(count_installed_files)" -eq "${#INSTALL_FILES[@]}" ]]
}

is_partially_installed()
{
    local count
    count="$(count_installed_files)"

    [[ "$count" -gt 0 && "$count" -lt "${#INSTALL_FILES[@]}" ]]
}

is_not_installed()
{
    [[ "$(count_installed_files)" -eq 0 ]]
}

# ------------------------------------------------------------
# Status
# ------------------------------------------------------------

show_status()
{
    echo
    echo -e "${BOLD}Linux WebAuthn installation status${RESET}"
    echo "==================================="
    echo
    echo "Prefix: $PREFIX"
    echo

    local installed=0
    local missing=0
    local file

    for file in "${INSTALL_FILES[@]}"; do
        if [[ -e "$file" ]]; then
            echo -e "  ${GREEN}[installed]${RESET} $file"
            ((installed+=1))
        else
            echo -e "  ${RED}[missing]${RESET}   $file"
            ((missing+=1))
        fi
    done

    echo

    if [[ "$installed" -eq "${#INSTALL_FILES[@]}" ]]; then
        echo -e "Status: ${GREEN}FULLY INSTALLED${RESET}"
    elif [[ "$installed" -gt 0 ]]; then
        echo -e "Status: ${YELLOW}PARTIALLY INSTALLED${RESET}"
    else
        echo -e "Status: ${CYAN}NOT INSTALLED${RESET}"
    fi

    echo

    if [[ -d "$BUILD_DIR" ]]; then
        echo "Build directory: present"
    else
        echo "Build directory: absent"
    fi

    echo
}

# ------------------------------------------------------------
# udev
# ------------------------------------------------------------

reload_udev()
{
    info "Reloading udev rules..."

    run_root udevadm control --reload-rules

    info "Triggering udev..."

    run_root udevadm trigger --subsystem-match=misc

    success "udev rules reloaded."
}

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

configure_build()
{
    info "Configuring Meson build..."

    if [[ -d "$BUILD_DIR" ]]; then
        info "Existing build directory detected."

        meson setup "$BUILD_DIR" \
            --reconfigure \
            -Dprefix="$PREFIX"
    else
        meson setup "$BUILD_DIR" \
            -Dprefix="$PREFIX"
    fi

    success "Meson configuration completed."
}

build_project()
{
    info "Building ${PROJECT_NAME}..."

    meson compile -C "$BUILD_DIR"

    success "Build completed."
}

# ------------------------------------------------------------
# Installation
# ------------------------------------------------------------

perform_install()
{
    require_root
    check_source_tree

    echo
    echo -e "${BOLD}Installing Linux WebAuthn${RESET}"
    echo "========================"
    echo

    info "Installation prefix: $PREFIX"

    configure_build
    build_project

    info "Installing system files..."

    run_root meson install -C "$BUILD_DIR"

    success "Files installed."

    reload_udev

    echo
    echo -e "${GREEN}${BOLD}Linux WebAuthn installation completed successfully.${RESET}"
    echo

    show_status
}

# ------------------------------------------------------------
# Repair
# ------------------------------------------------------------

perform_repair()
{
    require_root
    check_source_tree

    echo
    echo -e "${BOLD}Repairing Linux WebAuthn installation${RESET}"
    echo "======================================"
    echo

    warning "The existing installation will be rebuilt and reinstalled."
    echo

    configure_build
    build_project

    info "Reinstalling project files..."

    run_root meson install -C "$BUILD_DIR"

    success "Project files reinstalled."

    reload_udev

    echo
    echo -e "${GREEN}${BOLD}Linux WebAuthn repair completed successfully.${RESET}"
    echo

    show_status
}

# ------------------------------------------------------------
# Remove a single file safely
# ------------------------------------------------------------

remove_file()
{
    local file="$1"

    if [[ -e "$file" || -L "$file" ]]; then
        info "Removing: $file"
        run_root rm -f -- "$file"
        success "Removed."
    else
        info "Already absent: $file"
    fi
}

# ------------------------------------------------------------
# Uninstall
# ------------------------------------------------------------

perform_uninstall()
{
    require_root

    echo
    echo -e "${BOLD}Uninstalling Linux WebAuthn${RESET}"
    echo "==========================="
    echo

    warning "The following project files will be removed:"
    echo

    local file

    for file in "${INSTALL_FILES[@]}"; do
        echo "  $file"
    done

    echo

    read -r -p "Continue with uninstall? [y/N]: " answer

    case "$answer" in
        y|Y|yes|YES)
            ;;
        *)
            echo "Uninstall cancelled."
            return 0
            ;;
    esac

    echo

    for file in "${INSTALL_FILES[@]}"; do
        remove_file "$file"
    done

    # Remove empty project-specific directories only.
    #
    # Never recursively remove /usr/local itself or shared
    # directories containing unrelated software.
    info "Cleaning empty project directories..."

    run_root rmdir \
        "${PREFIX}/lib/udev/rules.d" \
        2>/dev/null || true

    run_root rmdir \
        "${PREFIX}/share/dbus-1/services" \
        2>/dev/null || true

    run_root rmdir \
        "${PREFIX}/share/dbus-1" \
        2>/dev/null || true

    reload_udev

    echo
    echo -e "${GREEN}${BOLD}Linux WebAuthn has been uninstalled.${RESET}"
    echo

    show_status
}

# ------------------------------------------------------------
# Existing installation menu
# ------------------------------------------------------------

existing_installation_menu()
{
    local count
    count="$(count_installed_files)"

    echo
    echo -e "${BOLD}Existing Linux WebAuthn installation detected.${RESET}"
    echo
    echo "Installed components: $count / ${#INSTALL_FILES[@]}"
    echo

    show_status

    echo "What would you like to do?"
    echo
    echo "  1) Repair installation"
    echo "  2) Uninstall"
    echo "  3) Cancel"
    echo

    local choice

    read -r -p "Select [1-3]: " choice

    case "$choice" in
        1)
            perform_repair
            ;;
        2)
            perform_uninstall
            ;;
        3)
            echo "Cancelled."
            ;;
        *)
            error "Invalid selection."
            exit 1
            ;;
    esac
}

# ------------------------------------------------------------
# Install dispatcher
# ------------------------------------------------------------

install_or_repair()
{
    if is_fully_installed || is_partially_installed; then
        existing_installation_menu
    else
        perform_install
    fi
}

# ------------------------------------------------------------
# Command line handling
# ------------------------------------------------------------

usage()
{
    cat <<EOF

Linux WebAuthn production installer

Usage:
    ./install.sh
    ./install.sh install
    ./install.sh repair
    ./install.sh uninstall
    ./install.sh status
    ./install.sh help

Commands:

    install
        Install Linux WebAuthn.
        If an installation already exists, show the
        repair/uninstall menu instead.

    repair
        Rebuild and reinstall the current source tree.

    uninstall
        Remove the files installed by Linux WebAuthn.

    status
        Show the current installation state.

    help
        Show this help.

With no command:
    Automatically detect the installation state.

EOF
}

main()
{
    case "${1:-}" in

        "")
            install_or_repair
            ;;

        install)
            install_or_repair
            ;;

        repair)
            perform_repair
            ;;

        uninstall)
            perform_uninstall
            ;;

        status)
            show_status
            ;;

        help|-h|--help)
            usage
            ;;

        *)
            error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

main "$@"
