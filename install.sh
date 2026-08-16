#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# Linux WebAuthn - Production Install / Repair / Uninstall
# ============================================================

PROJECT_NAME="linux-webauthn"

PREFIX="/usr/local"
BUILD_DIR="build"

# ------------------------------------------------------------
# Installed files
# ------------------------------------------------------------

BIN_FILE="${PREFIX}/bin/linux-webauthn"

UDEV_RULE="${PREFIX}/lib/udev/rules.d/70-linux-webauthn.rules"

USER_SYSTEMD_DIR="${PREFIX}/lib/systemd/user"
USER_SYSTEMD_SERVICE="${USER_SYSTEMD_DIR}/linux-webauthn.service"

USER_SYSTEMD_WANTS_DIR="${USER_SYSTEMD_DIR}/default.target.wants"
USER_SYSTEMD_WANTS_LINK="${USER_SYSTEMD_WANTS_DIR}/linux-webauthn.service"

DBUS_SERVICE="${PREFIX}/share/dbus-1/services/org.linux.WebAuthn.service"

SERVICE_NAME="linux-webauthn.service"


# ------------------------------------------------------------
# Explicit project-owned production files
# ------------------------------------------------------------

INSTALL_FILES=(
    "$BIN_FILE"
    "$UDEV_RULE"
    "$USER_SYSTEMD_SERVICE"
    "$USER_SYSTEMD_WANTS_LINK"
    "$DBUS_SERVICE"
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
# Output helpers
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


# ------------------------------------------------------------
# Root helper
# ------------------------------------------------------------

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
    if [[ "${EUID}" -ne 0 ]]; then

        command -v sudo >/dev/null 2>&1 ||
            die "sudo is required for this operation."

        sudo -v ||
            die "Unable to obtain root privileges."

    fi
}


# ------------------------------------------------------------
# Determine target user
# ------------------------------------------------------------

get_target_user()
{
    # Normal user execution
    if [[ "${EUID}" -ne 0 ]]; then
        echo "${USER}"
        return
    fi


    # sudo ./install.sh
    if [[ -n "${SUDO_USER:-}" &&
          "${SUDO_USER}" != "root" ]]; then

        echo "${SUDO_USER}"
        return

    fi


    # Direct root execution.
    if command -v loginctl >/dev/null 2>&1; then

        local uid

        uid="$(
            loginctl list-users --no-legend 2>/dev/null |
            awk '$2 != "root" {print $1; exit}' ||
            true
        )"

        if [[ -n "$uid" ]]; then

            id -nu "$uid" 2>/dev/null || true
            return

        fi

    fi


    echo ""
}


TARGET_USER="$(get_target_user || true)"


# ------------------------------------------------------------
# Source tree validation
# ------------------------------------------------------------

check_source_tree()
{
    [[ -f "meson.build" ]] ||
        die "meson.build was not found.

Run this script from the linux-webauthn source directory."

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

        if [[ -e "$file" || -L "$file" ]]; then
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

    [[ "$count" -gt 0 &&
       "$count" -lt "${#INSTALL_FILES[@]}" ]]
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

    echo "Project : $PROJECT_NAME"
    echo "Prefix  : $PREFIX"
    echo

    local installed=0
    local missing=0
    local file

    for file in "${INSTALL_FILES[@]}"; do

        if [[ -e "$file" || -L "$file" ]]; then

            echo -e \
                "  ${GREEN}[installed]${RESET} $file"

            ((installed+=1))

        else

            echo -e \
                "  ${RED}[missing]${RESET}   $file"

            ((missing+=1))

        fi

    done

    echo

    if [[ "$installed" -eq "${#INSTALL_FILES[@]}" ]]; then

        echo -e \
            "Installation: ${GREEN}FULLY INSTALLED${RESET}"

    elif [[ "$installed" -gt 0 ]]; then

        echo -e \
            "Installation: ${YELLOW}PARTIALLY INSTALLED${RESET}"

    else

        echo -e \
            "Installation: ${CYAN}NOT INSTALLED${RESET}"

    fi

    echo

    if [[ -d "$BUILD_DIR" ]]; then
        echo "Build tree: present"
    else
        echo "Build tree: absent"
    fi

    echo

    if [[ -n "$TARGET_USER" ]]; then

        echo "Target user: $TARGET_USER"

        if id "$TARGET_USER" >/dev/null 2>&1; then

            local uid
            uid="$(id -u "$TARGET_USER")"

            if [[ -S "/run/user/${uid}/bus" ]]; then

                if runuser -u "$TARGET_USER" -- \
                    env \
                    XDG_RUNTIME_DIR="/run/user/${uid}" \
                    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
                    systemctl --user is-enabled \
                    "$SERVICE_NAME" \
                    >/dev/null 2>&1
                then

                    echo -e \
                        "User service enabled: ${GREEN}yes${RESET}"

                else

                    echo -e \
                        "User service enabled: ${YELLOW}no${RESET}"

                fi


                if runuser -u "$TARGET_USER" -- \
                    env \
                    XDG_RUNTIME_DIR="/run/user/${uid}" \
                    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
                    systemctl --user is-active \
                    "$SERVICE_NAME" \
                    >/dev/null 2>&1
                then

                    echo -e \
                        "User service active:  ${GREEN}yes${RESET}"

                else

                    echo -e \
                        "User service active:  ${YELLOW}no${RESET}"

                fi

            else

                echo "User systemd session: not available"

            fi

        fi

    fi

    echo
}


# ------------------------------------------------------------
# Reload udev
# ------------------------------------------------------------

reload_udev()
{
    info "Reloading udev rules..."

    run_root udevadm control --reload-rules

    info "Triggering udev..."

    run_root udevadm trigger

    success "udev rules reloaded."
}


# ------------------------------------------------------------
# Reload systemd user daemon
# ------------------------------------------------------------

refresh_user_systemd()
{
    local user="${TARGET_USER:-}"

    if [[ -z "$user" ]]; then

        warning "Could not determine target user."

        warning "systemd user daemon was not reloaded."

        return 0

    fi


    if ! id "$user" >/dev/null 2>&1; then

        warning "User '$user' does not exist."

        return 0

    fi


    local uid

    uid="$(id -u "$user")"


    if [[ ! -S "/run/user/${uid}/bus" ]]; then

        warning \
            "No active systemd user session for '$user'."

        warning \
            "User daemon-reload could not be performed."

        return 0

    fi


    info "Reloading systemd user daemon for '$user'..."


    if runuser -u "$user" -- \
        env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user daemon-reload
    then

        success "systemd user daemon reloaded."

    else

        warning "systemd user daemon-reload failed."

    fi
}


# ------------------------------------------------------------
# Stop user service
# ------------------------------------------------------------

stop_user_service()
{
    local user="${TARGET_USER:-}"

    [[ -n "$user" ]] || return 0

    id "$user" >/dev/null 2>&1 || return 0


    local uid

    uid="$(id -u "$user")"


    [[ -S "/run/user/${uid}/bus" ]] || return 0


    info "Stopping $SERVICE_NAME..."


    runuser -u "$user" -- \
        env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user stop "$SERVICE_NAME" \
        >/dev/null 2>&1 || true


    success "User service stopped."
}


# ------------------------------------------------------------
# Disable user service
# ------------------------------------------------------------

disable_user_service()
{
    local user="${TARGET_USER:-}"

    [[ -n "$user" ]] || return 0

    id "$user" >/dev/null 2>&1 || return 0


    local uid

    uid="$(id -u "$user")"


    [[ -S "/run/user/${uid}/bus" ]] || return 0


    info "Disabling $SERVICE_NAME..."


    runuser -u "$user" -- \
        env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user disable "$SERVICE_NAME" \
        >/dev/null 2>&1 || true


    success "User service disabled."
}


# ------------------------------------------------------------
# Explicitly remove systemd wants symlink
# ------------------------------------------------------------

remove_user_systemd_link()
{
    if [[ -L "$USER_SYSTEMD_WANTS_LINK" ||
          -e "$USER_SYSTEMD_WANTS_LINK" ]]; then

        info "Removing systemd user service symlink:"

        echo "  $USER_SYSTEMD_WANTS_LINK"


        run_root rm -f -- "$USER_SYSTEMD_WANTS_LINK"


        success "Systemd user service symlink removed."

    else

        info "Systemd user service symlink already absent."

    fi
}


# ------------------------------------------------------------
# Enable/start user service
# ------------------------------------------------------------

enable_user_service()
{
    local user="${TARGET_USER:-}"


    if [[ -z "$user" ]]; then

        warning "Target user could not be determined."

        return 0

    fi


    id "$user" >/dev/null 2>&1 ||
        return 0


    local uid

    uid="$(id -u "$user")"


    if [[ ! -S "/run/user/${uid}/bus" ]]; then

        warning \
            "No active user systemd session for '$user'."

        warning \
            "Service installed but not started."

        echo

        echo "After logging in, run:"

        echo
        echo "    systemctl --user daemon-reload"
        echo "    systemctl --user enable --now linux-webauthn.service"
        echo

        return 0

    fi


    info "Enabling $SERVICE_NAME..."


    runuser -u "$user" -- \
        env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user enable "$SERVICE_NAME" \
        >/dev/null 2>&1 || {

            warning "Could not enable user service."

            return 0
        }


    info "Starting $SERVICE_NAME..."


    runuser -u "$user" -- \
        env \
        XDG_RUNTIME_DIR="/run/user/${uid}" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user start "$SERVICE_NAME" \
        >/dev/null 2>&1 || {

            warning "Could not start user service."

            return 0
        }


    success "User service enabled and started."
}


# ------------------------------------------------------------
# Configure Meson
# ------------------------------------------------------------

configure_build()
{
    info "Configuring Meson build..."


    if [[ -d "$BUILD_DIR" ]]; then

        meson setup \
            "$BUILD_DIR" \
            --reconfigure \
            -Dprefix="$PREFIX"

    else

        meson setup \
            "$BUILD_DIR" \
            -Dprefix="$PREFIX"

    fi


    success "Meson configuration completed."
}


# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

build_project()
{
    info "Building $PROJECT_NAME..."

    meson compile -C "$BUILD_DIR"

    success "Build completed."
}


# ------------------------------------------------------------
# Remove explicit production files
# ------------------------------------------------------------

remove_explicit_files()
{
    local file


    for file in "${INSTALL_FILES[@]}"; do

        if [[ -e "$file" || -L "$file" ]]; then

            info "Removing: $file"

            run_root rm -f -- "$file"

            success "Removed."

        else

            info "Already absent: $file"

        fi

    done
}


# ------------------------------------------------------------
# Find additional project-specific artifacts
#
# Only paths containing "linux-webauthn" are considered.
# Nothing outside these relevant /usr/local trees is touched.
# ------------------------------------------------------------

find_additional_artifacts()
{
    local path


    # /usr/local/bin

    if [[ -d "${PREFIX}/bin" ]]; then

        find "${PREFIX}/bin" \
            -maxdepth 1 \
            -iname '*linux-webauthn*' \
            -print 2>/dev/null |
        while IFS= read -r path; do

            [[ "$path" == "$BIN_FILE" ]] && continue

            echo "$path"

        done

    fi


    # /usr/local/lib/systemd/user

    if [[ -d "$USER_SYSTEMD_DIR" ]]; then

        find "$USER_SYSTEMD_DIR" \
            -maxdepth 3 \
            -iname '*linux-webauthn*' \
            -print 2>/dev/null |
        while IFS= read -r path; do

            [[ "$path" == "$USER_SYSTEMD_SERVICE" ]] && continue
            [[ "$path" == "$USER_SYSTEMD_WANTS_LINK" ]] && continue

            echo "$path"

        done

    fi


    # /usr/local/lib/udev/rules.d

    if [[ -d "${PREFIX}/lib/udev/rules.d" ]]; then

        find "${PREFIX}/lib/udev/rules.d" \
            -maxdepth 1 \
            -iname '*linux-webauthn*' \
            -print 2>/dev/null |
        while IFS= read -r path; do

            [[ "$path" == "$UDEV_RULE" ]] && continue

            echo "$path"

        done

    fi


    # /usr/local/share

    if [[ -d "${PREFIX}/share" ]]; then

        find "${PREFIX}/share" \
            -maxdepth 8 \
            -iname '*linux-webauthn*' \
            -print 2>/dev/null |
        while IFS= read -r path; do

            [[ "$path" == "$DBUS_SERVICE" ]] && continue

            echo "$path"

        done

    fi
}


# ------------------------------------------------------------
# Remove additional artifacts
# ------------------------------------------------------------

remove_additional_artifacts()
{
    local artifacts=()
    local path


    while IFS= read -r path; do

        [[ -n "$path" ]] || continue

        artifacts+=("$path")

    done < <(find_additional_artifacts)


    if [[ "${#artifacts[@]}" -eq 0 ]]; then

        info "No additional linux-webauthn artifacts found."

        return 0

    fi


    echo

    warning "Additional linux-webauthn artifacts found:"

    for path in "${artifacts[@]}"; do
        echo "  $path"
    done

    echo


    for path in "${artifacts[@]}"; do

        if [[ -d "$path" ]]; then

            info "Removing directory: $path"

            run_root rm -rf -- "$path"

        else

            info "Removing: $path"

            run_root rm -f -- "$path"

        fi

    done


    success "Additional project artifacts removed."
}


# ------------------------------------------------------------
# Clean empty directories
# ------------------------------------------------------------

clean_empty_directories()
{
    info "Cleaning empty project directories..."


    local dirs=(
        "$USER_SYSTEMD_WANTS_DIR"
        "$USER_SYSTEMD_DIR"
        "${PREFIX}/lib/systemd"
        "${PREFIX}/lib/udev/rules.d"
        "${PREFIX}/lib/udev"
        "${PREFIX}/share/dbus-1/services"
        "${PREFIX}/share/dbus-1"
    )


    local dir


    for dir in "${dirs[@]}"; do

        [[ -d "$dir" ]] || continue

        run_root rmdir "$dir" 2>/dev/null || true

    done


    success "Empty directories cleaned."
}


# ------------------------------------------------------------
# Install
# ------------------------------------------------------------

perform_install()
{
    require_root
    check_source_tree


    echo
    echo -e "${BOLD}Installing Linux WebAuthn${RESET}"
    echo "========================"
    echo


    info "Production prefix: $PREFIX"


    configure_build

    build_project


    # Stop existing service before replacing files.

    if [[ -e "$USER_SYSTEMD_SERVICE" ]]; then
        stop_user_service
    fi


    info "Installing project files..."

    run_root meson install -C "$BUILD_DIR"

    success "Project files installed."


    # systemd must see the new unit.

    refresh_user_systemd


    # Enable and start service.

    enable_user_service


    # Reload udev.

    reload_udev


    echo
    echo -e \
        "${GREEN}${BOLD}Linux WebAuthn installation completed successfully.${RESET}"
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
    echo -e "${BOLD}Repairing Linux WebAuthn${RESET}"
    echo "========================"
    echo


    stop_user_service


    configure_build

    build_project


    info "Reinstalling project files..."

    run_root meson install -C "$BUILD_DIR"

    success "Project files reinstalled."


    refresh_user_systemd


    enable_user_service


    reload_udev


    echo
    echo -e \
        "${GREEN}${BOLD}Linux WebAuthn repair completed successfully.${RESET}"
    echo


    show_status
}


# ------------------------------------------------------------
# Clean uninstall
# ------------------------------------------------------------

perform_uninstall()
{
    require_root


    echo
    echo -e "${BOLD}Linux WebAuthn clean uninstall${RESET}"
    echo "=============================="
    echo


    echo "The following project-owned files will be removed:"
    echo


    for file in "${INSTALL_FILES[@]}"; do
        echo "  $file"
    done


    echo


    read -r -p \
        "Continue with clean uninstall? [y/N]: " answer


    case "$answer" in

        y|Y|yes|YES)
            ;;

        *)
            echo "Uninstall cancelled."
            return 0
            ;;

    esac


    echo


    # --------------------------------------------------------
    # Stop running service.
    # --------------------------------------------------------

    stop_user_service


    # --------------------------------------------------------
    # Disable service.
    # --------------------------------------------------------

    disable_user_service


    # --------------------------------------------------------
    # Explicitly remove enable symlink.
    #
    # This is important because systemctl --user disable
    # cannot always remove it when the user session is absent.
    # --------------------------------------------------------

    remove_user_systemd_link


    # --------------------------------------------------------
    # Remove known production files.
    # --------------------------------------------------------

    remove_explicit_files


    # --------------------------------------------------------
    # Remove any additional project-specific artifacts.
    # --------------------------------------------------------

    remove_additional_artifacts


    # --------------------------------------------------------
    # Refresh systemd after removing the unit.
    # --------------------------------------------------------

    refresh_user_systemd


    # --------------------------------------------------------
    # Refresh udev after removing the rule.
    # --------------------------------------------------------

    reload_udev


    # --------------------------------------------------------
    # Remove empty directories.
    # --------------------------------------------------------

    clean_empty_directories


    echo
    echo -e \
        "${GREEN}${BOLD}Linux WebAuthn clean uninstall completed.${RESET}"
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
    echo -e \
        "${BOLD}Existing Linux WebAuthn installation detected.${RESET}"
    echo


    echo "Installed standard components:"
    echo "  $count / ${#INSTALL_FILES[@]}"
    echo


    show_status


    echo "What would you like to do?"
    echo

    echo "  1) Repair installation"
    echo "  2) Clean uninstall"
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

install_or_manage()
{
    if is_fully_installed || is_partially_installed; then

        existing_installation_menu

    else

        perform_install

    fi
}


# ------------------------------------------------------------
# Usage
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

        If an existing installation is detected,
        show the repair/uninstall menu.


    repair
        Rebuild and reinstall Linux WebAuthn.


    uninstall
        Perform a clean uninstall.

        Stops and disables the user service,
        removes the systemd wants symlink,
        removes installed files,
        searches for additional
        linux-webauthn artifacts,
        reloads systemd,
        reloads udev,
        and cleans empty directories.


    status
        Show installation and service status.


    help
        Show this help.


With no command:

    Automatically detect installation state.

EOF
}


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

main()
{
    case "${1:-}" in

        "")
            install_or_manage
            ;;

        install)
            install_or_manage
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
