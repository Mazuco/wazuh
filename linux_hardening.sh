#!/usr/bin/env bash
set -e

# ==========================================
# 0. OS Detection & Variables Setup
# ==========================================
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID=$ID
    OS_ID_LIKE=$ID_LIKE
else
    echo "Erro: /etc/os-release não encontrado. Sistema não suportado."
    exit 1
fi

if [[ "$OS_ID" == "ubuntu" || "$OS_ID" == "debian" || "$OS_ID_LIKE" == *"debian"* ]]; then
    OS_FAMILY="debian"
    ADMIN_GROUP="sudo"
    TIME_SVC="systemd-timesyncd"
    CUPS_PKGS="cups cups-browsed cups-filters"
    PWQUALITY_PKG="libpam-pwquality"
    AUDIT_PKGS="auditd audispd-plugins"
    ERROR_RPT_SVC="apport.service"
elif [[ "$OS_ID" == "rhel" || "$OS_ID" == "centos" || "$OS_ID" == "almalinux" || "$OS_ID" == "rocky" || "$OS_ID_LIKE" == *"rhel"* || "$OS_ID_LIKE" == *"fedora"* ]]; then
    OS_FAMILY="rhel"
    ADMIN_GROUP="wheel"
    TIME_SVC="chronyd"
    CUPS_PKGS="cups"
    PWQUALITY_PKG="libpwquality"
    AUDIT_PKGS="audit"
    ERROR_RPT_SVC="abrtd.service"
else
    echo "Erro: Família de SO não suportada ($OS_ID)."
    exit 1
fi

echo "Detectado sistema da família: $OS_FAMILY ($OS_ID)"

# Helper functions for package management
install_pkg() {
    if [[ "$OS_FAMILY" == "debian" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"
    else
        dnf install -y "$@"
    fi
}

remove_pkg() {
    if [[ "$OS_FAMILY" == "debian" ]]; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y "$@" || true
    else
        dnf remove -y "$@" || true
    fi
}

############################################
# 35517 Ensure noexec on /dev/shm
fstab_file="/etc/fstab"
shm_entry="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"

if grep -q "^tmpfs /dev/shm" "$fstab_file"; then
    sed -i "s|^tmpfs /dev/shm.*|$shm_entry|" "$fstab_file"
else
    echo "$shm_entry" >> "$fstab_file"
fi
mount -o remount,noexec /dev/shm || true
systemctl daemon-reload

############################################
# 35545 Disable Automatic Error Reporting
systemctl disable "$ERROR_RPT_SVC" --now || true

if [[ "$OS_FAMILY" == "debian" ]] && [ -f /etc/default/apport ]; then
    sed -i 's/enabled=1/enabled=0/' /etc/default/apport || true
elif [[ "$OS_FAMILY" == "rhel" ]] && [ -f /etc/abrt/abrt-action-save-package-data.conf ]; then
    sed -i 's/OpenGPGCheck = yes/OpenGPGCheck = no/' /etc/abrt/abrt-action-save-package-data.conf || true
fi

############################################
# 35547 & 35548 Local and Remote login banners
banner_msg="Authorized users only. All activities are monitored."
grep -qxF "$banner_msg" /etc/issue || echo "$banner_msg" > /etc/issue
grep -qxF "$banner_msg" /etc/issue.net || echo "$banner_msg" > /etc/issue.net

############################################
# 35553 GDM login banner
if [[ "$OS_FAMILY" == "debian" ]] && dpkg -s gdm3 >/dev/null 2>&1; then
    gdm_file="/etc/gdm3/greeter.dconf-defaults"
    grep -Eq '^\s*\[org/gnome/login-screen\]' "$gdm_file" 2>/dev/null || echo "[org/gnome/login-screen]" >> "$gdm_file"

    set_gdm_param() {
        local key="$1"
        local value="$2"
        if grep -Eq "^\s*#?\s*${key}\s*=" "$gdm_file"; then
            sed -i "s|^\s*#\?\s*${key}\s*=.*|${key}=${value}|" "$gdm_file"
        else
            sed -i "/^\[org\/gnome\/login-screen\]/a ${key}=${value}" "$gdm_file"
        fi
    }
    set_gdm_param banner-message-enable true
    set_gdm_param banner-message-text "'$banner_msg'"
    dconf update || true

elif [[ "$OS_FAMILY" == "rhel" ]] && rpm -q gdm >/dev/null 2>&1; then
    mkdir -p /etc/dconf/profile
    echo -e "user-profile\nfile-db:/usr/share/authconfig/dconf\nsystem-db:gdm" > /etc/dconf/profile/gdm
    mkdir -p /etc/dconf/db/gdm.d
    cat << EOF > /etc/dconf/db/gdm.d/01-banner-message
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized users only. All activities are monitored.'
EOF
    dconf update || true
fi

############################################
# 35562 Disable avahi
for svc in avahi-daemon.socket avahi-daemon.service; do
    systemctl stop $svc || true
    systemctl kill $svc || true
    systemctl disable $svc || true
    systemctl mask $svc || true
done

############################################
# 35571 Disable print services
for svc in cups.socket cups.service; do
    systemctl stop $svc || true
    systemctl mask $svc || true
done
remove_pkg $CUPS_PKGS

############################################
# 35588 Configure Time Synchronization
if [[ "$OS_FAMILY" == "debian" ]]; then
    timesync_file="/etc/systemd/timesyncd.conf"
    if grep -q "^#NTP=" "$timesync_file"; then
        sed -i 's/^#NTP=.*/NTP=pool.ntp.org/' "$timesync_file"
    elif ! grep -q "^NTP=" "$timesync_file"; then
        echo "NTP=pool.ntp.org" >> "$timesync_file"
    fi
    systemctl restart systemd-timesyncd || true
else
    chrony_file="/etc/chrony.conf"
    if [ -f "$chrony_file" ]; then
        if ! grep -q "^server pool.ntp.org" "$chrony_file" && ! grep -q "^pool pool.ntp.org" "$chrony_file"; then
            echo "pool pool.ntp.org iburst" >> "$chrony_file"
        fi
        systemctl enable chronyd --now || true
        systemctl restart chronyd || true
    fi
fi

############################################
# 35594-35599 Cron permissions
for file in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    if [ -e "$file" ]; then
        chown root:root "$file"
        chmod og-rwx "$file"
    fi
done

############################################
# 35609-35616 Network sysctl hardening
CONFIG_FILE="/etc/sysctl.d/99-hardening.conf"
sysctl_settings=(
    "net.ipv4.conf.all.send_redirects=0"
    "net.ipv4.conf.all.accept_redirects=0"
    "net.ipv4.conf.all.secure_redirects=0"
    "net.ipv4.conf.all.accept_source_route=0"
    "net.ipv4.conf.all.rp_filter=1"
    "net.ipv4.conf.all.log_martians=1"
    "net.ipv4.conf.default.send_redirects=0"
    "net.ipv4.conf.default.accept_redirects=0"
    "net.ipv4.conf.default.secure_redirects=0"
    "net.ipv4.conf.default.accept_source_route=0"
    "net.ipv4.conf.default.rp_filter=1"
    "net.ipv4.conf.default.log_martians=1"
    "net.ipv6.conf.all.accept_redirects=0"
    "net.ipv6.conf.default.accept_redirects=0"
)

for setting in "${sysctl_settings[@]}"; do
    key="${setting%%=*}"
    grep -q "^$key" "$CONFIG_FILE" 2>/dev/null || echo "$setting" >> "$CONFIG_FILE"
done
sysctl --system >/dev/null

############################################
# 35664 Ensure sudo log file
if ! grep -Eq '^\s*Defaults\s+logfile=' /etc/sudoers; then
    echo 'Defaults logfile="/var/log/sudo.log"' | EDITOR='tee -a' visudo
else
    sed -i 's|^\s*Defaults\s\+logfile=.*|Defaults logfile="/var/log/sudo.log"|' /etc/sudoers
    visudo -c
fi

############################################
# 35668 Restrict su command
if ! grep -Eq "^\s*auth\s+required\s+pam_wheel\.so.*group=$ADMIN_GROUP" /etc/pam.d/su; then
    sed -i "/^auth/a auth required pam_wheel.so use_uid group=$ADMIN_GROUP" /etc/pam.d/su
fi

############################################
# 35676-35683 Password policies (PAM)
install_pkg $PWQUALITY_PKG

set_config() {
    local key="$1"
    local value="$2"
    local file="$3"
    if [ ! -f "$file" ]; then return; fi
    if grep -Eq "^\s*${key}\s*=" "$file"; then
        sed -i "s|^\s*#\?\s*${key}\s*=.*|${key} = ${value}|" "$file"
    else
        echo "${key} = ${value}" >> "$file"
    fi
}

pwquality_conf="/etc/security/pwquality.conf"
set_config difok 2 "$pwquality_conf"
set_config minlen 14 "$pwquality_conf"
set_config minclass 4 "$pwquality_conf"
set_config maxrepeat 3 "$pwquality_conf"
set_config maxsequence 3 "$pwquality_conf"

faillock_conf="/etc/security/faillock.conf"
if [ -f "$faillock_conf" ]; then
    set_config deny 5 "$faillock_conf"
    set_config unlock_time 900 "$faillock_conf"
    set_config root_unlock_time 60 "$faillock_conf"
fi

############################################
# 35694-35698 Password aging
set_login_def() {
    local key="$1"
    local value="$2"
    local file="/etc/login.defs"
    if grep -Eq "^\s*#?\s*${key}\b" "$file"; then
        sed -i "s|^\s*#\?\s*${key}.*|${key} ${value}|" "$file"
    else
        echo "${key} ${value}" >> "$file"
    fi
}

set_login_def PASS_MAX_DAYS 90
set_login_def PASS_MIN_DAYS 1
set_login_def PASS_WARN_AGE 7

for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" && $1 != "nfsnobody" {print $1}' /etc/passwd); do
    chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 "$user" || true
done
chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 root || true

############################################
# 35723 auditd installed
install_pkg $AUDIT_PKGS

if [ -f /etc/audit/auditd.conf ]; then
    sed -i 's/^priority_boost\s*=.*/priority_boost = 0/' /etc/audit/auditd.conf
fi

if systemd-detect-virt -c -q; then
    echo "Ambiente de container detectado. O auditd será instalado mas o serviço não será ativado."
    systemctl disable auditd || true
else
    systemctl enable auditd --now || true
fi

############################################
# Finish
mkdir -p /var/ossec/logs/
echo "$(date '+%Y-%m-%d %H:%M:%S') Hardening complete on $OS_FAMILY ($OS_ID)." >> /var/ossec/logs/ossec.log
echo "Hardening finalizado com sucesso!"