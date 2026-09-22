#!/usr/bin/env bash
set -e

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

systemctl disable apport.service --now || true
sed -i 's/enabled=1/enabled=0/' /etc/default/apport || true

############################################
# 35547 Local login banner

banner_msg="Authorized users only. All activities are monitored."
grep -qxF "$banner_msg" /etc/issue || echo "$banner_msg" > /etc/issue

############################################
# 35548 Remote login banner

grep -qxF "$banner_msg" /etc/issue.net || echo "$banner_msg" > /etc/issue.net

############################################
# 35553 GDM login banner

if dpkg -s gdm3 >/dev/null 2>&1; then

gdm_file="/etc/gdm3/greeter.dconf-defaults"

# Ensure section exists
grep -Eq '^\s*\[org/gnome/login-screen\]' "$gdm_file" 2>/dev/null || \
    echo "[org/gnome/login-screen]" >> "$gdm_file"

set_gdm_param() {
    local key="$1"
    local value="$2"

    if grep -Eq "^\s*#?\s*${key}\s*=" "$gdm_file"; then
        # Replace commented OR uncommented line
        sed -i "s|^\s*#\?\s*${key}\s*=.*|${key}=${value}|" "$gdm_file"
    else
        # Add under section
        sed -i "/^\[org\/gnome\/login-screen\]/a ${key}=${value}" "$gdm_file"
    fi
}

# Apply settings
set_gdm_param banner-message-enable true
set_gdm_param banner-message-text "'$banner_msg'"

dconf update

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

pkg="cups cups-browsed cups-filters"

for svc in cups.socket cups.service; do
    systemctl stop $svc || true
    systemctl mask $svc || true
    apt purge $pkg -y || true
done

############################################
# 35588 Configure systemd-timesyncd

timesync_file="/etc/systemd/timesyncd.conf"
if grep -q "^#NTP=" "$timesync_file"; then
    sed -i 's/^#NTP=.*/NTP=pool.ntp.org/' "$timesync_file"
elif ! grep -q "^NTP=" "$timesync_file"; then
    echo "NTP=pool.ntp.org" >> "$timesync_file"
fi
systemctl restart systemd-timesyncd

############################################
# 35594-35599 Cron permissions

for file in /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d; do
    chown root:root "$file"
    chmod og-rwx "$file"
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
     "$CONFIG_FILE" 2>/dev/null || echo "$setting" >> "$CONFIG_FILE"grep -q "^$key"
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
grep -Eq '^\s*auth\s+required\s+pam_wheel\.so.*group=sudo' /etc/pam.d/su || \
    sed -i '/^auth/a auth required pam_wheel.so use_uid group=sudo' /etc/pam.d/su

############################################
# 35676-35683 Password policies (PAM)
apt-get install -y libpam-pwquality

# Set key=value
set_config() {
    local key="$1"
    local value="$2"
    local file="$3"

    if grep -Eq "^\s*${key}\s*=" "$file"; then
        # Replace existing (commented or not)
        sed -i "s|^\s*#\?\s*${key}\s*=.*|${key} = ${value}|" "$file"
    else
        # Add if missing
        echo "${key} = ${value}" >> "$file"
    fi
}

# pwquality.conf settings
pwquality_conf="/etc/security/pwquality.conf"

set_config difok 2 "$pwquality_conf"
set_config minlen 14 "$pwquality_conf"
set_config minclass 4 "$pwquality_conf"
set_config maxrepeat 3 "$pwquality_conf"
set_config maxsequence 3 "$pwquality_conf"


# faillock.conf settings
faillock_conf="/etc/security/faillock.conf"

set_config deny 5 "$faillock_conf"
set_config unlock_time 900 "$faillock_conf"
set_config root_unlock_time 60 "$faillock_conf"

############################################
# 35694-35698 Password aging

# Set login.defs values
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

# Apply for future users
set_login_def PASS_MAX_DAYS 90
set_login_def PASS_MIN_DAYS 1
set_login_def PASS_WARN_AGE 7

# Apply to existing users (/etc/shadow via chage)
# Note - Passwords for users with password age over the setting should be changed first or else the user will be locked out.

for user in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); do
    chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 "$user"
done

# Apply to root
chage --mindays 1 --maxdays 90 --warndays 7 --inactive 45 root


############################################
# 35723 auditd installed
apt-get install -y auditd audispd-plugins

# Disables priority boosting to avoid the "Operation not permitted" error.
sed -i 's/^priority_boost\s*=.*/priority_boost = 0/' /etc/audit/auditd.conf

systemctl enable auditd --now

echo "$(date '+%Y-%m-%d %H:%M:%S') Hardening complete." >> /var/ossec/logs/ossec.log
