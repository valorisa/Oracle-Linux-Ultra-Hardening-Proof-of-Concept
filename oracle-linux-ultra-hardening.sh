#!/bin/bash
# ================================================================
# Oracle Linux 10 — Ultra Hardening v3.0 "Gold" (Enterprise)
# Synthèse définitive — prêt déploiement production
# Auteur  : valorisa — DevSecOps senior
# Cibles  : Serveur SSH + Hôte KVM + Serveur Web
# Usage   : ./oracle-linux-ultra-hardening.sh [--dry-run]
# ================================================================
set -euo pipefail
IFS=$'\n\t'

readonly VERSION="3.0"
readonly LOGFILE="/var/log/hardening-$(date +%Y%m%d).log"
readonly BACKUP_DIR="/var/backup/hardening-$(date +%Y%m%d-%H%M%S)"
readonly DRY_RUN="${1:-}"
ERRORS=0

exec > >(tee -a "$LOGFILE") 2>&1

# ── Fonctions utilitaires ─────────────────────────────────────
log()    { echo "[$(date +%H:%M:%S)] $*"; }
ok()     { echo "  [OK]   $*"; }
warn()   { echo "  [WARN] $*"; }
err()    { echo "  [ERR]  $*"; (( ERRORS++ )) || true; }
sep()    { echo ""; echo "─────────────────────────────────────────────────"; }
is_dry() { [[ "${DRY_RUN}" == "--dry-run" ]]; }

bak() {
    local f="$1"
    [[ -f "$f" ]] || return 0
    mkdir -p "$BACKUP_DIR"
    local dest="${BACKUP_DIR}/$(basename "${f}").$(date +%s).bak"
    cp -a "$f" "$dest"
    log "  Backup : $f → $dest"
}

# Édition idempotente clé=valeur (key = value ou KEY\tvalue)
set_kv() {
    local file="$1" key="$2" val="$3" sep="${4:- = }"
    [[ -f "$file" ]] || { mkdir -p "$(dirname "$file")"; touch "$file"; }
    if grep -qE "^[#[:space:]]*${key}[[:space:]]*[=[:space:]]" "$file" 2>/dev/null; then
        sed -ri "s|^[#[:space:]]*${key}[[:space:]]*[=[:space:]].*|${key}${sep}${val}|" "$file"
    else
        echo "${key}${sep}${val}" >> "$file"
    fi
}

# ── Pré-requis obligatoires ───────────────────────────────────
sep
log "=== Oracle Linux 10 Ultra Hardening v${VERSION} — $(date) ==="

[[ "$EUID" -eq 0 ]] || { echo "FATAL : root requis."; exit 1; }

[[ -f /etc/os-release ]] || { echo "FATAL : /etc/os-release introuvable."; exit 1; }
# shellcheck source=/dev/null
source /etc/os-release
[[ "${ID:-}" == "ol" && "${VERSION_ID%%.*}" == "10" ]] || {
    echo "FATAL : Oracle Linux 10 requis (détecté : ${ID:-?} ${VERSION_ID:-?})."; exit 1
}

is_dry && log "=== MODE DRY-RUN — aucune modification ===" \
       || log "=== MODE APPLY ==="

# ──────────────────────────────────────────────────────────────
# PHASE 0 — Mise à jour + paquets requis
# ──────────────────────────────────────────────────────────────
sep
log "Phase 0 : Mise à jour et paquets"

PKGS=(
    policycoreutils policycoreutils-python-utils selinux-policy-targeted
    audit audispd-plugins
    firewalld
    openssh-server
    aide
    chrony
    libpwquality
    authselect
)

if ! is_dry; then
    dnf update -y
    dnf install -y "${PKGS[@]}"
    ok "Paquets installés"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 1 — SELinux : enforcing / targeted (strict n'existe pas OL10)
# ──────────────────────────────────────────────────────────────
sep
log "Phase 1 : SELinux enforcing/targeted"
bak /etc/selinux/config

if ! is_dry; then
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/'       /etc/selinux/config
    sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=targeted/' /etc/selinux/config

    CURRENT_MODE=$(getenforce 2>/dev/null || echo "Disabled")
    case "$CURRENT_MODE" in
        Enforcing)
            ok "SELinux déjà en enforcing"
            ;;
        Permissive)
            setenforce 1 && ok "SELinux passé en enforcing (runtime)" \
                          || warn "setenforce 1 a échoué — reboot requis"
            ;;
        Disabled)
            warn "SELinux était Disabled — reboot + relabeling nécessaires"
            touch /.autorelabel
            ;;
    esac

    # Supprimer uniquement les domaines permissifs personnalisés (Customized)
    if command -v semanage &>/dev/null; then
        # Extraire la section "Customized Permissive Types" seulement
        PERM_DOMAINS=$(semanage permissive -l 2>/dev/null \
            | awk '/^Customized Permissive/{p=1;next}/^Policy Permissive/{p=0}
                   p && /[a-z]/{print $1}' || true)
        if [[ -n "$PERM_DOMAINS" ]]; then
            while IFS= read -r domain; do
                [[ -z "$domain" ]] && continue
                semanage permissive -d "$domain" 2>/dev/null && \
                    warn "Domaine permissif supprimé : $domain" || true
            done <<< "$PERM_DOMAINS"
        else
            ok "Aucun domaine permissif personnalisé"
        fi
    fi
    ok "SELinux : enforcing/targeted configuré"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 2 — SSH : drop-in (préserve la config OL10 et crypto-policies)
# ──────────────────────────────────────────────────────────────
sep
log "Phase 2 : Durcissement SSH (drop-in sshd_config.d)"

if ! is_dry; then
    install -d -m 0755 /etc/ssh/sshd_config.d

    # Garde-fou anti-lockout : vérifier existence d'une clé SSH valide
    ADMIN_KEY_FOUND=0
    for home_dir in /root /home/*; do
        if [[ -f "${home_dir}/.ssh/authorized_keys" ]] && \
           grep -qE '^(ssh-|ecdsa-|sk-)' "${home_dir}/.ssh/authorized_keys" 2>/dev/null; then
            ADMIN_KEY_FOUND=1
            break
        fi
    done

    if [[ "$ADMIN_KEY_FOUND" -eq 1 ]]; then
        PWD_AUTH_VAL="no"
        ok "Clé SSH trouvée — PasswordAuthentication désactivée"
    else
        PWD_AUTH_VAL="yes"
        warn "Aucune clé SSH détectée — PasswordAuthentication maintenue (anti-lockout)"
        warn "Ajouter une clé puis réexécuter pour désactiver les mots de passe"
    fi

    # Bannière légale
    cat > /etc/ssh/banner.txt << 'BANNEREOF'
****************************************************************************
* Acces strictement reserve aux utilisateurs autorises.                    *
* Toute connexion non autorisee est enregistree et passible de poursuites. *
****************************************************************************
BANNEREOF

    # Drop-in : complète /etc/ssh/sshd_config, ne le remplace PAS
    # Les algorithmes crypto sont gérés par les crypto-policies OL10
    cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# OL10 Ultra Hardening v${VERSION} — Drop-in SSH
PermitRootLogin no
PasswordAuthentication ${PWD_AUTH_VAL}
PermitEmptyPasswords no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
ChallengeResponseAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
KerberosAuthentication no
GSSAPIAuthentication no
AllowTcpForwarding no
X11Forwarding no
AllowAgentForwarding no
PermitTunnel no
MaxAuthTries 4
MaxSessions 4
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
MaxStartups 10:30:60
SyslogFacility AUTHPRIV
LogLevel VERBOSE
Banner /etc/ssh/banner.txt
EOF

    chmod 0600 /etc/ssh/sshd_config.d/99-hardening.conf

    # Validation OBLIGATOIRE avant restart
    if sshd -t; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
        ok "SSH : drop-in appliqué, service rechargé"
    else
        err "SSH : configuration invalide — drop-in retiré"
        rm -f /etc/ssh/sshd_config.d/99-hardening.conf
    fi
fi

# ──────────────────────────────────────────────────────────────
# PHASE 3 — Sysctl : durcissement kernel + réseau
# ──────────────────────────────────────────────────────────────
sep
log "Phase 3 : Sysctl sécurité"

if ! is_dry; then
    cat > /etc/sysctl.d/99-hardening.conf << 'SYSCTLEOF'
# OL10 Ultra Hardening — Sysctl kernel/réseau

# ── Réseau IPv4 ─────────────────────────────────────────────
net.ipv4.conf.all.rp_filter                = 1
net.ipv4.conf.default.rp_filter            = 1
net.ipv4.conf.all.accept_source_route      = 0
net.ipv4.conf.default.accept_source_route  = 0
net.ipv4.conf.all.accept_redirects         = 0
net.ipv4.conf.default.accept_redirects     = 0
net.ipv4.conf.all.secure_redirects         = 0
net.ipv4.conf.default.secure_redirects     = 0
net.ipv4.conf.all.send_redirects           = 0
net.ipv4.conf.default.send_redirects       = 0
net.ipv4.conf.all.log_martians             = 1
net.ipv4.conf.default.log_martians         = 1
net.ipv4.icmp_echo_ignore_broadcasts       = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies                    = 1
net.ipv4.tcp_timestamps                    = 0
net.ipv4.ip_forward                        = 0

# ── Réseau IPv6 ─────────────────────────────────────────────
net.ipv6.conf.all.accept_redirects         = 0
net.ipv6.conf.default.accept_redirects     = 0
net.ipv6.conf.all.accept_source_route      = 0
net.ipv6.conf.all.accept_ra                = 0
net.ipv6.conf.default.accept_ra            = 0
net.ipv6.conf.all.forwarding               = 0

# ── Kernel ──────────────────────────────────────────────────
kernel.randomize_va_space            = 2
kernel.kptr_restrict                 = 2
kernel.dmesg_restrict                = 1
kernel.perf_event_paranoid           = 3
kernel.yama.ptrace_scope             = 2
kernel.core_uses_pid                 = 1
kernel.sysrq                         = 0
kernel.unprivileged_bpf_disabled     = 1

# ── Système de fichiers ─────────────────────────────────────
fs.suid_dumpable       = 0
fs.protected_hardlinks = 1
fs.protected_symlinks  = 1
SYSCTLEOF

    # Appliquer en signalant les paramètres absents (ne pas échouer)
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        [[ -z "${line// /}" ]] && continue
        param="${line%%=*}"
        param="${param// /}"
        proc_path="/proc/sys/${param//.//}"
        [[ -e "$proc_path" ]] || warn "sysctl non supporté par ce kernel : $param"
    done < /etc/sysctl.d/99-hardening.conf

    sysctl --system &>/dev/null
    ok "Sysctl appliqués et persistants"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 4 — auditd : configuration démon + règles + 32 bits
# ──────────────────────────────────────────────────────────────
sep
log "Phase 4 : auditd (démon + règles CIS)"
bak /etc/audit/auditd.conf

if ! is_dry; then
    systemctl enable --now auditd

    # Tuning auditd.conf : comportement en cas de disque plein (critique prod)
    set_kv /etc/audit/auditd.conf "max_log_file"            "20"
    set_kv /etc/audit/auditd.conf "max_log_file_action"     "keep_logs"
    set_kv /etc/audit/auditd.conf "space_left_action"       "SYSLOG"
    set_kv /etc/audit/auditd.conf "admin_space_left_action" "HALT"
    set_kv /etc/audit/auditd.conf "disk_full_action"        "HALT"
    set_kv /etc/audit/auditd.conf "disk_error_action"       "HALT"

    # Règles audit production
    cat > /etc/audit/rules.d/99-hardening.rules << 'AUDITEOF'
# OL10 Ultra Hardening — Règles audit production v3.0
-D
-b 8192

# Identité et authentification
-w /etc/passwd           -p wa -k identity
-w /etc/shadow           -p wa -k identity
-w /etc/group            -p wa -k identity
-w /etc/gshadow          -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers          -p wa -k sudoers
-w /etc/sudoers.d/       -p wa -k sudoers

# Configuration SSH et SELinux
-w /etc/ssh/sshd_config    -p wa -k ssh-config
-w /etc/ssh/sshd_config.d/ -p wa -k ssh-config
-w /etc/selinux/           -p wa -k selinux-config

# PAM / politique de mots de passe
-w /etc/security/faillock.conf  -p wa -k pam-config
-w /etc/security/pwquality.conf -p wa -k pam-config
-w /etc/login.defs              -p wa -k login-config

# Sessions / connexions
-w /var/log/lastlog  -p wa -k logins
-w /var/run/faillock -p wa -k logins

# Changements d'heure (64 bits)
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Appels système critiques (64 bits)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat        -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -k perm_mod
-a always,exit -F arch=b64 -S open,openat -F exit=-EACCES   -k access-denied
-a always,exit -F arch=b64 -S open,openat -F exit=-EPERM    -k access-denied
-a always,exit -F arch=b64 -S sethostname,setdomainname     -k system-locale
-a always,exit -F arch=b64 -S mount                         -k mounts
-a always,exit -F arch=b64 -S init_module,delete_module     -k modules

# Modules kernel
-w /sbin/insmod   -p x -k modules
-w /sbin/rmmod    -p x -k modules
-w /sbin/modprobe -p x -k modules

# Escalade de privilèges
-w /usr/bin/su   -p x -k priv-escalation
-w /usr/bin/sudo -p x -k priv-escalation

# Infrastructure audit (auto-protection)
-w /etc/audit/    -p wa -k audit-config
-w /sbin/auditctl -p x  -k audit-tools
-w /sbin/auditd   -p x  -k audit-tools
AUDITEOF

    # Règles 32 bits obligatoires sur x86_64
    # Sans elles, un attaquant peut contourner l'audit via les appels système 32 bits
    if [[ "$(uname -m)" == "x86_64" ]]; then
        cat >> /etc/audit/rules.d/99-hardening.rules << 'AUDIT32EOF'

# Règles 32 bits (x86_64 — anti-contournement mode compat)
-a always,exit -F arch=b32 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat        -k perm_mod
-a always,exit -F arch=b32 -S chown,fchown,lchown,fchownat -k perm_mod
-a always,exit -F arch=b32 -S open,openat -F exit=-EACCES   -k access-denied
-a always,exit -F arch=b32 -S open,openat -F exit=-EPERM    -k access-denied
-a always,exit -F arch=b32 -S mount                         -k mounts
-a always,exit -F arch=b32 -S init_module,delete_module     -k modules
AUDIT32EOF
        ok "Règles audit 32 bits ajoutées"
    fi

    # Immutabilité — reboot requis pour toute modification ultérieure
    echo ""        >> /etc/audit/rules.d/99-hardening.rules
    echo "# Règles immuables — reboot requis pour modification" \
                   >> /etc/audit/rules.d/99-hardening.rules
    echo "-e 2"    >> /etc/audit/rules.d/99-hardening.rules

    augenrules --load 2>/dev/null || \
        auditctl -R /etc/audit/rules.d/99-hardening.rules 2>/dev/null || true
    ok "auditd : règles chargées, immuables (-e 2)"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 5 — PAM : pwquality + faillock + login.defs + umask
# ──────────────────────────────────────────────────────────────
sep
log "Phase 5 : PAM, politique de mots de passe"
bak /etc/security/pwquality.conf
bak /etc/security/faillock.conf
bak /etc/login.defs

if ! is_dry; then
    # Politique de complexité des mots de passe
    cat > /etc/security/pwquality.conf << 'PWQEOF'
minlen      = 14
dcredit     = -1
ucredit     = -1
lcredit     = -1
ocredit     = -1
minclass    = 4
maxrepeat   = 3
maxsequence = 3
difok       = 4
PWQEOF

    # Anti-bruteforce local (faillock)
    # even_deny_root = 0 : root non verrouillé (accès récupération préservé)
    cat > /etc/security/faillock.conf << 'FLOCKEOF'
deny          = 5
fail_interval = 900
unlock_time   = 900
even_deny_root = 0
FLOCKEOF

    # Activation via authselect (méthode officielle OL10/RHEL)
    if command -v authselect &>/dev/null; then
        CURRENT_PROFILE=$(authselect current --raw 2>/dev/null | head -1 || echo "")
        if [[ -n "$CURRENT_PROFILE" ]]; then
            authselect enable-feature with-faillock  2>/dev/null || true
            authselect enable-feature with-pwquality 2>/dev/null || true
            authselect apply-changes                 2>/dev/null || true
            ok "authselect : faillock + pwquality activés"
        else
            warn "Aucun profil authselect actif — PAM modules à vérifier manuellement"
        fi
    else
        warn "authselect non disponible — vérifier PAM manuellement"
    fi

    # login.defs : durée de vie mots de passe
    bak /etc/login.defs
    sed -ri 's/^(PASS_MAX_DAYS)[[:space:]]+.*/\1\t90/'  /etc/login.defs
    sed -ri 's/^(PASS_MIN_DAYS)[[:space:]]+.*/\1\t1/'   /etc/login.defs
    sed -ri 's/^(PASS_WARN_AGE)[[:space:]]+.*/\1\t7/'   /etc/login.defs
    sed -ri 's/^(UMASK)[[:space:]]+.*/\1\t027/'          /etc/login.defs

    # UMASK global pour toutes les sessions
    cat > /etc/profile.d/99-hardening-umask.sh << 'UMASKEOF'
# OL10 Ultra Hardening — UMASK restrictif
umask 027
UMASKEOF
    chmod 0644 /etc/profile.d/99-hardening-umask.sh

    ok "PAM, mots de passe et UMASK 027 configurés"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 6 — Firewalld : zone drop (tout bloquer sauf whitelist)
# ──────────────────────────────────────────────────────────────
sep
log "Phase 6 : Firewalld zone drop"

if ! is_dry; then
    systemctl enable --now firewalld

    firewall-cmd --set-default-zone=drop

    # Whitelist explicite des services métier (SSH + Web)
    firewall-cmd --zone=drop --add-service=ssh   --permanent
    firewall-cmd --zone=drop --add-service=http  --permanent
    firewall-cmd --zone=drop --add-service=https --permanent

    firewall-cmd --reload
    ok "Firewall : zone drop + SSH/HTTP/HTTPS autorisés"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 7 — Services inutiles : disable + mask
# ──────────────────────────────────────────────────────────────
sep
log "Phase 7 : Désactivation services inutiles"

MASK_LIST=(
    sendmail rpcbind avahi-daemon cups
    nfs-server bluetooth ypbind tftp
    xinetd telnet vsftpd rsh
)

if ! is_dry; then
    for svc in "${MASK_LIST[@]}"; do
        if systemctl list-unit-files "${svc}.service" 2>/dev/null \
           | grep -qE "^${svc}\.service"; then
            systemctl stop    "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
            systemctl mask    "$svc" 2>/dev/null || true
            log "  Masqué : $svc"
        fi
    done
    ok "Services inutiles désactivés et masqués"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 8 — Chrony : synchronisation horaire (NTP sécurisé)
# ──────────────────────────────────────────────────────────────
sep
log "Phase 8 : Synchronisation horaire (chronyd)"

if ! is_dry; then
    systemctl enable --now chronyd
    ok "chronyd actif et activé"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 9 — KVM / sVirt (conditionnel détection VT-x/AMD-V)
# ──────────────────────────────────────────────────────────────
sep
log "Phase 9 : KVM / sVirt"

if ! is_dry; then
    if grep -qE '(vmx|svm)' /proc/cpuinfo 2>/dev/null; then
        dnf install -y qemu-kvm libvirt virt-install

        QEMU_CONF=/etc/libvirt/qemu.conf
        bak "$QEMU_CONF"

        # Configuration idempotente sVirt (SELinux MCS pour les VMs)
        for setting in \
            'security_driver = "selinux"' \
            'security_default_confined = 1'
        do
            key="${setting%% =*}"
            if grep -qE "^#?\s*${key}" "$QEMU_CONF" 2>/dev/null; then
                sed -i "s|^#*\s*${key}.*|${setting}|" "$QEMU_CONF"
            else
                echo "$setting" >> "$QEMU_CONF"
            fi
        done

        systemctl enable --now libvirtd
        systemctl restart libvirtd
        ok "KVM/sVirt : security_driver=selinux + confinement par défaut"
    else
        warn "VT-x/AMD-V absent dans /proc/cpuinfo — KVM non installé"
    fi
fi

# ──────────────────────────────────────────────────────────────
# PHASE 10 — Systemd drop-in sshd (jeu sûr validé OL10)
# Note : SystemCallFilter omis volontairement — sshd+PAM nécessitent
#        des syscalls privilégiés qui varient selon les modules PAM.
#        Activer @system-service uniquement après validation en lab.
# ──────────────────────────────────────────────────────────────
sep
log "Phase 10 : Systemd hardening sshd (drop-in)"

if ! is_dry; then
    mkdir -p /etc/systemd/system/sshd.service.d

    cat > /etc/systemd/system/sshd.service.d/hardening.conf << 'DROPIN'
[Service]
NoNewPrivileges=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
PrivateMounts=yes
PrivateTmp=yes
ProtectControlGroups=yes
ProtectKernelModules=yes
ProtectKernelTunables=yes
DROPIN

    systemctl daemon-reload

    if sshd -t; then
        systemctl reload sshd 2>/dev/null || systemctl restart sshd
        ok "Systemd drop-in sshd : appliqué et validé"
    else
        err "sshd invalide après drop-in — rollback"
        rm -f /etc/systemd/system/sshd.service.d/hardening.conf
        systemctl daemon-reload
    fi
fi

# ──────────────────────────────────────────────────────────────
# PHASE 11 — Permissions fichiers critiques
# ──────────────────────────────────────────────────────────────
sep
log "Phase 11 : Permissions fichiers sensibles"

if ! is_dry; then
    chmod 0000 /etc/shadow                                     2>/dev/null || true
    chmod 0000 /etc/gshadow                                    2>/dev/null || true
    chmod 0644 /etc/passwd
    chmod 0644 /etc/group
    chmod 0440 /etc/sudoers                                    2>/dev/null || true
    chmod 0700 /root
    chmod 0600 /etc/ssh/sshd_config.d/99-hardening.conf       2>/dev/null || true
    chmod 0644 /etc/profile.d/99-hardening-umask.sh           2>/dev/null || true
    ok "Permissions fichiers sensibles appliquées"
fi

# ──────────────────────────────────────────────────────────────
# PHASE 12 — AIDE : initialisation + timer hebdomadaire
# ──────────────────────────────────────────────────────────────
sep
log "Phase 12 : AIDE (IDS hôte + scan hebdomadaire)"

if ! is_dry; then
    if command -v aide &>/dev/null; then
        if [[ ! -f /var/lib/aide/aide.db.gz && ! -f /var/lib/aide/aide.db ]]; then
            aide --init
            if [[ -f /var/lib/aide/aide.db.new.gz ]]; then
                mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
                ok "AIDE : base d'intégrité initialisée"
            fi
        else
            ok "AIDE : base déjà présente"
        fi

        # Timer systemd pour scan hebdomadaire automatique
        cat > /etc/systemd/system/aide-check.service << 'AIDESERVICE'
[Unit]
Description=AIDE — Vérification d'intégrité système
After=network.target auditd.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/aide --check
StandardOutput=journal
StandardError=journal
AIDESERVICE

        cat > /etc/systemd/system/aide-check.timer << 'AIDETIMER'
[Unit]
Description=AIDE — Scan hebdomadaire d'intégrité

[Timer]
OnCalendar=weekly
RandomizedDelaySec=3600
Persistent=true

[Install]
WantedBy=timers.target
AIDETIMER

        systemctl daemon-reload
        systemctl enable --now aide-check.timer
        ok "AIDE : timer hebdomadaire activé"
    else
        warn "AIDE non installé — vérifier phase 0"
    fi
fi

# ── Résumé final ─────────────────────────────────────────────
sep
log "=================================================================="
log " OL10 Ultra Hardening v${VERSION} terminé : $(date)"
log " Logs    : ${LOGFILE}"
log " Backups : ${BACKUP_DIR}"
if ! is_dry; then
    log ""
    log " ACTIONS POST-DÉPLOIEMENT :"
    log "   1. REBOOT si SELinux était Disabled (relabeling)"
    log "   2. REBOOT pour activer les règles auditd immuables (-e 2)"
    log "   3. Exécuter validate-hardening.sh après le reboot"
    log "   4. Ajouter clé SSH si PasswordAuthentication conservé"
fi
log "=================================================================="

(( ERRORS > 0 )) && {
    log "ATTENTION : ${ERRORS} erreur(s) — consulter ${LOGFILE}"
    exit 1
}
exit 0