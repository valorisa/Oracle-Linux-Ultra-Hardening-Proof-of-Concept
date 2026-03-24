#!/bin/bash
# ================================================================
# Oracle Linux 10 — Validation post-hardening v3.0 "Gold"
# Compatible CI/CD — exit 0 si conforme, exit 1 sinon
# Auteur  : valorisa — DevSecOps senior
# Usage   : ./validate-hardening.sh
# ================================================================
# set -e absent intentionnellement : tous les checks doivent s'exécuter
set -uo pipefail
IFS=$'\n\t'

readonly VERSION="3.0"
readonly REPORT="/var/log/validation-$(date +%Y%m%d-%H%M%S).log"
PASS=0
FAIL=0
WARNS=0

# ── Fonctions ──────────────────────────────────────────────────
tlog()  { echo "$*" | tee -a "$REPORT"; }
pass()  { tlog "[OK]   $*"; (( PASS++ ))  || true; }
fail()  { tlog "[FAIL] $*"; (( FAIL++ ))  || true; }
warn()  { tlog "[WARN] $*"; (( WARNS++ )) || true; }
info()  { tlog "[INFO] $*"; }
sect()  { tlog ""; tlog "─── $*"; }

chk() {
    local desc="$1"; shift
    if "$@" &>/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

chk_e() {
    local desc="$1"; shift
    if eval "$*" &>/dev/null 2>&1; then pass "$desc"; else fail "$desc"; fi
}

chk_perm() {
    local f="$1"; shift
    local valid_perms=("$@")
    [[ -e "$f" ]] || { info "$f : absent (skip)"; return; }
    local actual
    actual=$(stat -c "%a" "$f" 2>/dev/null || echo "?")
    local ok_flag=0
    for p in "${valid_perms[@]}"; do
        [[ "$actual" == "$p" ]] && ok_flag=1 && break
    done
    (( ok_flag )) \
        && pass "Permissions $f : $actual" \
        || fail "Permissions $f : $actual (attendu: ${valid_perms[*]})"
}

# ── Pré-requis ─────────────────────────────────────────────────
[[ "$EUID" -eq 0 ]] || { echo "ERREUR : root requis."; exit 1; }

{
    echo "=================================================================="
    echo " VALIDATION — OL10 Ultra Hardening v${VERSION}"
    echo " Date    : $(date)"
    echo " Système : $(uname -n) | Kernel : $(uname -r)"
    echo "=================================================================="
} | tee "$REPORT"

# ──────────────────────────────────────────────────────────────
# 1. SELinux
# ──────────────────────────────────────────────────────────────
sect "1. SELinux"

SEMODE=$(getenforce 2>/dev/null || echo "Disabled")
[[ "$SEMODE" == "Enforcing" ]] \
    && pass "SELinux runtime : Enforcing" \
    || fail "SELinux runtime : $SEMODE (attendu: Enforcing)"

chk_e "SELinux enforcing persistant (config)" \
    "grep -qE '^SELINUX=enforcing' /etc/selinux/config"

SETYPE=$(grep -E '^SELINUXTYPE=' /etc/selinux/config 2>/dev/null \
    | cut -d= -f2 | tr -d ' ' || echo "?")
[[ "$SETYPE" == "targeted" || "$SETYPE" == "mls" ]] \
    && pass "SELinux type : $SETYPE (valide)" \
    || fail "SELinux type : '$SETYPE' (attendu: targeted ou mls)"

if command -v semanage &>/dev/null; then
    PERM_DOMAINS=$(semanage permissive -l 2>/dev/null \
        | awk '/^Customized Permissive/{p=1;next}/^Policy Permissive/{p=0}
               p && /[a-z]/{print $1}' || true)
    [[ -z "$PERM_DOMAINS" ]] \
        && pass "SELinux : aucun domaine permissif personnalisé" \
        || fail "SELinux : domaines permissifs actifs — $PERM_DOMAINS"
else
    warn "semanage indisponible — vérification domaines permissifs ignorée"
fi

info "$(sestatus 2>/dev/null | head -5 || echo 'sestatus indisponible')"

# ──────────────────────────────────────────────────────────────
# 2. SSH
# ──────────────────────────────────────────────────────────────
sect "2. Durcissement SSH"

chk "sshd_config syntaxiquement valide" sshd -t
chk "Service sshd actif"                systemctl is-active sshd
chk "sshd activé au démarrage"          systemctl is-enabled sshd

[[ -f /etc/ssh/sshd_config.d/99-hardening.conf ]] \
    && pass "Drop-in SSH présent" \
    || warn "Drop-in SSH absent (config via sshd_config principal ?)"

# Source de vérité : configuration effective (sshd -T)
SSHD_T=$(sshd -T 2>/dev/null || true)

grep -qi '^permitrootlogin no'      <<< "$SSHD_T" \
    && pass "PermitRootLogin = no"  || fail "PermitRootLogin ≠ no"

grep -qi '^permitemptypasswords no' <<< "$SSHD_T" \
    && pass "PermitEmptyPasswords = no" || fail "PermitEmptyPasswords ≠ no"

grep -qi '^x11forwarding no'        <<< "$SSHD_T" \
    && pass "X11Forwarding = no"    || fail "X11Forwarding ≠ no"

grep -qi '^allowtcpforwarding no'   <<< "$SSHD_T" \
    && pass "AllowTcpForwarding = no" || fail "AllowTcpForwarding ≠ no"

grep -qi '^pubkeyauthentication yes' <<< "$SSHD_T" \
    && pass "PubkeyAuthentication = yes" || fail "PubkeyAuthentication ≠ yes"

# MaxAuthTries <= 4
MAX_AUTH=$(awk '/^maxauthtries /{print $2}' <<< "$SSHD_T" || echo "?")
if [[ "$MAX_AUTH" =~ ^[0-9]+$ ]] && (( MAX_AUTH <= 4 )); then
    pass "MaxAuthTries = $MAX_AUTH (<= 4)"
else
    fail "MaxAuthTries = $MAX_AUTH (attendu: <= 4)"
fi

# ClientAliveCountMax <= 2
CALC=$(awk '/^clientalivecountmax /{print $2}' <<< "$SSHD_T" || echo "?")
if [[ "$CALC" =~ ^[0-9]+$ ]] && (( CALC <= 2 )); then
    pass "ClientAliveCountMax = $CALC (<= 2)"
else
    fail "ClientAliveCountMax = $CALC (attendu: <= 2)"
fi

# LoginGraceTime <= 60
LGT=$(awk '/^logingracetime /{print $2}' <<< "$SSHD_T" || echo "?")
if [[ "$LGT" =~ ^[0-9]+$ ]] && (( LGT <= 60 )); then
    pass "LoginGraceTime = $LGT (<= 60s)"
else
    fail "LoginGraceTime = $LGT (attendu: <= 60)"
fi

# Vérification PasswordAuthentication (warn si encore active)
grep -qi '^passwordauthentication yes' <<< "$SSHD_T" \
    && warn "PasswordAuthentication = yes (clé SSH admin absente au moment du hardening)" \
    || pass "PasswordAuthentication = no"

# ──────────────────────────────────────────────────────────────
# 3. Sysctl
# ──────────────────────────────────────────────────────────────
sect "3. Sysctl sécurité"

declare -A SYSCTL_EXPECT=(
    [kernel.randomize_va_space]="2"
    [kernel.kptr_restrict]="2"
    [kernel.dmesg_restrict]="1"
    [kernel.perf_event_paranoid]="3"
    [kernel.yama.ptrace_scope]="2"
    [kernel.sysrq]="0"
    [fs.suid_dumpable]="0"
    [fs.protected_hardlinks]="1"
    [fs.protected_symlinks]="1"
    [net.ipv4.conf.all.rp_filter]="1"
    [net.ipv4.conf.all.accept_redirects]="0"
    [net.ipv4.conf.all.send_redirects]="0"
    [net.ipv4.conf.all.accept_source_route]="0"
    [net.ipv4.conf.all.log_martians]="1"
    [net.ipv4.tcp_syncookies]="1"
    [net.ipv4.ip_forward]="0"
    [net.ipv6.conf.all.accept_redirects]="0"
    [net.ipv6.conf.all.forwarding]="0"
)

for param in "${!SYSCTL_EXPECT[@]}"; do
    expected="${SYSCTL_EXPECT[$param]}"
    proc_path="/proc/sys/${param//.//}"
    if [[ ! -e "$proc_path" ]]; then
        info "sysctl $param : non supporté par ce kernel (skip)"
        continue
    fi
    actual=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    [[ "$actual" == "$expected" ]] \
        && pass "sysctl $param = $actual" \
        || fail "sysctl $param = $actual (attendu: $expected)"
done

# BPF : peut ne pas exister selon version kernel
if [[ -e /proc/sys/kernel/unprivileged_bpf_disabled ]]; then
    actual=$(sysctl -n kernel.unprivileged_bpf_disabled 2>/dev/null || echo "?")
    [[ "$actual" == "1" ]] \
        && pass "sysctl kernel.unprivileged_bpf_disabled = 1" \
        || fail "sysctl kernel.unprivileged_bpf_disabled = $actual (attendu: 1)"
else
    info "kernel.unprivileged_bpf_disabled : non supporté (skip)"
fi

# ──────────────────────────────────────────────────────────────
# 4. auditd
# ──────────────────────────────────────────────────────────────
sect "4. auditd"

chk "Service auditd actif"          systemctl is-active  auditd
chk "auditd activé au démarrage"    systemctl is-enabled auditd

# Comportement disque plein
for kv in "admin_space_left_action:HALT" "disk_full_action:HALT" "disk_error_action:HALT"; do
    key="${kv%%:*}"
    expected="${kv##*:}"
    actual=$(grep -i "^${key}" /etc/audit/auditd.conf 2>/dev/null \
        | awk -F'[= ]+' '{print $2}' | tr -d '[:space:]' || echo "?")
    [[ "${actual^^}" == "$expected" ]] \
        && pass "auditd.conf $key = $expected" \
        || fail "auditd.conf $key = ${actual:-non défini} (attendu: $expected)"
done

# Nombre de règles actives
RULE_COUNT=$(auditctl -l 2>/dev/null | grep -c '^-' || echo "0")
(( RULE_COUNT > 10 )) \
    && pass "Règles auditd : $RULE_COUNT règles chargées" \
    || fail "Règles auditd : $RULE_COUNT (attendu: > 10)"

# Règles immuables (-e 2)
auditctl -s 2>/dev/null | grep -q "enabled 2" \
    && pass "Règles auditd immuables (-e 2)" \
    || fail "Règles auditd non immuables (règle -e 2 absente)"

# Surveillance fichiers critiques
for watched in "/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config.d/"; do
    auditctl -l 2>/dev/null | grep -q "$watched" \
        && pass "Règle audit : $watched surveillé" \
        || fail "Règle audit : $watched NON surveillé"
done

# Règles 32 bits sur x86_64
if [[ "$(uname -m)" == "x86_64" ]]; then
    auditctl -l 2>/dev/null | grep -q "arch=b32" \
        && pass "Règles audit 32 bits présentes (anti-contournement)" \
        || fail "Règles audit 32 bits absentes sur x86_64"
fi

# ──────────────────────────────────────────────────────────────
# 5. PAM — pwquality, faillock, login.defs, umask
# ──────────────────────────────────────────────────────────────
sect "5. PAM et politique de mots de passe"

# pwquality
if [[ -f /etc/security/pwquality.conf ]]; then
    MINLEN=$(grep -E '^minlen' /etc/security/pwquality.conf 2>/dev/null \
        | awk -F'[= ]+' '{print $2}' || echo "0")
    [[ "${MINLEN:-0}" -ge 14 ]] \
        && pass "pwquality minlen = $MINLEN (>= 14)" \
        || fail "pwquality minlen = ${MINLEN:-?} (attendu: >= 14)"

    MINCLASS=$(grep -E '^minclass' /etc/security/pwquality.conf 2>/dev/null \
        | awk -F'[= ]+' '{print $2}' || echo "0")
    [[ "${MINCLASS:-0}" -ge 4 ]] \
        && pass "pwquality minclass = $MINCLASS (>= 4)" \
        || fail "pwquality minclass = ${MINCLASS:-?} (attendu: >= 4)"
else
    fail "/etc/security/pwquality.conf absent"
fi

# faillock
if [[ -f /etc/security/faillock.conf ]]; then
    DENY=$(grep -E '^deny' /etc/security/faillock.conf 2>/dev/null \
        | awk -F'[= ]+' '{print $2}' || echo "?")
    [[ "${DENY:-0}" -le 5 && "${DENY:-0}" -gt 0 ]] \
        && pass "faillock deny = $DENY (<= 5)" \
        || fail "faillock deny = ${DENY:-?} (attendu: 1-5)"

    UNLOCK=$(grep -E '^unlock_time' /etc/security/faillock.conf 2>/dev/null \
        | awk -F'[= ]+' '{print $2}' || echo "?")
    [[ "${UNLOCK:-0}" -ge 900 ]] \
        && pass "faillock unlock_time = $UNLOCK (>= 900s)" \
        || fail "faillock unlock_time = ${UNLOCK:-?} (attendu: >= 900)"
else
    fail "/etc/security/faillock.conf absent"
fi

# login.defs
if [[ -f /etc/login.defs ]]; then
    PASS_MAX=$(awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs 2>/dev/null || echo "?")
    [[ "${PASS_MAX:-0}" -le 90 && "${PASS_MAX:-0}" -gt 0 ]] \
        && pass "login.defs PASS_MAX_DAYS = $PASS_MAX (<= 90)" \
        || fail "login.defs PASS_MAX_DAYS = ${PASS_MAX:-?} (attendu: <= 90)"

    UMASK_VAL=$(awk '/^UMASK/{print $2}' /etc/login.defs 2>/dev/null || echo "?")
    [[ "$UMASK_VAL" == "027" || "$UMASK_VAL" == "0027" ]] \
        && pass "login.defs UMASK = $UMASK_VAL" \
        || fail "login.defs UMASK = ${UMASK_VAL:-?} (attendu: 027)"
else
    fail "/etc/login.defs absent"
fi

# Profil UMASK global
[[ -f /etc/profile.d/99-hardening-umask.sh ]] \
    && pass "Profil UMASK 027 présent (/etc/profile.d/)" \
    || warn "Profil UMASK /etc/profile.d/99-hardening-umask.sh absent"

# ──────────────────────────────────────────────────────────────
# 6. Firewalld
# ──────────────────────────────────────────────────────────────
sect "6. Firewalld"

chk "Service firewalld actif"          systemctl is-active  firewalld
chk "firewalld activé au démarrage"    systemctl is-enabled firewalld

DEFZONE=$(firewall-cmd --get-default-zone 2>/dev/null || echo "inconnu")
[[ "$DEFZONE" == "drop" || "$DEFZONE" == "block" ]] \
    && pass "Zone par défaut restrictive : $DEFZONE" \
    || fail "Zone par défaut : $DEFZONE (attendu: drop ou block)"

# SSH accessible depuis la zone active
firewall-cmd --zone="$DEFZONE" --query-service=ssh &>/dev/null \
    && pass "SSH autorisé dans la zone $DEFZONE" \
    || fail "SSH NON autorisé dans la zone $DEFZONE"

info "Ports en écoute :"
ss -lntup 2>/dev/null | head -20 | tee -a "$REPORT" || true

# ──────────────────────────────────────────────────────────────
# 7. Services inutiles
# ──────────────────────────────────────────────────────────────
sect "7. Services inutiles (masked ou absent)"

RISKY_SERVICES=(
    sendmail rpcbind avahi-daemon cups
    nfs-server bluetooth ypbind tftp
    xinetd telnet vsftpd rsh
)

for svc in "${RISKY_SERVICES[@]}"; do
    STATUS=$(systemctl is-enabled "$svc" 2>/dev/null || echo "not-found")
    case "$STATUS" in
        masked|not-found|disabled)
            pass "Service $svc : $STATUS" ;;
        *)
            fail "Service $svc : $STATUS (doit être masked ou absent)" ;;
    esac
done

# ──────────────────────────────────────────────────────────────
# 8. Chrony (synchronisation horaire)
# ──────────────────────────────────────────────────────────────
sect "8. Chrony — synchronisation horaire"

chk "Service chronyd actif"         systemctl is-active  chronyd
chk "chronyd activé au démarrage"   systemctl is-enabled chronyd

# Vérifier synchronisation effective
if chronyc tracking &>/dev/null; then
    STRATUM=$(chronyc tracking 2>/dev/null | awk '/^Stratum/{print $3}' || echo "?")
    REF_SRC=$(chronyc tracking 2>/dev/null | awk '/^Reference ID/{print $4}' || echo "?")
    if [[ "${STRATUM:-16}" -lt 16 ]]; then
        pass "chronyd synchronisé (stratum $STRATUM, source $REF_SRC)"
    else
        warn "chronyd : stratum $STRATUM — synchronisation incomplète"
    fi
else
    warn "chronyc tracking indisponible — vérification manuelle requise"
fi

# ──────────────────────────────────────────────────────────────
# 9. Permissions fichiers critiques
# ──────────────────────────────────────────────────────────────
sect "9. Permissions fichiers sensibles"

# /etc/shadow : OL10 accepte 000 (défaut) ou 640 root:shadow
chk_perm /etc/shadow  "000" "640"
chk_perm /etc/gshadow "000" "640"
chk_perm /etc/passwd  "644"
chk_perm /etc/group   "644"
chk_perm /etc/sudoers "440" "440"
chk_perm /root        "700"

# Ownership shadow
if [[ -e /etc/shadow ]]; then
    OWNER=$(stat -c "%U:%G" /etc/shadow 2>/dev/null || echo "?")
    [[ "$OWNER" == "root:root" || "$OWNER" == "root:shadow" ]] \
        && pass "/etc/shadow ownership : $OWNER" \
        || fail "/etc/shadow ownership : $OWNER (attendu: root:root ou root:shadow)"
fi

# Drop-in SSH
chk_perm /etc/ssh/sshd_config.d/99-hardening.conf "600"

# ──────────────────────────────────────────────────────────────
# 10. KVM / sVirt (si libvirtd actif)
# ──────────────────────────────────────────────────────────────
sect "10. sVirt — confinement KVM/libvirt"

if systemctl is-active libvirtd &>/dev/null; then
    chk "libvirtd actif" systemctl is-active libvirtd

    grep -qE '^security_driver\s*=\s*"selinux"' /etc/libvirt/qemu.conf 2>/dev/null \
        && pass "sVirt : security_driver = selinux" \
        || fail "sVirt : security_driver manquant ou ≠ selinux"

    grep -qE '^security_default_confined\s*=\s*1' /etc/libvirt/qemu.conf 2>/dev/null \
        && pass "sVirt : security_default_confined = 1" \
        || fail "sVirt : security_default_confined non configuré"
else
    info "libvirtd non actif — vérification sVirt ignorée"
fi

# ──────────────────────────────────────────────────────────────
# 11. Systemd drop-in sshd
# ──────────────────────────────────────────────────────────────
sect "11. Systemd hardening sshd"

DROPIN="/etc/systemd/system/sshd.service.d/hardening.conf"
if [[ -f "$DROPIN" ]]; then
    pass "Drop-in systemd sshd présent"

    for directive in \
        "NoNewPrivileges=yes" \
        "RestrictRealtime=yes" \
        "RestrictSUIDSGID=yes" \
        "LockPersonality=yes" \
        "ProtectKernelModules=yes" \
        "ProtectKernelTunables=yes"
    do
        grep -q "^${directive}" "$DROPIN" 2>/dev/null \
            && pass "sshd drop-in : $directive" \
            || fail "sshd drop-in : $directive manquant"
    done

    # Score systemd-analyze (informatif uniquement)
    if command -v systemd-analyze &>/dev/null; then
        SCORE=$(systemd-analyze security sshd 2>/dev/null \
            | awk '/→/{print $NF}' | tail -1 || echo "N/A")
        info "Score systemd-analyze sshd : $SCORE"
    fi
else
    fail "Drop-in systemd sshd absent : $DROPIN"
fi

# ──────────────────────────────────────────────────────────────
# 12. AIDE — intégrité système
# ──────────────────────────────────────────────────────────────
sect "12. AIDE — intégrité système"

if command -v aide &>/dev/null; then
    pass "AIDE installé"

    if [[ -f /var/lib/aide/aide.db.gz || -f /var/lib/aide/aide.db ]]; then
        pass "Base AIDE initialisée"
    else
        fail "Base AIDE non initialisée (lancer : aide --init)"
    fi

    # Timer systemd hebdomadaire
    if systemctl is-enabled aide-check.timer &>/dev/null; then
        pass "Timer AIDE hebdomadaire activé"
    else
        warn "Timer AIDE non activé — scans manuels requis"
    fi
else
    fail "AIDE non installé (dnf install aide)"
fi

# ──────────────────────────────────────────────────────────────
# 13. OpenSCAP (scan CIS si disponible)
# ──────────────────────────────────────────────────────────────
sect "13. OpenSCAP — conformité CIS"

if command -v oscap &>/dev/null; then
    pass "oscap installé"

    SSG_FILE=$(ls /usr/share/xml/scap/ssg/content/ssg-ol10-xccdf.xml \
                   /usr/share/xml/scap/ssg/content/*ol*10*xccdf.xml \
               2>/dev/null | head -1 || true)

    if [[ -n "$SSG_FILE" ]]; then
        pass "SSG Oracle Linux 10 trouvé : $SSG_FILE"
        info "Lancement scan CIS Level 1 (peut prendre quelques minutes)..."

        SCAP_REPORT="/var/log/scap-results-$(date +%Y%m%d).xml"
        SCAP_HTML="/var/log/scap-report-$(date +%Y%m%d).html"

        if oscap xccdf eval \
            --profile xccdf_org.ssgproject.content_profile_cis \
            --results  "$SCAP_REPORT" \
            --report   "$SCAP_HTML"  \
            "$SSG_FILE" &>/dev/null; then
            pass "Scan OpenSCAP terminé — rapport : $SCAP_HTML"
        else
            # oscap retourne 2 si des règles échouent (normal)
            EXIT_CODE=$?
            if [[ "$EXIT_CODE" -eq 2 ]]; then
                warn "Scan OpenSCAP : des règles CIS échouent — rapport : $SCAP_HTML"
            else
                fail "Scan OpenSCAP : erreur inattendue (code $EXIT_CODE)"
            fi
        fi

        # Extraire le score si disponible
        if [[ -f "$SCAP_REPORT" ]] && command -v xmllint &>/dev/null; then
            SCORE=$(xmllint --xpath \
                "string(//score)" "$SCAP_REPORT" 2>/dev/null || echo "N/A")
            info "Score CIS réel (OpenSCAP) : $SCORE"
        fi
    else
        warn "SSG OL10 non trouvé — installer : dnf install scap-security-guide"
        info "Scan OpenSCAP ignoré"
    fi
else
    warn "oscap non installé (dnf install openscap-scanner scap-security-guide)"
    info "Scan OpenSCAP ignoré"
fi

# ── Rapport final ──────────────────────────────────────────────
TOTAL=$(( PASS + FAIL + WARNS ))

{
    echo ""
    echo "=================================================================="
    echo " RÉSUMÉ FINAL — OL10 Ultra Hardening v${VERSION} — $(date)"
    echo "=================================================================="
    printf " %-25s : %d\n" "Tests réussis  [OK]"   "$PASS"
    printf " %-25s : %d\n" "Tests échoués  [FAIL]"  "$FAIL"
    printf " %-25s : %d\n" "Avertissements [WARN]"  "$WARNS"
    printf " %-25s : %d\n" "Total"                   "$TOTAL"
    echo "------------------------------------------------------------------"
    if (( FAIL == 0 && WARNS == 0 )); then
        echo " STATUT : ✅  PLEINEMENT CONFORME"
    elif (( FAIL == 0 )); then
        echo " STATUT : ⚠️  CONFORME avec avertissements ($WARNS WARN)"
    else
        echo " STATUT : ❌  NON CONFORME — $FAIL point(s) critiques à corriger"
    fi
    echo " Rapport complet : $REPORT"
    echo "=================================================================="
} | tee -a "$REPORT"

# Code de sortie CI/CD : 0 = conforme, 1 = échec(s) critique(s)
(( FAIL == 0 )) && exit 0 || exit 1



# Checklist de déploiement en production
# Les deux scripts sont prêts. Voici l'ordre opérationnel à respecter :
# 1. Avant déploiement — snapshot VM ou backup système, vérifier accès console OOB disponible, déposer une clé SSH admin valide 
# (/root/.ssh/authorized_keys).
# 2. Exécution — chmod +x oracle-linux-ultra-hardening.sh validate-hardening.sh, tester d'abord avec --dry-run, puis lancer 
# ./oracle-linux-ultra-hardening.sh en production.
# 3. Post-exécution — reboot obligatoire si SELinux était Disabled, puis lancer ./validate-hardening.sh et traiter chaque [FAIL] 
# avant mise en service.
# 4. Optionnel mais recommandé — dnf install openscap-scanner scap-security-guide pour activer le scan CIS réel dans le script de 
# validation.