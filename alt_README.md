# Réfutation de « The insecurity of OpenBSD » (2010) avec Oracle Linux 10 ultra‑durci

**Auteur** : valorisa – DevSecOps senior  
**Date** : 2026-03-23  
**Version scripts** : v3.0 "Gold" — Production Ready  
**Objectif** : Démontrer qu'une distribution Linux moderne (Oracle Linux 10) surpasse
largement OpenBSD en matière de sécurité, en réponse point‑par‑point à l'article
historique.

---

## Table des matières

1. [Introduction](#1-introduction)
2. [Secure by default](#2-secure-by-default)
3. [Security practices and philosophy](#3-security-practices-and-philosophy)
4. [No way to thoroughly lock down a system](#4-no-way-to-thoroughly-lock-down-a-system)
5. [The need for extended access controls](#5-the-need-for-extended-access-controls)
6. [Extended access controls are too complex](#6-extended-access-controls-are-too-complex)
7. [Conclusion](#7-conclusion)
8. [Déploiement — Guide opérationnel](#8-déploiement--guide-opérationnel)
9. [Annexes techniques](#9-annexes-techniques)
10. [Références](#10-références)

---

## 1. Introduction

> *« OpenBSD was not designed with security in mind »*  
> *« standard UNIX permissions, which are insufficient »*

L'article débute en affirmant qu'OpenBSD n'a pas été conçu pour la sécurité. Or,
Oracle Linux 10 repose sur une architecture de sécurité pensée dès le départ, avec
des composants comme **SELinux** (FLASK, développé par la NSA) et des mécanismes de
confinement avancés.

### 1.1 Conception de la sécurité dans Oracle Linux 10

Contrairement à OpenBSD, dont la sécurité a été ajoutée *a posteriori* (après le
fork de NetBSD), Oracle Linux 10 intègre dès le noyau un système de contrôle
d'accès obligatoire (MAC) mature, **SELinux**, basé sur le framework FLASK. Ce
dernier permet de définir des politiques de sécurité fines qui s'appliquent à tous
les processus, y compris ceux s'exécutant avec les privilèges root.

De plus, Oracle Linux 10 bénéficie de l'expérience de la communauté Linux et
d'entreprises comme Oracle, Red Hat et Google, qui ont contribué à faire évoluer le
noyau vers des fonctionnalités de sécurité avancées : **seccomp-bpf**,
**namespaces**, **capabilities**, **Landlock**, etc.

### 1.2 Tableau comparatif initial

| Critère | OpenBSD (2010) | Oracle Linux 10 ultra‑durci |
|--------|---------------|------------------------------|
| Conception sécurité | Ajoutée après coup (1996) | Intégrée dès le noyau (SELinux depuis 2003) |
| Modèle d'accès | DAC uniquement | MAC (SELinux) + DAC (ACLs) |
| Contrôle fin | Chroot limité | SELinux types, MCS, catégories, seccomp |
| Composants sécurité | < 1 000 lignes (hors audit) | > 500 000 (SELinux + seccomp + audit) |
| Vérification formelle | Non | Partielle (SELinux via FLASK, seccomp) |

---

## 2. Secure by default

> *« Only two remote holes in the default install, in a heck of a long time! »*  
> *« The ports tree is not audited »*

L'article minimise les "deux failles" en précisant qu'OpenBSD ne compte que les
vulnérabilités *remote*. Oracle Linux 10, avec son processus de certification
**CIS** et les scripts de ce dépôt, atteint un niveau de conformité élevé mesuré
objectivement par **OpenSCAP** (profil CIS niveau 1, score calculé — jamais simulé).

### 2.1 L'approche CIS Benchmarks

Le **Center for Internet Security (CIS)** publie des benchmarks pour les systèmes
d'exploitation. Oracle Linux 10 suit ces recommandations, ce qui garantit une
configuration sécurisée par défaut :

- Désactivation des services non essentiels (sendmail, rpcbind, avahi-daemon, cups…).
- Activation de l'audit (`auditd`) pour tracer les événements de sécurité.
- Configuration de `firewalld` avec zone `drop` (tout bloquer sauf whitelist explicite).
- Mise en place de `chrony` pour une synchronisation horaire sécurisée.
- PAM complet : `pwquality` + `faillock` + `login.defs` durci.

Contrairement à OpenBSD, où le "secure by default" ne concerne que la base
installée, Oracle Linux 10 applique une approche holistique : même les logiciels
installés via les dépôts sont audités, signés et régulièrement mis à jour.

### 2.2 Comparaison des processus d'audit

| Élément | OpenBSD | Oracle Linux 10 |
|--------|---------|----------------|
| Audit du noyau | Manuel par l'équipe | Automatisé, CI, audits externes |
| Audit des paquets | Base seulement | Dépôts entiers avec signatures GPG |
| Correctifs de sécurité | Patchs manuels | Kpatch (live patching) sans redémarrage |
| Score CIS | Non applicable | Mesuré par OpenSCAP (objectif et reproductible) |

### 2.3 Exemple concret : vérification post-installation

```bash
# Services actifs après installation minimale + hardening v3.0
systemctl list-units --state=active --type=service | grep -v "@"
# Résultat attendu : sshd, chronyd, firewalld, auditd, libvirtd (si hôte KVM)

# Score CIS réel via OpenSCAP
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --report /var/log/scap-report.html \
  /usr/share/xml/scap/ssg/content/ssg-ol10-xccdf.xml
```

---

## 3. Security practices and philosophy

> *« sendmail is still their MTA of choice and BIND is still their DNS server of choice »*  
> *« atrocious security records »*

Oracle Linux 10 remplace ces composants obsolètes par des alternatives modernes et
sécurisées :

- **Postfix** (MTA) avec support SMTP TLS et restriction d'accès.
- **Unbound** (DNS) en remplacement de BIND, avec DNSSEC validant.
- **Firewalld** et **nftables** pour le filtrage réseau.

### 3.1 Analyse des choix d'OpenBSD

En 2010, OpenBSD maintenait encore sendmail et BIND, deux logiciels ayant un
historique de vulnérabilités critique. Oracle Linux 10, en revanche, propose par
défaut des logiciels conçus pour la sécurité dès leur architecture :

- **Postfix** : isolation des processus, séparation des privilèges, support natif TLS.
- **Unbound** : résolveur DNS validant, conçu pour résister aux attaques par déni
  de service.

### 3.2 Philosophie de sécurité : au‑delà de l'audit

La philosophie OpenBSD consistant à "éliminer les bugs" est louable, mais elle omet
la nécessité de **contenir les dégâts en cas d'exploitation réussie**. Oracle Linux
10 combine la réduction des bugs (noyau maintenu activement) avec des mesures de
**confinement en profondeur** (SELinux, seccomp, namespaces).

### 3.3 Tableau des services par défaut

| Service | OpenBSD (2010) | Oracle Linux 10 (hardening v3.0) |
|---------|----------------|----------------------------------|
| MTA | Sendmail | Masqué (sendmail.service masked) |
| DNS | BIND | Masqué (bind.service masked) |
| Firewall | PF | nftables via firewalld (zone drop) |
| SSH | OpenSSH | OpenSSH + drop-in sshd_config.d + drop-in systemd |

---

## 4. No way to thoroughly lock down a system

> *« no sufficient way to restrict access »*  
> *« naïve at best and arrogant at worst »*

Contrairement à OpenBSD qui se repose sur `chroot` et `systrace` (désormais reconnu
comme insuffisant et abandonné), Oracle Linux 10 propose plusieurs couches de
confinement complémentaires et validées :

- **SELinux** : politique `targeted` enforcing, zero domaine permissif.
- **sVirt** : sécurité des machines virtuelles KVM via SELinux MCS.
- **seccomp** : filtrage des appels système via systemd (NoNewPrivileges, RestrictRealtime…).
- **Namespaces** et **Capabilities POSIX** : isolation fine des processus.

### 4.1 Analyse de `chroot` et `systrace`

`systrace` a été prouvé vulnérable à des attaques de concurrence (TOCTOU) et
abandonné. Oracle Linux 10 utilise des technologies intégrées au noyau, bénéficiant
d'une maturité et d'une vérification formelle (FLASK pour SELinux).

### 4.2 Exemple de confinement SELinux pour Apache

```bash
# Contexte SELinux du processus Apache
ps -eZ | grep httpd
# system_u:system_r:httpd_t:s0 ...

# Tentative d'écriture dans /root par Apache — refusée par SELinux
sudo -u apache touch /root/test
# Permission denied (bloqué par politique SELinux, pas par DAC)

# Vérification de la règle SELinux
sesearch -A -s httpd_t -t etc_t -c file -p write
# Aucune règle n'autorise cette opération
```

### 4.3 Tableau des mécanismes de confinement

| Outil | OpenBSD | Oracle Linux 10 |
|-------|---------|----------------|
| Chroot | Oui, amélioré | Oui (rarement seul) |
| Jail/Virtualisation | vmm minimal | KVM + sVirt, LXC, Docker, Podman |
| MAC | Aucun | SELinux (targeted enforcing) |
| Filtrage syscall | Non | seccomp-bpf via systemd drop-ins |
| Capabilities POSIX | Non | Oui |
| Namespaces | Non | Oui (user, net, mount, pid, ipc…) |

---

## 5. The need for extended access controls

> *« DAC insufficient »*  
> *« post-root game over »*

L'article a raison sur un point : le contrôle d'accès discrétionnaire (DAC) ne
suffit pas. Oracle Linux 10 intègre des EACL matures :

- **SELinux** : politique `targeted` vérifiée, zéro exception en production.
- **auditd** : traçabilité complète des accès avec règles 32 et 64 bits.
- **setroubleshoot** : facilite l'écriture de politiques personnalisées.

### 5.1 Comment SELinux change la donne

SELinux implémente le modèle « Type Enforcement » (TE). Chaque processus est associé
à un domaine, chaque objet à un type. Des règles définissent quels domaines peuvent
accéder à quels types. Un attaquant ayant obtenu les privilèges root reste confiné
dans le domaine SELinux du processus compromis.

### 5.2 Exemple pratique : compromission d'un serveur Apache

```bash
# L'attaquant exploite une faille Apache et obtient un shell dans le contexte httpd_t
# SELinux bloque toute écriture dans /etc/passwd (type etc_t)

# Règles effectives
sesearch -A -s httpd_t -t etc_t -c file -p write
# Résultat : aucune règle → write() refusé par le noyau

# L'événement est immédiatement tracé dans auditd
ausearch -k identity -ts recent
```

### 5.3 Tableau des capacités EACL

| Capacité | OpenBSD | Oracle Linux 10 |
|----------|---------|----------------|
| MAC complet | Non | SELinux (targeted enforcing) |
| Contrôle accès fichiers | DAC (rwx) | DAC + ACL étendues + types SELinux |
| Isolation processus | Chroot | SELinux + seccomp + namespaces |
| Séparation des privilèges | Partielle (privsep) | Systématique via domaines SELinux |
| Audit des accès | Partiel | Complet (auditd + règles 32/64 bits) |

---

## 6. Extended access controls are too complex

> *« SELinux/RSBAC formally verified »*  
> *« fortress built upon sand »*

La complexité de SELinux est souvent citée comme excuse, mais Oracle Linux 10
fournit des outils pour la maîtriser sans sacrifier la rigueur :

- **semanage** : gestion des politiques (booleans, types, ports).
- **audit2allow** : conversion des messages d'audit en règles politiques.
- **OpenSCAP** : validation automatisée de la conformité CIS/STIG.
- **setroubleshoot** : diagnostic interactif des refus SELinux.

### 6.1 Démystifier la complexité de SELinux

Les politiques prédéfinies (`targeted`) fonctionnent sans intervention pour la
quasi-totalité des applications. Le mode `permissive` permet de tester les règles
avant de passer en `enforcing`. Le script `oracle-linux-ultra-hardening.sh` active
directement `enforcing` avec la politique `targeted` et supprime tout domaine
permissif résiduel.

### 6.2 Comparaison des frameworks EACL

| Framework | Complexité | Maturité | Adoption |
|-----------|-----------|---------|----------|
| SELinux | Élevée | Très mature (>20 ans) | RHEL, Oracle Linux, Fedora |
| RSBAC | Élevée | Mature, moins répandu | Hardened Gentoo |
| Systrace | Faible | Obsolète, vulnérable | Abandonné |

### 6.3 Exemple : création d'une règle SELinux avec audit2allow

```bash
# En mode permissif, les violations s'enregistrent dans l'audit log
grep "denied" /var/log/audit/audit.log | audit2allow -M mon_module
semodule -i mon_module.pp

# Retour en enforcing après validation
setenforce 1
```

---

## 7. Conclusion

> *« Linux more secure despite NDA »*

L'article de 2010 sous‑estimait profondément les progrès de Linux. Aujourd'hui,
Oracle Linux 10 avec le hardening v3.0 de ce dépôt offre une sécurité
**multi‑couches** objectivement mesurable et supérieure à OpenBSD sur tous les
critères pertinents :

| Domaine | OpenBSD | Oracle Linux 10 (v3.0) |
|---------|---------|------------------------|
| Audit code | Excellent, mais équipe réduite | Large, soutenu par Oracle/Red Hat/Google |
| MAC | Aucun | SELinux targeted enforcing, zéro permissive |
| Sécurité virtuelle | vmm minimal | sVirt + KVM + SELinux MCS |
| Filtrage syscall | Non | seccomp via systemd drop-ins |
| Vulnérabilités | Peu nombreuses | Réponses rapides + Kpatch live patching |
| Outils de validation | Limités | CIS, OVAL, OpenSCAP, auditd |
| Politique mots de passe | Basique | pwquality + faillock (anti-bruteforce) |
| Traçabilité | Limitée | auditd complet, règles 32+64 bits, immuables |

**La preuve est dans l'exécution** : les deux scripts de ce dépôt permettent de
reproduire un durcissement ultra-robuste, validé par des tests concrets et un score
CIS **réel** calculé par OpenSCAP.

---

## 8. Déploiement — Guide opérationnel

### 8.1 Prérequis

#### Environnement cible

| Élément | Requis |
|---------|--------|
| OS | Oracle Linux 10 (testé), RHEL 10 compatible |
| Architecture | x86_64 (règles audit 32 bits conditionnelles) |
| Accès | root (sudo ou session root directe) |
| Réseau | Accès dnf aux dépôts Oracle (ou miroir interne) |
| Console OOB | **Fortement recommandé** (iDRAC, iLO, accès console VM) |

#### Paquets installés automatiquement par le script

Le script `oracle-linux-ultra-hardening.sh` installe via `dnf` les paquets
suivants si absents : `policycoreutils`, `policycoreutils-python-utils`,
`selinux-policy-targeted`, `audit`, `audispd-plugins`, `firewalld`,
`openssh-server`, `aide`, `chrony`, `libpwquality`, `authselect`.

Pour le scan CIS post-hardening (optionnel mais recommandé) :

```bash
dnf install openscap-scanner scap-security-guide
```

#### Pré-vérifications manuelles obligatoires

```bash
# 1. Vérifier la version OS
cat /etc/os-release | grep -E "^(ID|VERSION_ID)"
# Attendu : ID=ol, VERSION_ID=10.x

# 2. Vérifier l'accès réseau aux dépôts
dnf check-update --quiet && echo "Dépôts OK"

# 3. Vérifier l'espace disque disponible
df -h /var /etc /root
# Recommandé : > 2 Go libres sur /var (logs audit, AIDE DB)

# 4. Déposer une clé SSH admin AVANT le hardening
# (le script désactivera PasswordAuthentication si une clé est trouvée)
mkdir -p /root/.ssh
cat /chemin/vers/cle_pub.pub >> /root/.ssh/authorized_keys
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys

# 5. Vérifier que SELinux n'est pas désactivé via GRUB
grep "selinux=0\|enforcing=0" /proc/cmdline && echo "ALERTE : SELinux désactivé au boot"
```

---

### 8.2 Checklist de déploiement

#### Étape 1 — Préparation (avant exécution)

```bash
# Cloner le dépôt
git clone https://github.com/valorisa/oracle-linux-ultra-hardening-proof-of-concept.git
cd oracle-linux-ultra-hardening-proof-of-concept

# Rendre les scripts exécutables
chmod +x oracle-linux-ultra-hardening.sh validate-hardening.sh

# Lecture obligatoire du script avant exécution (bonne pratique)
less oracle-linux-ultra-hardening.sh
```

- [ ] Snapshot VM ou backup système réalisé
- [ ] Accès console OOB disponible et testé
- [ ] Clé SSH admin déposée dans `/root/.ssh/authorized_keys`
- [ ] Espace disque vérifié (> 2 Go sur `/var`)
- [ ] Dépôts dnf accessibles
- [ ] Version OS confirmée (OL10)

#### Étape 2 — Test à blanc (dry-run)

```bash
# Simuler sans appliquer — aucune modification du système
./oracle-linux-ultra-hardening.sh --dry-run
```

- [ ] Dry-run exécuté sans erreur
- [ ] Logs dry-run lus : `/var/log/hardening-YYYYMMDD.log`
- [ ] Phases identifiées comme pertinentes pour ce rôle (SSH/KVM/Web)

#### Étape 3 — Application du hardening

```bash
# Exécution en production
./oracle-linux-ultra-hardening.sh 2>&1 | tee /var/log/hardening-apply.log
```

- [ ] Script terminé sans erreur `[ERR]`
- [ ] Vérifier les `[WARN]` — notamment PasswordAuthentication si pas de clé
- [ ] Backups créés dans `/var/backup/hardening-YYYYMMDD-HHMMSS/`
- [ ] Log complet disponible : `/var/log/hardening-YYYYMMDD.log`

#### Étape 4 — Reboot

> **Le reboot est obligatoire** si SELinux était en mode `Disabled` avant
> l'exécution (relabeling du système de fichiers) ou pour activer les règles
> `auditd` immuables (`-e 2`).

```bash
# Vérifier si le reboot est nécessaire
[[ -f /.autorelabel ]] && echo "REBOOT REQUIS — relabeling SELinux planifié"
auditctl -s 2>/dev/null | grep -q "enabled 2" \
    || echo "REBOOT RECOMMANDÉ — règles auditd immuables actives après reboot"

# Reboot
systemctl reboot
```

- [ ] Reboot effectué
- [ ] Système redémarré sans erreur (vérifier console OOB)
- [ ] Connexion SSH rétablie avec clé (pas de mot de passe)

---

### 8.3 Actions post-reboot

#### Vérification immédiate (dans les 5 minutes)

```bash
# 1. SELinux doit être Enforcing
getenforce
# Attendu : Enforcing

# 2. Règles auditd immuables
auditctl -s | grep "enabled"
# Attendu : enabled 2

# 3. Firewall actif, zone drop
firewall-cmd --get-default-zone
# Attendu : drop

# 4. SSH accessible
ssh -o PasswordAuthentication=no root@<IP> "echo OK"
```

#### Exécution du script de validation

```bash
# Validation complète post-hardening
./validate-hardening.sh

# Le rapport est généré ici :
ls /var/log/validation-*.log | tail -1
```

- [ ] Aucun `[FAIL]` dans le rapport de validation
- [ ] Les `[WARN]` sont documentés et justifiés
- [ ] Score OpenSCAP CIS consulté (si `oscap` installé)

#### Traitement des [FAIL] courants

| [FAIL] fréquent | Cause probable | Correctif |
|-----------------|----------------|-----------|
| SELinux runtime ≠ Enforcing | SELinux était Disabled → reboot manqué | rebooter |
| Règles auditd non immuables | Reboot non effectué | rebooter |
| PasswordAuthentication = yes | Aucune clé SSH au moment du hardening | Déposer clé, relancer script |
| Base AIDE non initialisée | aide --init échoué | `aide --init && mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz` |
| chronyd stratum 16 | Pas de NTP accessible | Vérifier `/etc/chrony.conf` et réseau |

#### Maintenance continue

```bash
# Vérification hebdomadaire AIDE (ou attendre le timer systemd)
systemctl status aide-check.timer

# Mise à jour système (maintenir le hardening)
dnf update -y

# Vérification des règles SELinux (nouveaux services)
ausearch -m AVC -ts recent | grep denied

# Re-scan CIS mensuel
oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis \
  --report /var/log/scap-report-$(date +%Y%m).html \
  /usr/share/xml/scap/ssg/content/ssg-ol10-xccdf.xml
```

---

## 9. Annexes techniques

### 9.1 Architecture des scripts v3.0

Les deux scripts forment un couple hardening/validation complémentaire,
entièrement aligné sur Oracle Linux 10 (base RHEL), sans AppArmor (non supporté
nativement), sans `SELINUXTYPE=strict` (politique inexistante sur OL10) et sans
score CIS simulé.

#### `oracle-linux-ultra-hardening.sh` — 12 phases

| Phase | Action | Criticité |
|-------|--------|-----------|
| 0 | Mise à jour système + installation paquets | Obligatoire |
| 1 | SELinux enforcing/targeted, suppression domaines permissifs | Critique |
| 2 | SSH via drop-in `sshd_config.d` + garde-fou anti-lockout | Critique |
| 3 | Sysctl kernel + réseau (20+ paramètres) | Critique |
| 4 | auditd : démon + règles CIS 32/64 bits + immutabilité | Critique |
| 5 | PAM : pwquality + faillock + login.defs + UMASK 027 | Majeur |
| 6 | Firewalld zone drop (SSH/HTTP/HTTPS whitelist) | Critique |
| 7 | Services inutiles : disable + mask | Majeur |
| 8 | Chrony : synchronisation NTP | Majeur |
| 9 | KVM/sVirt conditionnel (détection VT-x/AMD-V) | Conditionnel |
| 10 | Systemd drop-in sshd (NoNewPrivileges + protect*) | Majeur |
| 11 | Permissions fichiers critiques (shadow, sudoers, root) | Critique |
| 12 | AIDE : initialisation base + timer hebdomadaire | Majeur |

#### `validate-hardening.sh` — 13 sections

| Section | Vérifie | Méthode |
|---------|---------|---------|
| 1 | SELinux runtime + persistant + domaines permissifs | `getenforce`, `sestatus`, `semanage` |
| 2 | SSH : config effective, drop-in, tous paramètres | `sshd -T` (source de vérité) |
| 3 | Sysctl : 20 paramètres kernel/réseau | `sysctl -n` par paramètre |
| 4 | auditd : actif, règles >10, immuable, watchs clés | `auditctl -s/-l` |
| 5 | PAM : pwquality, faillock, login.defs, UMASK | grep ciblés sur les fichiers |
| 6 | Firewalld : actif, zone drop/block, SSH autorisé | `firewall-cmd` |
| 7 | Services masqués : sendmail, rpcbind, avahi… | `systemctl is-enabled` |
| 8 | Chrony : actif, synchronisé (stratum < 16) | `chronyc tracking` |
| 9 | Permissions : shadow(000/640), sudoers(440), root(700)… | `stat -c "%a"` |
| 10 | KVM/sVirt : security_driver=selinux si libvirtd actif | `grep` sur `qemu.conf` |
| 11 | Systemd drop-in sshd : directives protect* présentes | `grep` sur le drop-in |
| 12 | AIDE : installé, base initialisée, timer actif | `systemctl`, fichiers |
| 13 | OpenSCAP : scan CIS réel si `oscap` + SSG disponibles | `oscap xccdf eval` |

### 9.2 Choix techniques justifiés

**Pourquoi pas AppArmor ?**  
Oracle Linux 10 est basé sur RHEL, qui utilise **SELinux** comme LSM (Linux
Security Module) exclusif. AppArmor est natif sur Ubuntu/SUSE. Tenter d'installer
AppArmor sur OL10 produit un service apparent mais sans module noyau fonctionnel —
créant une fausse sécurité. Ce dépôt n'utilise pas AppArmor.

**Pourquoi `SELINUXTYPE=targeted` et pas `strict` ?**  
La politique `strict` a été **dépréciée et supprimée** depuis RHEL 7. Sur OL10,
les seules politiques valides sont `targeted` et `mls`. Forcer `strict` rend le
système non-bootable. La politique `targeted` avec zéro domaine permissif est le
standard de production.

**Pourquoi sans `SystemCallFilter=~@privileged` sur sshd ?**  
sshd utilise PAM pour l'authentification, qui requiert des appels système
privilégiés variables selon les modules PAM installés. Un blacklist agressif peut
casser sshd silencieusement ou interrompre l'accès distant. Le jeu de directives
retenu (`NoNewPrivileges`, `ProtectKernelModules`, `RestrictRealtime`…) est validé
pour OL10 sans risque.

**Pourquoi `-e 2` (règles auditd immuables) ?**  
En mode `enabled 2`, les règles auditd ne peuvent être modifiées qu'après un
reboot. Cela empêche un attaquant ayant compromis root de désactiver l'audit pour
couvrir ses traces. C'est le niveau requis par les frameworks CIS/STIG.

---

## 10. Références

1. [SELinux Project](https://github.com/SELinuxProject)
2. [seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
3. [CIS Benchmarks Oracle Linux](https://www.cisecurity.org/benchmark/oracle_linux/)
4. [Oracle Linux 10 Security Guide](https://docs.oracle.com/en/operating-systems/oracle-linux/10/)
5. [SCAP Security Guide](https://github.com/ComplianceAsCode/content)
6. [OpenSCAP](https://www.open-scap.org/)
7. [auditd — Linux Audit Framework](https://github.com/linux-audit/audit-userspace)
8. [AIDE — Advanced Intrusion Detection Environment](https://aide.github.io/)
9. [chrony NTP](https://chrony-project.org/)
10. [The insecurity of OpenBSD — article original (2010)](https://allthatiswrong.wordpress.com/2010/01/20/the-insecurity-of-openbsd/)

---

*Ce dépôt constitue une preuve de concept opérationnelle — les scripts sont
testés et reproductibles sur Oracle Linux 10.*  
*Version scripts : v3.0 "Gold" | Dernière mise à jour : 2026-03-23*