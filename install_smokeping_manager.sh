#!/bin/bash
# ============================================================
# SmokePing Manager 5.9 - Complete All-in-One Installer
#
# Features:
#   - Interactief installatiemenu
#   - Categorieën + Targets + IPv6
#   - Probe beheer (Probes config)
#   - MultiHost grafieken (IPv4+IPv6 gecombineerd)
#   - Backup / Restore via CLI en webinterface
#   - Uptime/downtime overzicht per target
#   - Deeplinks naar SmokePing grafieken
#   - Gebruikersbeheer
#   - Volledige SmokePing config editor
#   - 4.1 - Mailprobleem met +1u extra tijd bij uitval opgelost.
#   - 4.2 - weergave uitval in grafieken verduidelijkt door rode blokken in de grafieken te tonen tijdens uitval.
#   - 4.3 - Layout grafieken verbeterd voor uitval en packetloss.
#   - 4.4 - Diverse kleine verbeteringen en bugfixes. Backup layout verbeterd, gebruikersbeheer uitgebreid, en meer.
#   - 4.5 - Loop in de installatie opgelost. 
#   - 5.0 - Grote update met veel nieuwe functies, verbeterde beveiliging, en een compleet vernieuwde webinterface.
#   - 5.1 - Mogelijkheid om link te delen met gebruiker om zelf target toe te voegen
#   - 5.2 - Snelheid van de webinterface verbeterd door caching toe te voegen aan de backend en optimalisaties in database queries.
#   - 5.3 - Email preview toegevoegd onder Admin Debug sectie.
#   - 5.4 - Layout gewijzigd, Targets wachtrij toegevoegd, en diverse kleine verbeteringen.
#   - 5.5 - Google Auth toegevoegd. Gebruikersrechten uitgebreid, en diverse kleine verbeteringen.
#   - 5.6 - Default pingtijden verlaagd zodat uitval sneller wordt gedetecteerd. Stappenplan gewijzigd en optie toegevoegd om in te loggen met Google account.
#   - 5.7 - Nieuwe gebruikers krijgen nu gebruikersrechten ipv manager  rechten. Diverse kleine verbeteringen en bugfixes.
#   - 5.8 - Bij toevoegen van nieuwe targets worden deze automatisch toegevoegd aan de wachtrij.
#   - 5.9 - Bij meerdere uitval wordt alles verzameld per target in 1 mail ipv aparte mails. Opschonen IPv6 grafieken bij opschonen RRD grafieken opgelost.
#
# Voer uit als root in je LXC-container:
#   wget -O install_smokeping_manager.sh https://charlesderidder.nl/proxmox/install_smokeping_manager.sh && chmod +x install_smokeping_manager.sh && ./install_smokeping_manager.sh
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; ORANGE='\033[0;33m'; CYAN='\033[0;36m'; NC='\033[0m'

WEBDIR="/var/www/html/smokeping-manager"
DBDIR="$WEBDIR/data"
BACKUPDIR="$WEBDIR/data/backups"
SMOKEPING_CONF_DIR="/etc/smokeping/config.d"
SMOKEPING_CONF="/etc/smokeping/config"
TARGETS_FILE="$SMOKEPING_CONF_DIR/Targets"
PROBES_FILE="$SMOKEPING_CONF_DIR/Probes"
SUDOERS_FILE="/etc/sudoers.d/smokeping-manager"
LAUNCHER_CMD="/usr/local/bin/smokepingmanager"

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}✗ Dit script moet als root worden uitgevoerd!${NC}"
    exit 1
fi

log_ts() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_info() {
    echo -e "${CYAN}[$(log_ts)]${NC} $*"
}

log_ok() {
    echo -e "${GREEN}[$(log_ts)] ✓${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[$(log_ts)] ⚠${NC} $*"
}

log_err() {
    echo -e "${RED}[$(log_ts)] ✗${NC} $*"
}

setup_notify_cron() {
    cat > /etc/cron.d/smokeping-notify << 'CRONEOF'
* * * * * www-data /usr/bin/php /var/www/html/smokeping-manager/smokeping-notify.php >> /var/log/smokeping-notify.log 2>&1
CRONEOF
    chmod 644 /etc/cron.d/smokeping-notify
    touch /var/log/smokeping-notify.log
    chown www-data:www-data /var/log/smokeping-notify.log
    chmod 644 /var/log/smokeping-notify.log
}

is_safe_tar_archive() {
    local tar_file="$1"
    local entry=""
    while IFS= read -r entry; do
        [ -z "$entry" ] && continue
        case "$entry" in
            /*|../*|*/../*|*".."*)
                return 1
                ;;
        esac
    done < <(tar tzf "$tar_file" 2>/dev/null)
    return 0
}

extract_tar_safe() {
    local tar_file="$1"
    local dest_dir="$2"
    if ! [ -f "$tar_file" ]; then
        return 1
    fi
    if ! is_safe_tar_archive "$tar_file"; then
        return 1
    fi
    tar xzf "$tar_file" -C "$dest_dir" --no-same-owner --no-same-permissions
}

show_menu() {
    clear
    echo -e "${ORANGE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${ORANGE}║${NC}            ${CYAN}SmokePing Manager 5.9 - Installer${NC}                 ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  Start na update of installatie met: ${GREEN}smokepingmanager${NC}        ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC} ${YELLOW}Installatie & Update${NC}                                         ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  1) Volledige installatie                                    ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  2) Script updaten en direct opnieuw starten                 ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  3) Alles verwijderen (clean uninstall)                      ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC} ${YELLOW}Configuratie & Data${NC}                                          ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  4) Targets herstellen (basisconfig leeg)                    ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  5) RRD bestanden wissen (grafiekdata)                       ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  6) Alle targets wissen (database + bestand)                 ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  7) Targets bestand downloaden                               ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC} ${YELLOW}Backup & Herstel${NC}                                             ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  8) Backup maken                                             ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC}  9) Backup terugzetten                                       ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC} ${YELLOW}Gebruikersbeheer${NC}                                             ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 10) Gebruikersnaam/wachtwoord wijzigen                       ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 11) Gebruikersbeheer CLI                                     ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC} ${YELLOW}SmokePing Service${NC}                                            ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 12) Restart SmokePing                                        ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 13) Reload SmokePing                                         ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 14) Status SmokePing                                         ${ORANGE}║${NC}"
    echo -e "${ORANGE}║${NC} 15) SmokePing --check                                        ${ORANGE}║${NC}"
    echo -e "${ORANGE}╠══════════════════════════════════════════════════════════════╣${NC}"
    echo -e "${ORANGE}║${NC}  0) Afsluiten                                                ${ORANGE}║${NC}"
    echo -e "${ORANGE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "Keuze [0-15]: " choice
}

pause_for_enter() {
    echo ""
    read -rp "Druk op Enter om terug te gaan naar het menu..." _
}

install_cli_launcher() {
    local script_path="${1:-$0}"
    local escaped_script_path=""

    if command -v readlink >/dev/null 2>&1; then
        script_path=$(readlink -f "$script_path" 2>/dev/null || printf '%s' "$script_path")
    fi

    printf -v escaped_script_path '%q' "$script_path"

    cat > "$LAUNCHER_CMD" <<EOF
#!/bin/bash
exec bash $escaped_script_path "\$@"
EOF
    chmod 755 "$LAUNCHER_CMD"
}

do_restart_smokeping() {
    echo -e "${YELLOW}SmokePing wordt herstart...${NC}"
    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping
    chmod 755 /run/smokeping 2>/dev/null || true
    systemd-tmpfiles --create /etc/tmpfiles.d/smokeping.conf 2>/dev/null || true
    if systemctl restart smokeping 2>/dev/null; then
        echo -e "${GREEN}✓ SmokePing succesvol herstart.${NC}"
    else
        echo -e "${RED}✗ Fout bij herstarten van SmokePing.${NC}"
    fi
}

do_reload_smokeping() {
    echo ""
    echo -e "${YELLOW}SmokePing wordt herladen...${NC}"
    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping 2>/dev/null || true
    chmod 755 /run/smokeping 2>/dev/null || true
    systemd-tmpfiles --create /etc/tmpfiles.d/smokeping.conf 2>/dev/null || true
    if systemctl reload smokeping 2>/dev/null; then
        echo -e "${GREEN}✓ SmokePing succesvol herladen.${NC}"
    else
        echo -e "${RED}✗ Fout bij herladen van SmokePing.${NC}"
    fi
}

do_status_smokeping() {
    echo ""
    echo -e "${YELLOW}Status SmokePing:${NC}"
    systemctl status smokeping --no-pager
}

do_check_smokeping() {
    echo ""
    echo -e "${YELLOW}SmokePing check uitvoeren...${NC}"
    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping 2>/dev/null || true
    chmod 755 /run/smokeping 2>/dev/null || true
    systemd-tmpfiles --create /etc/tmpfiles.d/smokeping.conf 2>/dev/null || true
    smokeping --check || true
}

ensure_smokeping_paths_and_permissions() {
    mkdir -p "$SMOKEPING_CONF_DIR"
    chown root:www-data "$SMOKEPING_CONF_DIR" 2>/dev/null || true
    chmod 2775 "$SMOKEPING_CONF_DIR" 2>/dev/null || true

    for f in "$SMOKEPING_CONF_DIR"/*; do
        [ -f "$f" ] || continue
        chown root:www-data "$f" 2>/dev/null || true
        chmod 664 "$f" 2>/dev/null || true
    done

    [ -f "$TARGETS_FILE" ] || touch "$TARGETS_FILE"
    [ -f "$PROBES_FILE" ] || touch "$PROBES_FILE"
    chown root:www-data "$TARGETS_FILE" "$PROBES_FILE" 2>/dev/null || true
    chmod 664 "$TARGETS_FILE" "$PROBES_FILE" 2>/dev/null || true

    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping 2>/dev/null || true
    chmod 755 /run/smokeping 2>/dev/null || true
    echo "d /run/smokeping 0755 smokeping smokeping -" > /etc/tmpfiles.d/smokeping.conf
    systemd-tmpfiles --create /etc/tmpfiles.d/smokeping.conf 2>/dev/null || true

    mkdir -p /var/log/smokeping
    chown smokeping:smokeping /var/log/smokeping 2>/dev/null || true
    chmod 755 /var/log/smokeping 2>/dev/null || true

    [ -f "$SMOKEPING_CONF" ] && chmod 644 "$SMOKEPING_CONF" 2>/dev/null || true

    # Presentation config: activeer loss_background voor volledige uitvalbalk en nodata_color voor 100% verlies
    local PRES_FILE="$SMOKEPING_CONF_DIR/Presentation"
    if [ -f "$PRES_FILE" ] && ! grep -q "loss_background" "$PRES_FILE"; then
        awk '/^[+] detail$/{print; print "loss_background = yes"; print "nodata_color = ffffff"; next}1' "$PRES_FILE" > "${PRES_FILE}.tmp" && mv "${PRES_FILE}.tmp" "$PRES_FILE"
        chown root:www-data "$PRES_FILE" 2>/dev/null || true
        chmod 664 "$PRES_FILE" 2>/dev/null || true
    fi
}

apply_php_upload_limits() {
    local upload_limit="${1:-50M}"
    local post_limit="${2:-64M}"
    local applied=0
    local conf_dir=""

    for conf_dir in /etc/php/*/apache2/conf.d; do
        [ -d "$conf_dir" ] || continue
        cat > "$conf_dir/99-smokeping-manager-upload.ini" <<EOF
; Managed by SmokePing Manager installer
upload_max_filesize = ${upload_limit}
post_max_size = ${post_limit}
EOF
        applied=1
    done

    if [ "$applied" -eq 1 ]; then
        log_ok "PHP uploadlimieten ingesteld (upload_max_filesize=${upload_limit}, post_max_size=${post_limit})"
        return 0
    fi

    log_warn "Geen Apache PHP conf.d pad gevonden; uploadlimieten niet automatisch ingesteld"
    return 1
}

show_smokeping_commands_menu() {
    while true; do
        clear
        echo "=== SmokePing Commands ==="
        echo "1) Restart SmokePing"
        echo "2) Reload SmokePing"
        echo "3) Status SmokePing"
        echo "4) SmokePing --check"
        echo "0) Terug"
        read -rp "Keuze [0-4]: " sc
        case "$sc" in
            1) do_restart_smokeping; read -rp "Druk op Enter..." ;; 
            2) do_reload_smokeping; read -rp "Druk op Enter..." ;; 
            3) do_status_smokeping; read -rp "Druk op Enter..." ;; 
            4) do_check_smokeping; read -rp "Druk op Enter..." ;; 
            0) break ;;
            *) echo "Ongeldige keuze."; sleep 1 ;;
        esac
    done
}

do_install() {
    local KEEP_DB="$1"
    local REQUIRED_PACKAGES=(apache2 php php-sqlite3 libapache2-mod-php sqlite3 sudo rrdtool)
    local MISSING_PACKAGES=()
    local pkg
    echo ""
    log_info "[1/8] Systeem controleren en package bronnen verversen..."
    apt-get -o Acquire::Retries=3 update

    for pkg in "${REQUIRED_PACKAGES[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            MISSING_PACKAGES+=("$pkg")
        fi
    done

    if [ "${#MISSING_PACKAGES[@]}" -gt 0 ]; then
        log_info "[2/8] Ontbrekende pakketten installeren: ${MISSING_PACKAGES[*]}"
        apt-get install -y --no-install-recommends "${MISSING_PACKAGES[@]}"
        log_ok "Pakketten geïnstalleerd"
    else
        log_ok "Alle vereiste pakketten waren al aanwezig"
    fi

    log_info "[3/8] Apache modules activeren..."
    a2enmod php* > /dev/null 2>&1 || true
    a2enmod rewrite > /dev/null 2>&1 || true
    log_ok "Modules actief"

    log_info "[4/8] Directories voorbereiden..."
    mkdir -p "$WEBDIR" "$DBDIR" "$BACKUPDIR"
    log_ok "Directories aangemaakt"

    log_info "[5/8] Webapp bestanden deployen..."
    deploy_php
    log_ok "index.php gedeployd"

    log_info "[6/8] Command launcher installeren..."
    install_cli_launcher "$0"
    log_ok "Startcommando beschikbaar als 'smokepingmanager'"

    log_info "[7/8] Rechten en paden instellen..."
    chown -R www-data:www-data "$WEBDIR"
    chmod 755 "$WEBDIR"
    chmod 644 "$WEBDIR/index.php"
    chmod 750 "$DBDIR"
    chmod 750 "$BACKUPDIR"
    cat > "$DBDIR/.htaccess" << 'EOF'
Deny from all
EOF
    chown www-data:www-data "$DBDIR/.htaccess"

    if [ "$KEEP_DB" != "keep" ]; then
        [ -f "$DBDIR/smokeping_manager.db" ] && mv "$DBDIR/smokeping_manager.db" "$DBDIR/smokeping_manager.db.bak.$(date +%s)"
    fi

    ensure_smokeping_paths_and_permissions
    log_ok "Rechten ingesteld"

    log_info "[8/8] Service-hulpscripts, Sudoers en cron configureren..."
    # Create RRD helper script voor PHP
    cat > /usr/local/bin/smokeping-clear-rrd << 'RRDSCRIPT'
#!/bin/bash
# Clear RRD files for SmokePing with different scopes
RRDDIR="/var/lib/smokeping"
SCOPE="$1"
CATNAME="$2"
TGTNAME="$3"

case "$SCOPE" in
    all)
        find "$RRDDIR" -name "*.rrd" -type f -delete 2>/dev/null
        ;;
    category)
        if [ -n "$CATNAME" ] && [ -d "$RRDDIR/$CATNAME" ]; then
            find "$RRDDIR/$CATNAME" -name "*.rrd" -type f -delete 2>/dev/null
        fi
        ;;
    target)
        if [ -n "$CATNAME" ] && [ -n "$TGTNAME" ]; then
            rm -f "$RRDDIR/$CATNAME/$TGTNAME.rrd" 2>/dev/null
        fi
        ;;
esac
RRDSCRIPT
    chmod 755 /usr/local/bin/smokeping-clear-rrd
    
    cat > "$SUDOERS_FILE" << 'EOF'
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl stop smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl start smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl status smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/smokeping --check
www-data ALL=(ALL) NOPASSWD: /usr/local/bin/smokeping-reset-rrd
www-data ALL=(ALL) NOPASSWD: /usr/local/bin/smokeping-clear-rrd
EOF
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE" > /dev/null 2>&1 && log_ok "Sudoers OK" || log_err "Sudoers fout"

    log_info "Cron job voor sessie- en uitval-notificaties aanmaken..."
    deploy_notify_php
    chown www-data:www-data "$WEBDIR/smokeping-notify.php"
    chmod 640 "$WEBDIR/smokeping-notify.php"
    setup_notify_cron
    log_ok "Cron job geïnstalleerd (/etc/cron.d/smokeping-notify)"

    log_info "FPing6 probe en /run/smokeping controleren..."
    ensure_fping6_probe
    # Zorg dat /run/smokeping bestaat (wordt gewist bij reboot)
    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping
    # Maak persistent via tmpfiles.d zodat het na reboot ook bestaat
    echo "d /run/smokeping 0755 smokeping smokeping -" > /etc/tmpfiles.d/smokeping.conf
    log_ok "Probes en /run/smokeping gecontroleerd"

    log_info "PHP uploadlimieten instellen op 50MB..."
    apply_php_upload_limits "50M" "64M" || true

    log_info "Apache herstarten..."
    if systemctl restart apache2; then
        log_ok "Apache herstart"
    else
        log_err "Apache herstart mislukt"
    fi

    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${ORANGE}════════════════════════════════════════════${NC}"
    echo -e "${GREEN} ✓ SmokePing Manager 5.9 geïnstalleerd!${NC}"
    echo -e "${ORANGE}════════════════════════════════════════════${NC}"
    echo -e " URL:   ${YELLOW}http://${IP}/smokeping-manager/${NC}"
    echo -e " Login: ${YELLOW}admin${NC} / ${YELLOW}admin${NC}"
    echo -e " ${RED}⚠  Wijzig het wachtwoord direct na eerste login!${NC}"
    echo -e " Start: ${YELLOW}smokepingmanager${NC}"
    echo -e "${ORANGE}════════════════════════════════════════════${NC}"
}

do_update() {
    SCRIPT_PATH="$0"
    SCRIPT_NAME=$(basename "$SCRIPT_PATH")
    TEMP_SCRIPT="/tmp/${SCRIPT_NAME}.new"
    TEMP_HASH="/tmp/${SCRIPT_NAME}.sha256"
    BACKUP_SCRIPT="${SCRIPT_PATH}.bak.$(date +%Y%m%d_%H%M%S)"
    REMOTE_URL="https://charlesderidder.nl/proxmox/install_smokeping_manager.sh"
    
    echo ""
    log_info "SmokePing Manager script bijwerken..."
    
    if wget --progress=bar:force:noscroll -O "$TEMP_SCRIPT" "$REMOTE_URL"; then
        log_ok "Script gedownload"
    else
        log_err "Download mislukt. Controleer internetverbinding."
        rm -f "$TEMP_SCRIPT" "$TEMP_HASH"
        return 1
    fi

    if wget -q -O "$TEMP_HASH" "${REMOTE_URL}.sha256"; then
        local expected got
        expected=$(awk '{print $1}' "$TEMP_HASH" | head -n1)
        got=$(sha256sum "$TEMP_SCRIPT" | awk '{print $1}')
        if [ -n "$expected" ] && [ "$expected" != "$got" ]; then
            log_err "Checksum controle mislukt. Update afgebroken."
            rm -f "$TEMP_SCRIPT" "$TEMP_HASH"
            return 1
        fi
        log_ok "Checksum gecontroleerd"
    else
        log_warn "Geen .sha256 bestand gevonden; update gaat door zonder checksumcontrole"
    fi

    chmod +x "$TEMP_SCRIPT"
    if ! bash -n "$TEMP_SCRIPT" >/dev/null 2>&1; then
        log_err "Nieuw script heeft syntaxfouten. Update afgebroken."
        rm -f "$TEMP_SCRIPT" "$TEMP_HASH"
        return 1
    fi

    if cp -a "$SCRIPT_PATH" "$BACKUP_SCRIPT"; then
        log_ok "Rollback-backup gemaakt: $BACKUP_SCRIPT"
    else
        log_err "Kon geen rollback-backup maken. Update afgebroken."
        rm -f "$TEMP_SCRIPT" "$TEMP_HASH"
        return 1
    fi

    if mv "$TEMP_SCRIPT" "$SCRIPT_PATH"; then
        log_ok "Script bijgewerkt"
    else
        log_err "Kan script niet vervangen"
        rm -f "$TEMP_SCRIPT" "$TEMP_HASH"
        return 1
    fi

    install_cli_launcher "$SCRIPT_PATH"
    log_ok "Startcommando bijgewerkt: smokepingmanager"

    log_info "Nieuwe versie valideren en webbestanden deployen..."
    if bash "$SCRIPT_PATH" --deploy-only >/dev/null 2>&1; then
        log_ok "Webbestanden overschreven"
    else
        log_warn "Deploy faalde; script wordt teruggezet naar rollback"
        cp -a "$BACKUP_SCRIPT" "$SCRIPT_PATH"
        chmod +x "$SCRIPT_PATH"
        rm -f "$TEMP_HASH"
        return 1
    fi
        
    rm -f "$TEMP_HASH"
    echo ""
    log_info "Nieuwe versie wordt gestart..."
    sleep 1
    exec "$SCRIPT_PATH"
}

ensure_fping6_probe() {
    if [ -f "$PROBES_FILE" ]; then
        if ! grep -q 'FPing6' "$PROBES_FILE"; then
            # Voeg FPing6 toe aan bestaand Probes bestand
            if grep -q '^\*\*\* Probes \*\*\*' "$PROBES_FILE"; then
                echo "" >> "$PROBES_FILE"
                echo "+ FPing6" >> "$PROBES_FILE"
                echo "binary = /usr/bin/fping" >> "$PROBES_FILE"
                echo "" >> "$PROBES_FILE"
            fi
            echo -e "${GREEN}  ✓ FPing6 probe toegevoegd aan Probes bestand${NC}"
        fi
    fi
}

do_uninstall() {
    echo ""
    read -rp "Weet je zeker dat je ALLES wilt verwijderen? (ja/nee): " confirm
    if [ "$confirm" = "ja" ]; then
        rm -rf "$WEBDIR"
        rm -f "$SUDOERS_FILE"
        rm -f /usr/local/bin/smokeping-reset-rrd
        rm -f "$LAUNCHER_CMD"
        echo -e "${GREEN}✓ SmokePing Manager volledig verwijderd.${NC}"
        echo -e "${YELLOW}  SmokePing zelf en config bestanden zijn NIET verwijderd.${NC}"
    else
        echo "Geannuleerd."
    fi
}

do_clear_targets() {
    echo ""
    read -rp "Targets bestand leeg maken en InstellingenConfig overschrijven? Dit verwijdert alle targets! (ja/nee): " confirm
    if [ "$confirm" = "ja" ]; then
        cat > "$TARGETS_FILE" << 'EOF'
*** Targets ***

probe = FPing
menu = Top
title = Netwerk Latency Monitor
remark = Beheerd via SmokePing Manager
EOF
        chown root:www-data "$TARGETS_FILE"
        chmod 664 "$TARGETS_FILE"
        mkdir -p /run/smokeping && chown smokeping:smokeping /run/smokeping
        systemctl restart smokeping 2>/dev/null || true
        echo -e "${GREEN}✓ Targets bestand geleegd en SmokePing herstart.${NC}"
        
        echo -e "${YELLOW}Info: je kunt nu targets toevoegen of een bestaand Targets bestand importeren.${NC}"
    else
        echo "Geannuleerd."
    fi
}

do_backup() {
    local STAMP=$(date +%Y%m%d_%H%M%S)
    local BDIR="$BACKUPDIR/backup_$STAMP"
    mkdir -p "$BDIR"
    # Config bestanden
    cp -a "$SMOKEPING_CONF_DIR"/* "$BDIR/" 2>/dev/null || true
    [ -f "$SMOKEPING_CONF" ] && cp "$SMOKEPING_CONF" "$BDIR/"
    # Database
    [ -f "$DBDIR/smokeping_manager.db" ] && cp "$DBDIR/smokeping_manager.db" "$BDIR/"
    # RRD data
    tar czf "$BDIR/rrd_data.tar.gz" -C /var/lib/smokeping . 2>/dev/null || true
    chown -R www-data:www-data "$BDIR"
    echo -e "${GREEN}✓ Backup gemaakt: $BDIR${NC}"
    ls -la "$BDIR"
}

do_restore() {
    echo ""
    echo "Beschikbare backups:"
    ls -1d "$BACKUPDIR"/backup_* 2>/dev/null || { echo "Geen backups gevonden."; return; }
    echo ""
    read -rp "Volledige padnaam van backup: " bpath
    if [ -d "$bpath" ]; then
        # Config bestanden terugzetten
        for f in "$bpath"/*.cfg "$bpath"/Targets "$bpath"/Probes "$bpath"/Database "$bpath"/General "$bpath"/Alerts "$bpath"/Presentation "$bpath"/config; do
            [ -f "$f" ] && cp "$f" "$SMOKEPING_CONF_DIR/" 2>/dev/null
        done
        # Database
        [ -f "$bpath/smokeping_manager.db" ] && cp "$bpath/smokeping_manager.db" "$DBDIR/"
        # RRD
        if [ -f "$bpath/rrd_data.tar.gz" ]; then
            if extract_tar_safe "$bpath/rrd_data.tar.gz" /var/lib/smokeping/; then
                log_ok "RRD archief veilig uitgepakt"
            else
                log_warn "RRD archief overgeslagen: onveilig of ongeldig tarbestand"
            fi
        fi
        chown -R www-data:www-data "$WEBDIR"
        for f in "$SMOKEPING_CONF_DIR"/*; do chown root:www-data "$f"; chmod 664 "$f"; done
        chown -R smokeping:smokeping /var/lib/smokeping/
        mkdir -p /run/smokeping && chown smokeping:smokeping /run/smokeping
        systemctl restart smokeping 2>/dev/null || true
        echo -e "${GREEN}✓ Backup hersteld en SmokePing herstart.${NC}"
    else
        echo -e "${RED}Pad niet gevonden.${NC}"
    fi
}

do_clear_rrd() {
    echo ""
    echo -e "${YELLOW}⚠️  Dit verwijdert ALLE RRD bestanden en grafiekhistorie!${NC}"
    read -rp "Weet je zeker dat je alle RRD bestanden wilt verwijderen? (ja/nee): " confirm
    if [ "$confirm" = "ja" ]; then
        echo -e "${YELLOW}SmokePing wordt gestopt...${NC}"
        systemctl stop smokeping 2>/dev/null || true
        sleep 1
        
        echo -e "${YELLOW}RRD bestanden worden verwijderd...${NC}"
        if [ -d "/var/lib/smokeping" ]; then
            find /var/lib/smokeping -name "*.rrd" -type f -delete
            echo -e "${GREEN}✓ RRD bestanden verwijderd${NC}"
        else
            echo -e "${YELLOW}⚠️  /var/lib/smokeping directory niet gevonden${NC}"
        fi
        
        sleep 1
        echo -e "${YELLOW}SmokePing wordt gestart...${NC}"
        mkdir -p /run/smokeping
        chown smokeping:smokeping /run/smokeping
        systemctl start smokeping 2>/dev/null || true
        sleep 2
        
        if systemctl is-active --quiet smokeping; then
            echo -e "${GREEN}✓ SmokePing succesvol herstart. Grafiekdata is gewist!${NC}"
        else
            echo -e "${RED}✗ Fout bij herstarten van SmokePing.${NC}"
        fi
    else
        echo "Geannuleerd."
    fi
}

do_change_creds() {
    if [ ! -f "$DBDIR/smokeping_manager.db" ]; then
        echo -e "${RED}Database niet gevonden. Installeer eerst.${NC}"
        return
    fi
    echo ""
    read -rp "Nieuwe gebruikersnaam (leeg = behouden): " newuser
    read -rsp "Nieuw wachtwoord: " newpass
    echo ""
    if [ -n "$newpass" ]; then
        HASH=$(php -r "echo password_hash('$newpass', PASSWORD_BCRYPT);")
        if [ -n "$newuser" ]; then
            sqlite3 "$DBDIR/smokeping_manager.db" "UPDATE users SET username='$newuser', password='$HASH' WHERE id=1;"
            echo -e "${GREEN}✓ Gebruikersnaam en wachtwoord gewijzigd.${NC}"
        else
            sqlite3 "$DBDIR/smokeping_manager.db" "UPDATE users SET password='$HASH' WHERE id=1;"
            echo -e "${GREEN}✓ Wachtwoord gewijzigd.${NC}"
        fi
    else
        echo "Geen wijzigingen."
    fi
}

do_manage_users() {
    if [ ! -f "$DBDIR/smokeping_manager.db" ]; then
        echo -e "${RED}Database niet gevonden. Installeer eerst.${NC}"
        return
    fi
    
    while true; do
        clear
        echo -e "${ORANGE}════════════════════════════════════════════${NC}"
        echo -e "${CYAN}👥 Gebruikersbeheer${NC}"
        echo -e "${ORANGE}════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${YELLOW}Huidige gebruikers:${NC}"
        sqlite3 "$DBDIR/smokeping_manager.db" "SELECT id, username, role FROM users ORDER BY id;" | while IFS='|' read id user role; do
            echo -e "  ${id}. ${user} ${YELLOW}(${role})${NC}"
        done
        echo ""
        echo "1) Gebruiker toevoegen"
        echo "2) Gebruiker wachtwoord wijzigen"
        echo "3) Gebruiker rol wijzigen"
        echo "4) Gebruiker verwijderen"
        echo "0) Terug"
        echo ""
        read -rp "Keuze [0-4]: " userchoice
        
        case "$userchoice" in
            1)
                echo ""
                read -rp "Gebruikersnaam: " newuser
                read -rsp "Wachtwoord: " newpass
                echo ""
                read -rp "Rol (admin/manager/user/readonly) [user]: " newrole
                newrole=${newrole:-user}
                
                if ! echo "$newuser" | grep -q '^[a-zA-Z0-9_]*$' || [ ${#newuser} -lt 3 ]; then
                    echo -e "${RED}✗ Ongeldige gebruikersnaam (min. 3 alfanumerieke tekens)${NC}"
                    sleep 2
                    continue
                fi
                
                if [ ${#newpass} -lt 6 ]; then
                    echo -e "${RED}✗ Wachtwoord moet min. 6 tekens zijn${NC}"
                    sleep 2
                    continue
                fi
                
                if ! echo "$newrole" | grep -q '^admin\|manager\|user\|readonly$'; then
                    echo -e "${RED}✗ Ongeldige rol. Gebruik: admin, manager, user of readonly${NC}"
                    sleep 2
                    continue
                fi
                
                HASH=$(php -r "echo password_hash('$newpass', PASSWORD_BCRYPT);")
                sqlite3 "$DBDIR/smokeping_manager.db" "INSERT INTO users(username, password, role) VALUES('$newuser', '$HASH', '$newrole');" 2>/dev/null
                if [ $? -eq 0 ]; then
                    echo -e "${GREEN}✓ Gebruiker '$newuser' toegevoegd met rol '$newrole'${NC}"
                else
                    echo -e "${RED}✗ Fout: gebruiker bestaat waarschijnlijk al${NC}"
                fi
                read -rp "Druk op Enter..." ;;
            2)
                echo ""
                read -rp "User ID: " userid
                read -rsp "Nieuw wachtwoord: " newpass
                echo ""
                if [ ${#newpass} -lt 6 ]; then
                    echo -e "${RED}✗ Wachtwoord moet min. 6 tekens zijn${NC}"
                    sleep 2
                    continue
                fi
                HASH=$(php -r "echo password_hash('$newpass', PASSWORD_BCRYPT);")
                sqlite3 "$DBDIR/smokeping_manager.db" "UPDATE users SET password='$HASH' WHERE id=$userid;"
                echo -e "${GREEN}✓ Wachtwoord bijgewerkt${NC}"
                read -rp "Druk op Enter..." ;;
            3)
                echo ""
                read -rp "User ID: " userid
                read -rp "Nieuwe rol (admin/manager/readonly): " newrole
                if ! echo "$newrole" | grep -q '^admin\|manager\|readonly$'; then
                    echo -e "${RED}✗ Ongeldige rol${NC}"
                    sleep 2
                    continue
                fi
                sqlite3 "$DBDIR/smokeping_manager.db" "UPDATE users SET role='$newrole' WHERE id=$userid;"
                echo -e "${GREEN}✓ Rol bijgewerkt${NC}"
                read -rp "Druk op Enter..." ;;
            4)
                echo ""
                read -rp "User ID om te verwijderen: " userid
                read -rp "Bevestig (typ 'ja'): " confirm
                if [ "$confirm" = "ja" ]; then
                    sqlite3 "$DBDIR/smokeping_manager.db" "DELETE FROM users WHERE id=$userid;"
                    echo -e "${GREEN}✓ Gebruiker verwijderd${NC}"
                else
                    echo "Geannuleerd."
                fi
                read -rp "Druk op Enter..." ;;
            0) break ;;
            *) echo "Ongeldige keuze"; sleep 1 ;;
        esac
    done
}

do_wipe_all_targets() {
    echo ""
    echo -e "${RED}⚠️  WAARSCHUWING: Dit zal ALLE targets verwijderen!${NC}"
    read -rp "Type 'ja' om te bevestigen: " confirm
    if [ "$confirm" != "ja" ]; then
        echo "Geannuleerd."
        return
    fi
    
    echo -e "${YELLOW}Backup maken...${NC}"
    cp "$TARGETS_FILE" "$TARGETS_FILE.wipe_backup_$(date +%s)" 2>/dev/null || true
    
    echo -e "${YELLOW}Alle targets verwijderen uit database...${NC}"
    if [ -f "$DBDIR/smokeping_manager.db" ]; then
        sqlite3 "$DBDIR/smokeping_manager.db" << 'SQLEOF'
DELETE FROM targets;
DELETE FROM categories;
DELETE FROM target_outages;
SQLEOF
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Database opgeschoond${NC}"
        else
            echo -e "${RED}✗ Fout bij verwijderen uit database${NC}"
            return 1
        fi
    fi
    
    echo -e "${YELLOW}RRD bestanden wissen...${NC}"
    if [ -d "/var/lib/smokeping" ]; then
        find /var/lib/smokeping -name "*.rrd" -type f -delete 2>/dev/null
        echo -e "${GREEN}✓ RRD bestanden verwijderd${NC}"
    fi
    
    echo -e "${YELLOW}Targets bestand resetten...${NC}"
    cat > "$TARGETS_FILE" << 'EOF'
*** Targets ***

probe = FPing
menu = Top
title = Netwerk Latency Monitor
remark = Beheerd via SmokePing Manager
EOF
    chown root:www-data "$TARGETS_FILE"
    chmod 664 "$TARGETS_FILE"
    
    echo -e "${YELLOW}SmokePing herstarten...${NC}"
    mkdir -p /run/smokeping && chown smokeping:smokeping /run/smokeping
    systemctl restart smokeping 2>/dev/null || true
    
    echo -e "${GREEN}✓ Alle targets gewist. SmokePing herstart.${NC}"
    echo -e "${YELLOW}Info: er zijn nu geen targets zichtbaar totdat je nieuwe targets toevoegt of importeert.${NC}"
}

do_download_targets() {
    echo ""
    if [ ! -f "$TARGETS_FILE" ]; then
        echo -e "${RED}✗ Targets bestand niet gevonden: $TARGETS_FILE${NC}"
        return 1
    fi
    
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    DOWNLOAD_DIR="$WEBDIR/downloads"
    DOWNLOAD_NAME="Targets_${TIMESTAMP}.backup"
    DOWNLOAD_FILE="$DOWNLOAD_DIR/$DOWNLOAD_NAME"
    HOST_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    HOST_IP=${HOST_IP:-127.0.0.1}
    
    echo -e "${YELLOW}Targets bestand kopiëren naar...${NC}"
    mkdir -p "$DOWNLOAD_DIR"
    chown www-data:www-data "$DOWNLOAD_DIR"
    chmod 755 "$DOWNLOAD_DIR"
    cp "$TARGETS_FILE" "$DOWNLOAD_FILE"
    chown www-data:www-data "$DOWNLOAD_FILE"
    chmod 644 "$DOWNLOAD_FILE"
    
    if [ -f "$DOWNLOAD_FILE" ]; then
        echo -e "${GREEN}✓ Bestand gereed voor download${NC}"
        echo ""
        echo "Download locatie:"
        echo -e "${CYAN}  $DOWNLOAD_FILE${NC}"
        echo ""
        echo "Directe download URL:"
        echo -e "${CYAN}  http://${HOST_IP}/smokeping-manager/downloads/${DOWNLOAD_NAME}${NC}"
        echo ""
        echo "Via SCP vanaf je computer:"
        echo -e "${CYAN}  scp root@${HOST_IP}:${DOWNLOAD_FILE} ~/${DOWNLOAD_NAME}${NC}"
        echo ""
        if [ -f "$DBDIR/smokeping_manager.db" ]; then
            DB_TARGETS=$(sqlite3 "$DBDIR/smokeping_manager.db" "SELECT COUNT(*) FROM targets;" 2>/dev/null || echo 0)
            if [ "$DB_TARGETS" = "0" ]; then
                echo -e "${YELLOW}Let op: er staan momenteel 0 targets in de database.${NC}"
                echo -e "${YELLOW}Gebruik optie 4 om targets opnieuw in te laden.${NC}"
            fi
        fi
        echo ""
        ls -lh "$DOWNLOAD_FILE"
    else
        echo -e "${RED}✗ Fout bij kopiëren van Targets bestand${NC}"
        return 1
    fi
}

deploy_notify_php() {
cat > "$WEBDIR/smokeping-notify.php" << 'ENDOFNOTIFYPHP'
<?php
// smokeping-notify.php — standalone cron script voor sessie- en uitvalnotificaties
// Draait elke minuut via /etc/cron.d/smokeping-notify als www-data
if (php_sapi_name() !== 'cli') { http_response_code(403); exit; }
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
$tz = trim((string)@file_get_contents('/etc/timezone'));
if ($tz === '') $tz = 'Europe/Amsterdam';
@date_default_timezone_set($tz);

define('DB_PATH',           __DIR__ . '/data/smokeping_manager.db');
define('BACKUP_DIR',        __DIR__ . '/data/backups');
define('SMOKEPING_CONF_DIR', '/etc/smokeping/config.d');
define('SMOKEPING_DATA_DIR', '/var/lib/smokeping');

define('SECRET_KEY_FILE',   __DIR__ . '/data/.secret_key');

function smGetOrCreateSecretKey(): string {
    $f = SECRET_KEY_FILE;
    if (is_file($f)) { $k = trim((string)@file_get_contents($f)); if (strlen($k) === 64) return $k; }
    $k = bin2hex(random_bytes(32));
    @file_put_contents($f, $k); @chmod($f, 0600);
    return $k;
}
function smEncryptPassword(string $plain): string {
    if ($plain === '') return '';
    $key = hex2bin(smGetOrCreateSecretKey());
    $iv = random_bytes(16);
    $cipher = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $cipher !== false ? 'enc:' . base64_encode($iv . $cipher) : $plain;
}
function smDecryptPassword(string $stored): string {
    if ($stored === '' || strpos($stored, 'enc:') !== 0) return $stored;
    $key = hex2bin(smGetOrCreateSecretKey());
    $raw = base64_decode(substr($stored, 4));
    if ($raw === false || strlen($raw) < 17) return '';
    $plain = openssl_decrypt(substr($raw, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    return $plain !== false ? $plain : '';
}

function getDB(): SQLite3 {
    $db = new SQLite3(DB_PATH);
    $db->busyTimeout(5000);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('CREATE TABLE IF NOT EXISTS email_settings (
        id INTEGER PRIMARY KEY, smtp_enabled INTEGER DEFAULT 0, smtp_host TEXT DEFAULT "",
        smtp_port INTEGER DEFAULT 587, smtp_encryption TEXT DEFAULT "tls", smtp_username TEXT DEFAULT "",
        smtp_password TEXT DEFAULT "", smtp_from_email TEXT DEFAULT "", smtp_from_name TEXT DEFAULT "SmokePing Manager",
        alert_enabled INTEGER DEFAULT 0, alert_targets TEXT DEFAULT "all", alert_threshold INTEGER DEFAULT 95,
        alert_interval_minutes INTEGER DEFAULT 15, mail_threshold REAL DEFAULT 5.0,
        alert_recipients TEXT DEFAULT "", updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS target_ping_loss_events (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL,
        sample_ts INTEGER NOT NULL,
        loss_fraction REAL NOT NULL,
        is_full_loss INTEGER DEFAULT 0,
        notified INTEGER DEFAULT 0,
        notified_at DATETIME DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE,
        UNIQUE(target_id, sample_ts)
    )');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_ping_loss_target_sample ON target_ping_loss_events(target_id, sample_ts DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_ping_loss_notified ON target_ping_loss_events(notified, target_id, sample_ts)');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (
        k TEXT PRIMARY KEY, v TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS mail_log (id INTEGER PRIMARY KEY, type TEXT DEFAULT "notification", target_name TEXT DEFAULT "", email_to TEXT DEFAULT "", subject TEXT DEFAULT "", status TEXT DEFAULT "failed", message TEXT DEFAULT "", debug_output TEXT DEFAULT "", body TEXT DEFAULT "", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN ping_loss_notifications INTEGER DEFAULT 0'); } catch (\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN outage_mail_interval INTEGER DEFAULT NULL'); } catch (\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN last_outage_notified_at DATETIME DEFAULT NULL'); } catch (\Exception $e) {}
    try { $db->exec('ALTER TABLE mail_log ADD COLUMN body TEXT DEFAULT ""'); } catch (\Exception $e) {}
    $c = $db->querySingle('SELECT COUNT(*) FROM email_settings');
    if ((int)$c === 0) $db->exec('INSERT INTO email_settings (id) VALUES (1)');
    return $db;
}
function getSetting($db, $k, $d = '') {
    $s = $db->prepare('SELECT v FROM settings WHERE k=:k');
    $s->bindValue(':k', $k);
    $r = $s->execute()->fetchArray(SQLITE3_ASSOC);
    return $r ? (string)$r['v'] : $d;
}
function setSetting($db, $k, $v) {
    $s = $db->prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(:k,:v)');
    $s->bindValue(':k', $k); $s->bindValue(':v', $v); $s->execute();
}
function removeDirectoryRecursive(string $path): bool {
    if ($path === '' || !file_exists($path)) return true;
    if (is_file($path) || is_link($path)) return @unlink($path);
    foreach (scandir($path) ?: [] as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $full = $path . '/' . $entry;
        if (is_dir($full) && !is_link($full)) {
            if (!removeDirectoryRecursive($full)) return false;
        } else {
            if (!@unlink($full)) return false;
        }
    }
    return @rmdir($path);
}
function createFullBackup(string $reason = 'manual'): array {
    if (!@mkdir(BACKUP_DIR, 0750, true) && !is_dir(BACKUP_DIR)) {
        return ['success' => false, 'msg' => 'Kon backup directory niet aanmaken.'];
    }
    $safeReason = preg_replace('/[^a-z0-9_]+/i', '_', strtolower(trim($reason)));
    $suffix = $safeReason !== '' ? '_' . trim($safeReason, '_') : '';
    $name = 'backup_' . date('Ymd_His') . $suffix;
    $dir = BACKUP_DIR . '/' . $name;
    if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
        return ['success' => false, 'msg' => 'Kon backup directory niet aanmaken.'];
    }
    foreach (glob(SMOKEPING_CONF_DIR . '/*') ?: [] as $file) {
        if (is_file($file)) @copy($file, $dir . '/' . basename($file));
    }
    if (file_exists(DB_PATH)) @copy(DB_PATH, $dir . '/smokeping_manager.db');
    @exec('tar czf ' . escapeshellarg($dir . '/rrd_data.tar.gz') . ' -C ' . escapeshellarg(SMOKEPING_DATA_DIR) . ' . 2>/dev/null');
    return ['success' => true, 'msg' => 'Backup gemaakt: ' . $name, 'name' => $name, 'dir' => $dir];
}
function getAutoBackupSettings($db): array {
    return [
        'enabled' => getSetting($db, 'auto_backup_enabled', '0') === '1',
        'frequency' => getSetting($db, 'auto_backup_frequency', 'daily'),
        'keep_latest' => max(1, (int)getSetting($db, 'auto_backup_keep_latest', '10')),
        'retain_daily' => max(0, (int)getSetting($db, 'auto_backup_retain_daily', '14')),
        'retain_weekly' => max(0, (int)getSetting($db, 'auto_backup_retain_weekly', '8')),
        'retain_monthly' => max(0, (int)getSetting($db, 'auto_backup_retain_monthly', '6')),
        'last_period_key' => getSetting($db, 'auto_backup_last_period_key', ''),
        'last_run_at' => getSetting($db, 'auto_backup_last_run_at', ''),
        'last_result' => getSetting($db, 'auto_backup_last_result', ''),
    ];
}
function autoBackupPeriodKey(string $frequency, ?int $ts = null): string {
    $ts = $ts ?? time();
    if ($frequency === 'weekly') return date('o-\\WW', $ts);
    if ($frequency === 'monthly') return date('Y-m', $ts);
    return date('Y-m-d', $ts);
}
function listAutoFullBackupDirs(): array {
    $dirs = [];
    foreach (glob(BACKUP_DIR . '/backup_*_auto_*') ?: [] as $dir) {
        if (!is_dir($dir)) continue;
        $dirs[] = ['path' => $dir, 'name' => basename($dir), 'mtime' => (int)@filemtime($dir)];
    }
    usort($dirs, static function ($a, $b) {
        return ($b['mtime'] <=> $a['mtime']);
    });
    return $dirs;
}
function pruneAutoFullBackups(array $cfg): array {
    $dirs = listAutoFullBackupDirs();
    if (empty($dirs)) return ['removed' => 0, 'kept' => 0];

    $keep = [];
    $weeklyBuckets = [];
    $monthlyBuckets = [];
    $now = time();
    $latestCount = max(1, (int)$cfg['keep_latest']);
    $dailyWindow = max(0, (int)$cfg['retain_daily']);
    $weeklyWindow = max(0, (int)$cfg['retain_weekly']);
    $monthlyWindow = max(0, (int)$cfg['retain_monthly']);

    foreach ($dirs as $index => $dir) {
        $name = $dir['name'];
        $mtime = (int)$dir['mtime'];
        $ageDays = (int)floor(max(0, $now - $mtime) / 86400);
        if ($index < $latestCount) {
            $keep[$name] = true;
            continue;
        }
        if ($dailyWindow > 0 && $ageDays <= $dailyWindow) {
            $keep[$name] = true;
            continue;
        }
        if ($weeklyWindow > 0 && $ageDays <= ($weeklyWindow * 7)) {
            $bucket = date('o-W', $mtime);
            if (!isset($weeklyBuckets[$bucket])) {
                $weeklyBuckets[$bucket] = $name;
                $keep[$name] = true;
            }
            continue;
        }
        if ($monthlyWindow > 0 && $ageDays <= ($monthlyWindow * 31)) {
            $bucket = date('Y-m', $mtime);
            if (!isset($monthlyBuckets[$bucket])) {
                $monthlyBuckets[$bucket] = $name;
                $keep[$name] = true;
            }
        }
    }

    $removed = 0;
    foreach ($dirs as $dir) {
        if (isset($keep[$dir['name']])) continue;
        if (removeDirectoryRecursive($dir['path'])) $removed++;
    }
    return ['removed' => $removed, 'kept' => count($keep)];
}
function runAutoBackupIfDue($db): array {
    $cfg = getAutoBackupSettings($db);
    if (!$cfg['enabled']) return ['success' => false, 'msg' => 'Automatische backups zijn uitgeschakeld.', 'skipped' => true];
    $frequency = in_array($cfg['frequency'], ['daily', 'weekly', 'monthly'], true) ? $cfg['frequency'] : 'daily';
    $periodKey = autoBackupPeriodKey($frequency);
    if ($cfg['last_period_key'] === $periodKey) {
        return ['success' => true, 'msg' => 'Automatische backup voor deze periode bestaat al.', 'skipped' => true];
    }

    $backup = createFullBackup('auto_' . $frequency);
    if (!$backup['success']) {
        setSetting($db, 'auto_backup_last_result', $backup['msg']);
        return $backup;
    }

    setSetting($db, 'auto_backup_last_period_key', $periodKey);
    setSetting($db, 'auto_backup_last_run_at', date('Y-m-d H:i:s'));
    $prune = pruneAutoFullBackups($cfg);
    $msg = $backup['msg'] . ' Automatisch schema: ' . $frequency . '. Opruimen verwijderd ' . (int)$prune['removed'] . ' oude auto-backups.';
    setSetting($db, 'auto_backup_last_result', $msg);
    return ['success' => true, 'msg' => $msg, 'name' => $backup['name'], 'skipped' => false];
}
function parseEmailList(?string $raw): array {
    $raw = str_replace(["\r", "\n", ';'], ',', (string)$raw);
    $parts = array_filter(array_map('trim', explode(',', $raw)), static function ($v) { return $v !== ''; });
    $valid = []; $seen = [];
    foreach ($parts as $mail) {
        $m = strtolower($mail);
        if (!filter_var($m, FILTER_VALIDATE_EMAIL)) continue;
        if (isset($seen[$m])) continue;
        $seen[$m] = 1;
        $valid[] = $m;
    }
    return $valid;
}
function normalizeEmailListString(?string $raw): string {
    return implode(', ', parseEmailList($raw));
}
function getDefaultNotifyRecipientList($db): string {
    $row = $db->query('SELECT alert_recipients FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    return normalizeEmailListString($row['alert_recipients'] ?? '');
}
function resolveNotifyRecipients($db, ?string $preferredList): array {
    $preferred = normalizeEmailListString($preferredList);
    if ($preferred !== '') return parseEmailList($preferred);
    return parseEmailList(getDefaultNotifyRecipientList($db));
}
function safeName(string $s): string { return preg_replace('/[^a-zA-Z0-9_]/', '_', $s); }
function parseDbDateToTs(?string $value): int {
    if ($value === null || trim($value) === '') return 0;
    // Parse database datetime strings as UTC, not local timezone
    $value = trim($value);
    if (preg_match('/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/', $value, $m)) {
        return (int)gmmktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
    }
    return 0;
}
function formatDbDateLocal(?string $value, string $format = 'd-m-Y H:i:s'): string {
    $ts = parseDbDateToTs($value);
    if ($ts <= 0) return (string)($value ?? '');
    return date($format, $ts);
}
function formatDurationSeconds(int $seconds): string {
    if ($seconds <= 0) return '0s';
    $h = (int)floor($seconds / 3600); $m = (int)floor(($seconds % 3600) / 60); $s = (int)($seconds % 60);
    $parts = [];
    if ($h > 0) $parts[] = $h . 'u';
    if ($m > 0 || $h > 0) $parts[] = $m . 'm';
    $parts[] = $s . 's';
    return implode(' ', $parts);
}
function normalizeSessionDuration(string $v): string {
    return in_array($v, ['unlimited','1m','1h','6h','12h','24h','7d','30d'], true) ? $v : 'unlimited';
}
function sessionDurationLabel(string $v): string {
    return ['unlimited'=>'Onbeperkt','1m'=>'1 minuut','1h'=>'1 uur','6h'=>'6 uur','12h'=>'12 uur',
            '24h'=>'24 uur','7d'=>'7 dagen','30d'=>'30 dagen'][$v] ?? 'Onbeperkt';
}
function sessionDurationHours(string $v): int {
    return ['1m'=>1,'1h'=>1,'6h'=>6,'12h'=>12,'24h'=>24,'7d'=>168,'30d'=>720,'unlimited'=>720][$v] ?? 720;
}
function sessionDurationSeconds(string $v): int {
    return ['1m'=>60,'1h'=>3600,'6h'=>21600,'12h'=>43200,'24h'=>86400,'7d'=>604800,'30d'=>2592000,'unlimited'=>0][$v] ?? 0;
}
function rrdtoolBin(): string {
    static $bin = null;
    if ($bin === null) {
        foreach (['/usr/bin/rrdtool','/usr/local/bin/rrdtool','/opt/homebrew/bin/rrdtool'] as $p) {
            if (file_exists($p)) { $bin = $p; break; }
        }
        if ($bin === null) $bin = 'rrdtool';
    }
    return $bin;
}
function isRrdUnknownValue($value): bool {
    if ($value === null) return true;
    $v = strtolower(trim((string)$value));
    return $v === '' || $v === 'u' || $v === 'nan' || $v === '-nan';
}
function findRrdColumnIndex(array $lines, string $column, int $default = 0): int {
    $needle = strtolower($column);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) continue;
        if (stripos($line, $column) === false) continue;
        $cols = preg_split('/\s+/', trim($line));
        if (!$cols) continue;
        $idx = array_search($needle, array_map('strtolower', $cols), true);
        if ($idx !== false) return (int)$idx;
    }
    return $default;
}
function getRrdPingColumnCount(array $lines): int {
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) continue;
        $cols = preg_split('/\s+/', trim($line));
        if (!$cols) continue;
        $count = 0;
        foreach ($cols as $col) {
            if (preg_match('/^ping\d+$/i', $col)) $count++;
        }
        if ($count > 0) return $count;
    }
    return 0;
}
function getTargetStatus(string $catName, string $targetName): array {
    static $cache = [];
    $key = safeName($catName) . '|' . safeName($targetName);
    if (isset($cache[$key])) return $cache[$key];
    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
    $result = ['exists' => false, 'loss' => null, 'median' => null, 'sample_ts' => null];
    if (file_exists($rrdFile)) {
        $result['exists'] = true;
            $out = @shell_exec(rrdtoolBin() . ' lastupdate ' . escapeshellarg($rrdFile) . ' 2>&1');
        if ($out) {
            $lines = explode("\n", trim($out));
            $lossIdx = findRrdColumnIndex($lines, 'loss', 0);
            $medianIdx = findRrdColumnIndex($lines, 'median', 1);
            $pingCols = getRrdPingColumnCount($lines);
            $last = end($lines);
            if (preg_match('/^(\d+):\s+(.+)/', $last, $m)) {
                $result['sample_ts'] = (int)$m[1];
                $vals = preg_split('/\s+/', trim($m[2]));
                $loss = $vals[$lossIdx] ?? null;
                $median = $vals[$medianIdx] ?? null;
                if (!isRrdUnknownValue($loss)) {
                    $lossVal = (float)$loss;
                    $result['loss'] = ($pingCols > 0 && $lossVal > 1.0) ? ($lossVal / $pingCols) : $lossVal;
                } else {
                    $result['loss'] = null;
                }
                $result['median'] = !isRrdUnknownValue($median) ? round((float)$median * 1000, 2) : null;
            }
        }
    }
    return $cache[$key] = $result;
}
function getTargetUptime(string $catName, string $targetName, int $periodHours = 24): array {
    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
    $result = ['uptime' => null, 'loss_avg' => null];
    if (!file_exists($rrdFile)) return $result;
        $fetch = @shell_exec(rrdtoolBin() . ' fetch ' . escapeshellarg($rrdFile) . ' AVERAGE -s -' . ($periodHours * 3600) . ' 2>&1');
    if (!$fetch) return $result;
    $lines = explode("\n", $fetch);
    $lossIdx = findRrdColumnIndex($lines, 'loss', 0);
    $pingCols = getRrdPingColumnCount($lines);
    $dataPoints = 0;
    $downPoints = 0;
    $firstTs = 0;
    $lastTs = 0;
    $prevTs = 0;
    $stepSec = 0;
    foreach ($lines as $line) {
        if (preg_match('/^(\d+):\s+(.+)/', $line, $m)) {
            $ts = (int)$m[1];
            if ($firstTs <= 0) $firstTs = $ts;
            $lastTs = $ts;
            if ($prevTs > 0) {
                $delta = $ts - $prevTs;
                if ($delta > 0 && ($stepSec === 0 || $delta < $stepSec)) $stepSec = $delta;
            }
            $prevTs = $ts;
            $vals = preg_split('/\s+/', trim($m[2]));
            $loss = $vals[$lossIdx] ?? null;
            $isDown = false;
            if (isRrdUnknownValue($loss)) {
                continue;
            } else {
                $lossVal = (float)$loss;
                $lossFrac = ($pingCols > 0 && $lossVal > 1.0) ? ($lossVal / $pingCols) : $lossVal;
                if ($lossFrac >= 1.0) $isDown = true;
            }
            $dataPoints++;
            if ($isDown) $downPoints++;
        }
    }
    if ($dataPoints > 0) {
        if ($stepSec <= 0) $stepSec = 10;
        $dataDuration = max($stepSec, ($lastTs - $firstTs) + $stepSec);
        $downDuration = min($dataDuration, $downPoints * $stepSec);
        $outagePct = ($dataDuration > 0) ? (($downDuration / $dataDuration) * 100) : 0;
        $result['uptime'] = max(0, min(100, round(100 - $outagePct, 2)));
        $result['loss_avg'] = round($outagePct, 2);
    }
    return $result;
}
function getAllTargets($db): array {
    $r = $db->query('SELECT t.*, c.name AS cat_name, c.display_name AS cat_display FROM targets t JOIN categories c ON t.category_id=c.id ORDER BY c.sort_order,c.name,t.sort_order,t.name');
    $a = [];
    while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
    return $a;
}
function syncTargetOutageState($db, array $target, array $status): void {
    $targetId = (int)($target['id'] ?? 0);
    if ($targetId <= 0) return;
    $sampleTs = (int)($status['sample_ts'] ?? 0);
    if ($sampleTs <= 0) $sampleTs = time();
    $openQ = $db->prepare('SELECT id, started_at FROM target_outages WHERE target_id=:tid AND is_open=1 ORDER BY id DESC LIMIT 1');
    $openQ->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $openRow = $openQ->execute()->fetchArray(SQLITE3_ASSOC);
    // Check: target is down if either:
    // 1) Has measurement AND full packet loss
    // 2) Has RRD file but data is stale beyond configured threshold
    $hasMeasure = ((int)($target['enabled'] ?? 0) === 1) && !empty($status['exists']) && $status['loss'] !== null;
    static $staleThresholdSec = null;
    if ($staleThresholdSec === null) {
        $cfgStale = max(20, (int)getSetting($db, 'outage_stale_seconds', '20'));
        $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes WHERE enabled=1');
        if ($probeStepSec <= 0) $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes');
        if ($probeStepSec <= 0) $probeStepSec = 300;
        $staleThresholdSec = max($cfgStale, 120, $probeStepSec * 2);
    }
    $isStaleData = ((int)($target['enabled'] ?? 0) === 1) && !empty($status['exists']) && (time() - $sampleTs > $staleThresholdSec);
    $isDown = ($hasMeasure && ((float)$status['loss'] >= 1.0)) || $isStaleData;
    if ($isDown) {
        if (!$openRow) {
            $ins = $db->prepare('INSERT INTO target_outages(target_id, started_at, is_open, start_source_ts, updated_at) VALUES(:tid, datetime(:st,"unixepoch"), 1, :st, CURRENT_TIMESTAMP)');
            $ins->bindValue(':tid', $targetId, SQLITE3_INTEGER);
            $ins->bindValue(':st', $sampleTs, SQLITE3_INTEGER);
            $ins->execute();
        }
        return;
    }
    // Keep outage open when measurement is uncertain (fresh sample but unknown loss) to avoid open/close flapping.
    if ($openRow && $status['loss'] === null && !$isStaleData) {
        return;
    }
    if ($openRow) {
        $startTs = parseDbDateToTs($openRow['started_at'] ?? null);
        if ($startTs <= 0) $startTs = $sampleTs;
        $endTs = max($sampleTs, $startTs);
        $duration = max(0, $endTs - $startTs);
        $upd = $db->prepare('UPDATE target_outages SET ended_at=datetime(:et,"unixepoch"), duration_seconds=:dur, is_open=0, end_source_ts=:et, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $upd->bindValue(':et', $endTs, SQLITE3_INTEGER);
        $upd->bindValue(':dur', $duration, SQLITE3_INTEGER);
        $upd->bindValue(':id', (int)$openRow['id'], SQLITE3_INTEGER);
        $upd->execute();
    }
}

function collectSessionOutageSummary($db, int $targetId, int $sessionStartTs, int $sessionEndTs, int $limit = 12): array {
    $summary = ['total_downtime_seconds' => 0, 'events' => []];
    if ($targetId <= 0 || $sessionEndTs <= $sessionStartTs) return $summary;

    $q = $db->prepare('SELECT id, started_at, ended_at, duration_seconds, is_open FROM target_outages WHERE target_id=:tid AND (is_open=1 OR started_at<=datetime(:end_ts,"unixepoch")) ORDER BY started_at DESC LIMIT :lim');
    $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $q->bindValue(':end_ts', $sessionEndTs, SQLITE3_INTEGER);
    $q->bindValue(':lim', $limit, SQLITE3_INTEGER);
    $rows = $q->execute();

    while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
        $startTs = parseDbDateToTs($row['started_at'] ?? null);
        if ($startTs <= 0) continue;

        $isOpen = (int)($row['is_open'] ?? 0) === 1;
        $rawEndTs = parseDbDateToTs($row['ended_at'] ?? null);
        $eventEndTs = $isOpen ? $sessionEndTs : $rawEndTs;
        if ($eventEndTs <= 0) $eventEndTs = $sessionEndTs;
        if ($eventEndTs < $startTs) $eventEndTs = $startTs;

        $clipStart = max($startTs, $sessionStartTs);
        $clipEnd = min($sessionEndTs, $eventEndTs);
        if ($clipEnd <= $clipStart) continue;

        $clipDur = $clipEnd - $clipStart;
        $summary['total_downtime_seconds'] += $clipDur;
        $summary['events'][] = [
            'started_at_label' => date('d-m-Y H:i:s', $clipStart),
            'ended_at_label' => date('d-m-Y H:i:s', $clipEnd),
            'duration_label' => formatDurationSeconds($clipDur),
        ];
    }

    return $summary;
}

function logPingLossSample($db, array $target, array $status): void {
    $targetId = (int)($target['id'] ?? 0);
    if ($targetId <= 0) return;
    if ((int)($target['enabled'] ?? 0) !== 1) return;

    $sampleTs = (int)($status['sample_ts'] ?? 0);
    $lossFrac = $status['loss'] ?? null;
    if ($sampleTs <= 0 || $lossFrac === null) return;
    $lossFrac = (float)$lossFrac;
    if ($lossFrac <= 0.0) return;

    $ins = $db->prepare('INSERT OR IGNORE INTO target_ping_loss_events(target_id, sample_ts, loss_fraction, is_full_loss, notified, created_at) VALUES(:tid, :ts, :loss, :full, 0, CURRENT_TIMESTAMP)');
    $ins->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $ins->bindValue(':ts', $sampleTs, SQLITE3_INTEGER);
    $ins->bindValue(':loss', $lossFrac, SQLITE3_FLOAT);
    $ins->bindValue(':full', $lossFrac >= 1.0 ? 1 : 0, SQLITE3_INTEGER);
    $ins->execute();
}

function buildPingLossGroups(array $events, int $gapSeconds = 120): array {
    if (empty($events)) return [];
    usort($events, static function ($a, $b) {
        return ((int)($a['sample_ts'] ?? 0)) <=> ((int)($b['sample_ts'] ?? 0));
    });

    $groups = [];
    $current = null;
    foreach ($events as $ev) {
        $ts = (int)($ev['sample_ts'] ?? 0);
        if ($ts <= 0) continue;
        $loss = max(0.0, min(1.0, (float)($ev['loss_fraction'] ?? 0)));
        if ($current === null) {
            $current = ['start_ts' => $ts, 'end_ts' => $ts, 'count' => 1, 'max_loss' => $loss, 'full_count' => $loss >= 1.0 ? 1 : 0, 'ids' => [(int)($ev['id'] ?? 0)]];
            continue;
        }
        if (($ts - (int)$current['end_ts']) <= $gapSeconds) {
            $current['end_ts'] = $ts;
            $current['count']++;
            if ($loss > (float)$current['max_loss']) $current['max_loss'] = $loss;
            if ($loss >= 1.0) $current['full_count']++;
            $current['ids'][] = (int)($ev['id'] ?? 0);
        } else {
            $groups[] = $current;
            $current = ['start_ts' => $ts, 'end_ts' => $ts, 'count' => 1, 'max_loss' => $loss, 'full_count' => $loss >= 1.0 ? 1 : 0, 'ids' => [(int)($ev['id'] ?? 0)]];
        }
    }
    if ($current !== null) $groups[] = $current;
    return $groups;
}

function collectSessionPingLossSummary($db, int $targetId, int $sessionStartTs, int $sessionEndTs, int $limit = 200): array {
    $summary = ['total_samples' => 0, 'groups' => [], 'event_ids' => []];
    if ($targetId <= 0 || $sessionEndTs <= $sessionStartTs) return $summary;

    $q = $db->prepare('SELECT id, sample_ts, loss_fraction, is_full_loss FROM target_ping_loss_events WHERE target_id=:tid AND sample_ts>=:st AND sample_ts<=:et ORDER BY sample_ts ASC LIMIT :lim');
    $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $q->bindValue(':st', $sessionStartTs, SQLITE3_INTEGER);
    $q->bindValue(':et', $sessionEndTs, SQLITE3_INTEGER);
    $q->bindValue(':lim', $limit, SQLITE3_INTEGER);
    $rows = $q->execute();

    $events = [];
    while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
        $events[] = $row;
        $summary['event_ids'][] = (int)($row['id'] ?? 0);
    }
    $summary['total_samples'] = count($events);
    $summary['groups'] = buildPingLossGroups($events);
    return $summary;
}

function sendEmail($db, $to, $subject, $body, &$debug_output = null): array {
    $result = ['success' => false, 'message' => ''];
    $debug = [];
    $settings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    if (!$settings || !$settings['smtp_enabled']) { $result['message'] = 'SMTP niet ingeschakeld'; return $result; }
    if (empty($settings['smtp_host']) || empty($settings['smtp_username']) || empty($settings['smtp_password'])) {
        $result['message'] = 'SMTP configuratie onvolledig'; return $result;
    }
    $host = $settings['smtp_host']; $port = (int)$settings['smtp_port'];
    $username = $settings['smtp_username']; $password = smDecryptPassword($settings['smtp_password']);
    $encryption = $settings['smtp_encryption'];
    $from_email = !empty($settings['smtp_from_email']) ? $settings['smtp_from_email'] : $username;
    $from_name  = !empty($settings['smtp_from_name'])  ? $settings['smtp_from_name']  : 'SmokePing Manager';
    if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) { $result['message'] = 'Ongeldig e-mailadres: ' . $to; return $result; }
    try {
        $remote = ($encryption === 'ssl' ? 'ssl://' : '') . $host . ':' . $port;
        $socket = @stream_socket_client($remote, $errno, $errstr, 30, STREAM_CLIENT_CONNECT);
        if (!$socket) { $result['message'] = "Verbinding mislukt: $errstr ($errno)"; return $result; }
        stream_set_timeout($socket, 30);
        $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '220') { fclose($socket); $result['message'] = 'SMTP: ' . trim($resp); return $result; }
        fputs($socket, "EHLO $host\r\n");
        while ($l = fgets($socket, 515)) { if (substr($l, 3, 1) == ' ') break; }
        if ($encryption === 'tls') {
            fputs($socket, "STARTTLS\r\n");
            $resp = fgets($socket, 515);
            if (substr($resp, 0, 3) != '220') { fclose($socket); $result['message'] = 'STARTTLS mislukt'; return $result; }
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) { fclose($socket); $result['message'] = 'TLS mislukt'; return $result; }
            fputs($socket, "EHLO $host\r\n");
            while ($l = fgets($socket, 515)) { if (substr($l, 3, 1) == ' ') break; }
        }
        fputs($socket, "AUTH LOGIN\r\n");
        $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '334') { fclose($socket); $result['message'] = 'AUTH LOGIN mislukt'; return $result; }
        fputs($socket, base64_encode($username) . "\r\n"); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '334') { fclose($socket); $result['message'] = 'Username geweigerd'; return $result; }
        fputs($socket, base64_encode($password) . "\r\n"); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '235') { fclose($socket); $result['message'] = 'Authenticatie mislukt'; return $result; }
        fputs($socket, "MAIL FROM: <$from_email>\r\n"); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '250') { fclose($socket); $result['message'] = 'MAIL FROM mislukt'; return $result; }
        fputs($socket, "RCPT TO: <$to>\r\n"); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '250') { fclose($socket); $result['message'] = 'RCPT TO mislukt'; return $result; }
        fputs($socket, "DATA\r\n"); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '354') { fclose($socket); $result['message'] = 'DATA mislukt'; return $result; }
        $msg  = "From: $from_name <$from_email>\r\nTo: $to\r\nSubject: $subject\r\n";
        $msg .= "Date: " . date('r') . "\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n";
        $msg .= $body . "\r\n.\r\n";
        fputs($socket, $msg); $resp = fgets($socket, 515);
        if (substr($resp, 0, 3) != '250') { fclose($socket); $result['message'] = 'Verzenden mislukt: ' . trim($resp); return $result; }
        fputs($socket, "QUIT\r\n"); fgets($socket, 515); fclose($socket);
        $result['success'] = true; $result['message'] = 'OK';
    } catch (Exception $e) { $result['message'] = 'Exception: ' . $e->getMessage(); }
    return $result;
}
function logAndSendEmail($db, string $to, string $subject, string $body, string $type = 'notification', string $targetName = ''): array {
    $debug = '';
    $res = sendEmail($db, $to, $subject, $body, $debug);
    try {
        $s = $db->prepare('INSERT INTO mail_log(type,target_name,email_to,subject,status,message,debug_output,body) VALUES(:tp,:tn,:to,:sb,:st,:ms,:dbg,:bd)');
        $s->bindValue(':tp', $type); $s->bindValue(':tn', $targetName); $s->bindValue(':to', $to);
        $s->bindValue(':sb', $subject); $s->bindValue(':st', $res['success'] ? 'success' : 'failed');
        $s->bindValue(':ms', $res['message']); $s->bindValue(':dbg', (string)$debug);
        $s->bindValue(':bd', $body);
        $s->execute();
        $db->exec('DELETE FROM mail_log WHERE id NOT IN (SELECT id FROM mail_log ORDER BY id DESC LIMIT 500)');
    } catch (\Exception $e) {}
    return $res;
}

function logAndSendEmailList($db, array $recipients, string $subject, string $body, string $type = 'notification', string $targetName = ''): array {
    if (empty($recipients)) {
        try {
            $s = $db->prepare('INSERT INTO mail_log(type,target_name,email_to,subject,status,message,debug_output,body) VALUES(:tp,:tn,:to,:sb,:st,:ms,:dbg,:bd)');
            $s->bindValue(':tp', $type); $s->bindValue(':tn', $targetName); $s->bindValue(':to', '');
            $s->bindValue(':sb', $subject); $s->bindValue(':st', 'failed');
            $s->bindValue(':ms', 'Geen geldige ontvangers geconfigureerd'); $s->bindValue(':dbg', '');
            $s->bindValue(':bd', $body);
            $s->execute();
            $db->exec('DELETE FROM mail_log WHERE id NOT IN (SELECT id FROM mail_log ORDER BY id DESC LIMIT 500)');
        } catch (\Exception $e) {}
        return ['success' => false, 'message' => 'Geen geldige ontvangers geconfigureerd'];
    }
    $ok = 0; $fail = 0; $last = 'OK';
    foreach ($recipients as $to) {
        $res = logAndSendEmail($db, $to, $subject, $body, $type, $targetName);
        if (!empty($res['success'])) $ok++; else { $fail++; $last = (string)($res['message'] ?? 'onbekende fout'); }
    }
    return ['success' => $ok > 0, 'message' => "success={$ok}, failed={$fail}, last={$last}"];
}
function buildOutageStartMailBody(array $row, int $startTs): string {
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#dc2626 0%,#991b1b 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">&#9888; UITVAL gedetecteerd</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Uitval melding</div></div>';
    $body .= '<div style="background:#fee2e2;border-bottom:3px solid #dc2626;padding:14px 32px"><div style="font-size:15px;font-weight:600;color:#991b1b">Volledig pakketverlies &mdash; host niet bereikbaar</div></div>';
    $body .= '<div style="padding:24px 32px"><p style="margin:0 0 18px;color:#374151;font-size:15px">Uitval gedetecteerd voor <strong style="color:#dc2626">'.htmlspecialchars($row['display_name']).'</strong>.</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    foreach ([['Categorie', htmlspecialchars($row['cat_display'])],['Target','<strong>'.htmlspecialchars($row['display_name']).'</strong>'],['Host','<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$row['host']).'</code>'],['Uitval vanaf',date('d-m-Y H:i:s',$startTs)]] as $i=>[$l,$v]) {
        $bg=($i%2===0)?'#f9fafb':'#fff'; $br=($i<3)?'border-bottom:1px solid #e5e7eb;':'';
        $body.='<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$br.'">'.$l.'</td><td style="padding:9px 14px;font-size:14px;color:#111827;'.$br.'">'.$v.'</td></tr>';
    }
    $body .= '</table></div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatische uitval melding</div></div></body></html>';
    return $body;
}
function buildBatchOutageStartMail(array $outages): string {
    $count = count($outages);
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:700px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#dc2626 0%,#991b1b 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:24px;font-weight:700">&#9888; MEERDERE UITVALLEN gedetecteerd</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:14px;margin-top:5px">SmokePing Manager &mdash; Uitval overzicht</div></div>';
    $body .= '<div style="background:#fee2e2;border-bottom:3px solid #dc2626;padding:16px 32px"><div style="font-size:18px;font-weight:700;color:#991b1b">' . $count . ' target(s) zijn momenteel niet bereikbaar</div></div>';
    $body .= '<div style="padding:24px 32px"><p style="margin:0 0 18px;color:#374151;font-size:15px">De volgende targets zijn uitgevallen:</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $body .= '<thead style="background:#f9fafb;border-bottom:2px solid #e5e7eb"><tr>';
    $body .= '<th style="text-align:left;padding:10px 14px;font-size:12px;color:#6b7280">Target</th>';
    $body .= '<th style="text-align:left;padding:10px 14px;font-size:12px;color:#6b7280">Categorie</th>';
    $body .= '<th style="text-align:left;padding:10px 14px;font-size:12px;color:#6b7280">Host</th>';
    $body .= '<th style="text-align:left;padding:10px 14px;font-size:12px;color:#6b7280">Uitval vanaf</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($outages as $i => $o) {
        $startTs = strtotime($o['started_at']) ?: time();
        $bg = ($i % 2 === 0) ? '#fff' : '#f9fafb';
        $body .= '<tr style="background:' . $bg . '"><td style="padding:9px 14px;font-size:14px;color:#111827;font-weight:600">' . htmlspecialchars($o['display_name']) . '</td>';
        $body .= '<td style="padding:9px 14px;font-size:13px;color:#6b7280">' . htmlspecialchars($o['cat_display']) . '</td>';
        $body .= '<td style="padding:9px 14px;font-size:12px;font-family:monospace;color:#6b7280">' . htmlspecialchars($o['host']) . '</td>';
        $body .= '<td style="padding:9px 14px;font-size:13px;color:#6b7280">' . date('d-m-Y H:i:s', $startTs) . '</td></tr>';
    }
    $body .= '</tbody></table></div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatische batch notificatie</div></div></body></html>';
    return $body;
}

function buildBatchOutageSummaryMail(array $started, array $ended, int $generatedTs, int $intervalMin): string {
    $startCount = count($started);
    $endCount = count($ended);
    $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SmokePing</title></head><body style="margin:0;padding:20px;background:#f3f4f6;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif">';
    $body .= '<div style="max-width:760px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $body .= '<div style="background:linear-gradient(135deg,#1d4ed8 0%,#1e3a8a 100%);color:#fff;padding:24px 32px">';
    $body .= '<div style="font-size:24px;font-weight:600;margin-bottom:4px">Uitval en herstel samenvatting</div>';
    $body .= '<div style="font-size:14px;opacity:0.95">Interval: elke '.(int)$intervalMin.' minuten | gegenereerd op '.date('d-m-Y H:i:s', $generatedTs).'</div>';
    $body .= '</div><div style="padding:26px 32px">';

    if ($startCount > 0) {
        $body .= '<div style="font-size:16px;font-weight:700;color:#991b1b;margin-bottom:8px">Nieuwe uitval: '.$startCount.'</div>';
        $body .= '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:18px">';
        $body .= '<thead><tr style="background:#fef2f2;border-bottom:2px solid #fecaca"><th style="padding:9px 8px;text-align:left">Target</th><th style="padding:9px 8px;text-align:left">Categorie</th><th style="padding:9px 8px;text-align:left">Host</th><th style="padding:9px 8px;text-align:left">Uitval vanaf</th></tr></thead><tbody>';
        foreach ($started as $row) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = $generatedTs;
            $body .= '<tr style="border-bottom:1px solid #e5e7eb">';
            $body .= '<td style="padding:9px 8px">'.htmlspecialchars((string)($row['display_name'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.htmlspecialchars((string)($row['cat_display'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280;font-family:monospace">'.htmlspecialchars((string)($row['host'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $startTs).'</td>';
            $body .= '</tr>';
        }
        $body .= '</tbody></table>';
    }

    if ($endCount > 0) {
        $body .= '<div style="font-size:16px;font-weight:700;color:#065f46;margin:6px 0 8px">Herstelde uitval: '.$endCount.'</div>';
        $body .= '<table style="width:100%;border-collapse:collapse;font-size:13px">';
        $body .= '<thead><tr style="background:#ecfdf5;border-bottom:2px solid #bbf7d0"><th style="padding:9px 8px;text-align:left">Target</th><th style="padding:9px 8px;text-align:left">Categorie</th><th style="padding:9px 8px;text-align:left">Host</th><th style="padding:9px 8px;text-align:left">Uitval vanaf</th><th style="padding:9px 8px;text-align:left">Hersteld op</th><th style="padding:9px 8px;text-align:left">Duur</th></tr></thead><tbody>';
        foreach ($ended as $row) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs = parseDbDateToTs($row['ended_at'] ?? null);
            if ($startTs <= 0) $startTs = $generatedTs;
            if ($endTs <= 0) $endTs = $generatedTs;
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            $body .= '<tr style="border-bottom:1px solid #e5e7eb">';
            $body .= '<td style="padding:9px 8px">'.htmlspecialchars((string)($row['display_name'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.htmlspecialchars((string)($row['cat_display'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280;font-family:monospace">'.htmlspecialchars((string)($row['host'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $startTs).'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $endTs).'</td>';
            $body .= '<td style="padding:9px 8px"><strong>'.formatDurationSeconds($duration).'</strong></td>';
            $body .= '</tr>';
        }
        $body .= '</tbody></table>';
    }

    if ($startCount === 0 && $endCount === 0) {
        $body .= '<p style="margin:0;color:#6b7280">Geen wijzigingen in deze interval.</p>';
    }

    $body .= '</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Gecombineerde uitval/herstel melding</div></div></body></html>';
    return $body;
}

function buildOutageEndMailBody(array $row, int $startTs, int $endTs, int $duration): string {
    $min=(int)floor($duration/60); $sec=$duration%60; $durStr=($min>0?$min.'m ':'').$sec.'s';
    if($duration>=3600){$h=(int)floor($duration/3600);$m=(int)floor(($duration%3600)/60);$durStr=$h.'u '.$m.'m';}
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#059669 0%,#047857 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">&#10003; Uitval opgelost</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Herstel melding</div></div>';
    $body .= '<div style="background:#d1fae5;border-bottom:3px solid #059669;padding:14px 32px"><div style="font-size:15px;font-weight:600;color:#047857">Host is weer bereikbaar</div></div>';
    $body .= '<div style="padding:24px 32px"><p style="margin:0 0 18px;color:#374151;font-size:15px">Verbinding met <strong style="color:#059669">'.htmlspecialchars($row['display_name']).'</strong> hersteld.</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    foreach ([['Categorie',htmlspecialchars($row['cat_display'])],['Target','<strong>'.htmlspecialchars($row['display_name']).'</strong>'],['Host','<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$row['host']).'</code>'],['Uitval vanaf',date('d-m-Y H:i:s',$startTs)],['Hersteld op',date('d-m-Y H:i:s',$endTs)],['Totale duur','<strong>'.$durStr.'</strong>']] as $i=>[$l,$v]) {
        $bg=($i%2===0)?'#f9fafb':'#fff'; $br=($i<5)?'border-bottom:1px solid #e5e7eb;':'';
        $body.='<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$br.'">'.$l.'</td><td style="padding:9px 14px;font-size:14px;color:#111827;'.$br.'">'.$v.'</td></tr>';
    }
    $body .= '</table></div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatische herstel melding</div></div></body></html>';
    return $body;
}
function buildSessionEndMailBody(array $t, string $dur, int $startedAt, int $endTs, array $st, array $ut, array $outageSummary = [], array $pingLossSummary = []): string {
    $lossFrac=$st['loss']; $lossPct=($lossFrac!==null)?round($lossFrac*100,1).'%':'n.v.t.';
    $median=($st['median']!==null)?$st['median'].' ms':'n.v.t.';
    $uptimePct=($ut['uptime']!==null)?$ut['uptime'].'%':'n.v.t.';
    $durLabel=htmlspecialchars(sessionDurationLabel($dur));
    $events = is_array($outageSummary['events'] ?? null) ? $outageSummary['events'] : [];
    $totalDownSec = (int)($outageSummary['total_downtime_seconds'] ?? 0);
    $pingGroups = is_array($pingLossSummary['groups'] ?? null) ? $pingLossSummary['groups'] : [];
    $pingSamples = (int)($pingLossSummary['total_samples'] ?? 0);
    $hasPingLoss = $pingSamples > 0 && !empty($pingGroups);
    $hadOutage = $totalDownSec > 0 || !empty($events);
    if($hadOutage){$sLabel='Uitval tijdens sessie';$sColor='#dc2626';$sBg='#fee2e2';}
    elseif($hasPingLoss){$sLabel='Pingverlies tijdens sessie';$sColor='#d97706';$sBg='#fef3c7';}
    elseif(!$st['exists']){$sLabel='Geen RRD data';$sColor='#6b7280';$sBg='#f3f4f6';}
    elseif($lossFrac!==null&&$lossFrac>=1.0){$sLabel='Volledige uitval';$sColor='#dc2626';$sBg='#fee2e2';}
    elseif($lossFrac!==null&&$lossFrac>0){$sLabel='Gedeeltelijk verlies';$sColor='#d97706';$sBg='#fef3c7';}
    else{$sLabel='Geen uitval';$sColor='#059669';$sBg='#d1fae5';}
    $uColor=($ut['uptime']===null)?'#6b7280':(($ut['uptime']>=99)?'#059669':(($ut['uptime']>=95)?'#d97706':'#dc2626'));
    $hColor=($hadOutage||($lossFrac!==null&&$lossFrac>0))?'linear-gradient(135deg,#dc2626 0%,#991b1b 100%)':'linear-gradient(135deg,#059669 0%,#047857 100%)';
    $hTitle=($hadOutage||($lossFrac!==null&&$lossFrac>0))?'Sessie afgerond &mdash; Let op':'Sessie afgerond';
    $body='<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body.='<div style="max-width:560px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body.='<div style="background:'.$hColor.';padding:28px 32px"><div style="color:#fff;font-size:22px;font-weight:700">'.$hTitle.'</div>';
    $body.='<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Sessie samenvatting</div></div>';
    $body.='<div style="background:'.$sBg.';border-bottom:3px solid '.$sColor.';padding:14px 32px;display:flex;align-items:center;gap:12px">';
    $body.='<div style="width:14px;height:14px;border-radius:50%;background:'.$sColor.';flex-shrink:0"></div>';
    $body.='<div style="font-size:15px;font-weight:600;color:'.$sColor.'">'.$sLabel.'</div>';
    if($ut['uptime']!==null) $body.='<div style="margin-left:auto;font-size:20px;font-weight:700;color:'.$uColor.'">'.$uptimePct.' uptime</div>';
    $body.='</div><div style="padding:24px 32px">';
    $body.='<p style="margin:0 0 18px;color:#374151;font-size:15px">Samenvatting voor <strong style="color:#1d4ed8">'.htmlspecialchars($t['display_name']).'</strong>.</p>';
    $actualSec=max(0,$endTs-$startedAt); $aH=(int)floor($actualSec/3600); $aM=(int)floor(($actualSec%3600)/60); $aS=$actualSec%60;
    $aDurStr=($aH>0?$aH.' uur ':''). ($aM>0||$aH>0?$aM.' min ':'').$aS.' sec';
    if($actualSec>=3600) $aDurStr=$aH.' uur '.$aM.' min';
    $body.='<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px">';
    foreach([['Categorie',htmlspecialchars($t['cat_display']),false],['Target','<strong>'.htmlspecialchars($t['display_name']).'</strong>',false],['Host','<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$t['host']).'</code>',true],['Sessieduur (gepland)',$durLabel,false],['Gestart op',date('d-m-Y H:i:s',$startedAt),true],['Beeindigd op',date('d-m-Y H:i:s',$endTs),false],['Totale duur','<strong>'.$aDurStr.'</strong>',true]] as $i=>[$l,$v,$a]){
        $bg=($i%2===0)?'#f9fafb':'#fff'; $br=($i<6)?'border-bottom:1px solid #e5e7eb;':'';
        $body.='<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$br.'">'.$l.'</td><td style="padding:9px 14px;font-size:14px;color:#111827;'.$br.'">'.$v.'</td></tr>';
    }
    $body.='</table><div style="font-size:13px;font-weight:600;color:#374151;margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px">Meetresultaten</div>';
    $body.='<div style="display:flex;gap:10px;flex-wrap:wrap">';
    foreach([['Packet Loss',$lossPct,$sColor],['Median RTT',$median,'#3b82f6'],['Uptime',$uptimePct,$uColor]] as[$ml,$mv,$mc]){
        $body.='<div style="flex:1;min-width:120px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;text-align:center">';
        $body.='<div style="font-size:20px;font-weight:700;color:'.$mc.'">'.$mv.'</div>';
        $body.='<div style="font-size:11px;color:#6b7280;margin-top:4px">'.$ml.'</div></div>';
    }
    $body.='</div>';
    if($hadOutage){
        $body.='<div style="margin-top:16px;background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px">';
        $body.='<div style="font-size:13px;font-weight:700;color:#9a3412;margin-bottom:8px">Uitval tijdens deze sessie</div>';
        $body.='<div style="font-size:13px;color:#7c2d12;margin-bottom:6px">Totale uitvaltijd: <strong>'.formatDurationSeconds($totalDownSec).'</strong></div>';
        if(!empty($events)){
            $body.='<ul style="margin:6px 0 0 16px;padding:0;color:#7c2d12;font-size:12px">';
            foreach(array_slice($events,0,5) as $ev){
                $body.='<li style="margin:3px 0">'.$ev['started_at_label'].' - '.$ev['ended_at_label'].' ('.$ev['duration_label'].')</li>';
            }
            $body.='</ul>';
        }
        $body.='</div>';
    }
    if($hasPingLoss){
        $body.='<div style="margin-top:16px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px">';
        $body.='<div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:8px">Pingverlies tijdens deze sessie</div>';
        $body.='<div style="font-size:13px;color:#78350f;margin-bottom:6px">Aantal meetmomenten met verlies: <strong>'.(int)$pingSamples.'</strong></div>';
        $body.='<ul style="margin:6px 0 0 16px;padding:0;color:#78350f;font-size:12px">';
        foreach(array_slice($pingGroups,0,8) as $pg){
            $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
            $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
            if($gCount<=1){
                $body.='<li style="margin:3px 0">'.date('d-m-Y H:i:s',$gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
            } else {
                $body.='<li style="margin:3px 0">Van '.date('d-m-Y H:i:s',$gStart).' t/m '.date('d-m-Y H:i:s',$gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
            }
        }
        $body.='</ul></div>';
    }
    $body.='</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatisch gegenereerde samenvatting</div></div></body></html>';
    return $body;
}

function buildPingLossMailBody(array $target, array $groups, int $sampleCount): string {
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:620px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#d97706 0%,#92400e 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">Pingverlies gedetecteerd</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Pingverlies rapport</div></div>';
    $body .= '<div style="padding:24px 32px">';
    $body .= '<p style="margin:0 0 14px;color:#374151;font-size:15px">Target <strong style="color:#92400e">'.htmlspecialchars((string)$target['display_name']).'</strong> had pingverlies.</p>';
    $body .= '<p style="margin:0 0 14px;color:#78350f;font-size:13px">Meetmomenten met verlies: <strong>'.(int)$sampleCount.'</strong></p>';
    $body .= '<ul style="margin:8px 0 0 16px;padding:0;color:#78350f;font-size:13px">';
    foreach (array_slice($groups, 0, 12) as $pg) {
        $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
        $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
        if ($gCount <= 1) {
            $body .= '<li style="margin:4px 0">'.date('d-m-Y H:i:s', $gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
        } else {
            $body .= '<li style="margin:4px 0">Van '.date('d-m-Y H:i:s', $gStart).' t/m '.date('d-m-Y H:i:s', $gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
        }
    }
    $body .= '</ul></div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatische pingverlies melding</div>';
    $body .= '</div></body></html>';
    return $body;
}

function buildSessionSnapshotMailBody(array $t, string $dur, int $startedAt, int $snapshotTs, array $st, array $ut, array $outageSummary, array $pingSummary, string $modeLabel = 'Tussenstand'): string {
    $lossPct = $st['loss'] !== null ? round(((float)$st['loss']) * 100, 1) . '%' : 'n.v.t.';
    $median = $st['median'] !== null ? $st['median'] . ' ms' : 'n.v.t.';
    $uptime = $ut['uptime'] !== null ? $ut['uptime'] . '%' : 'n.v.t.';

    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:660px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#2563eb 0%,#1e3a8a 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">Sessie '.$modeLabel.'</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Sessie samenvatting</div></div>';
    $body .= '<div style="padding:24px 32px">';
    if ($dur === 'unlimited') {
        $body .= '<p style="margin:0 0 12px;color:#1e3a8a;font-size:14px"><strong>Deze sessie loopt onbeperkt door.</strong></p>';
    }
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $rows = [
        ['Categorie', htmlspecialchars((string)$t['cat_display'])],
        ['Target', '<strong>'.htmlspecialchars((string)$t['display_name']).'</strong>'],
        ['Host', '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px">'.htmlspecialchars((string)$t['host']).'</code>'],
        ['Sessieduur', htmlspecialchars(sessionDurationLabel($dur))],
        ['Gestart op', date('d-m-Y H:i:s', $startedAt)],
        ['Snapshot op', date('d-m-Y H:i:s', $snapshotTs)],
        ['Packet loss', htmlspecialchars($lossPct)],
        ['Median RTT', htmlspecialchars($median)],
        ['Uptime', htmlspecialchars($uptime)],
    ];
    foreach ($rows as $i => $rowInfo) {
        $bg = ($i % 2 === 0) ? '#f9fafb' : '#fff';
        $body .= '<tr style="background:'.$bg.'"><td style="padding:8px 12px;font-size:12px;color:#6b7280;width:150px">'.$rowInfo[0].'</td><td style="padding:8px 12px;font-size:14px;color:#111827">'.$rowInfo[1].'</td></tr>';
    }
    $body .= '</table>';

    $events = is_array($outageSummary['events'] ?? null) ? $outageSummary['events'] : [];
    if (!empty($events)) {
        $body .= '<div style="margin-top:14px;background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px">';
        $body .= '<div style="font-size:13px;font-weight:700;color:#9a3412;margin-bottom:8px">Uitval tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#7c2d12;font-size:12px">';
        foreach (array_slice($events, 0, 10) as $ev) {
            $sTs = (int)($ev['started_at_ts'] ?? 0);
            $eTsRaw = (int)($ev['ended_at_ts'] ?? 0);
            $eTs = $eTsRaw > 0 ? $eTsRaw : $snapshotTs;
            $durSec = max(0, $eTs - $sTs);
            if ($durSec >= 60) {
                $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $sTs).' t/m '.date('d-m-Y H:i:s', $eTs).' ('.formatDurationSeconds($durSec).')</li>';
            } else {
                $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $sTs).' ('.formatDurationSeconds($durSec).')</li>';
            }
        }
        $body .= '</ul></div>';
    }

    $pingGroups = is_array($pingSummary['groups'] ?? null) ? $pingSummary['groups'] : [];
    if (!empty($pingGroups)) {
        $body .= '<div style="margin-top:14px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px">';
        $body .= '<div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:8px">Pingverlies tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#78350f;font-size:12px">';
        foreach (array_slice($pingGroups, 0, 12) as $pg) {
            $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
            $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
            if ($gCount <= 1) {
                $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
            } else {
                $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $gStart).' t/m '.date('d-m-Y H:i:s', $gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
            }
        }
        $body .= '</ul></div>';
    }

    $body .= '</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; '.$modeLabel.' sessie samenvatting</div></div></body></html>';
    return $body;
}
function processSessionEndNotifications($db): void {
    $last = (int)getSetting($db, 'session_mail_last_check', '0');
    $now = time();
    if ($now - $last < 55) return; // max 1x per ~60 seconden
    setSetting($db, 'session_mail_last_check', (string)$now);
    $rows = $db->query('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.enabled=1 AND t.session_duration!="unlimited" AND t.session_end_notified=0');
    while ($t = $rows->fetchArray(SQLITE3_ASSOC)) {
        $dur = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
        if ($dur === 'unlimited') continue;
        $notifyEnabled = (int)($t['session_notify_enabled'] ?? 0) === 1;
        $startedAt = !empty($t['session_started_at']) ? strtotime($t['session_started_at']) : 0;
        if ($startedAt <= 0) {
            $startedAt = parseDbDateToTs($t['created_at'] ?? null);
            if ($startedAt <= 0) continue;
            $fix = $db->prepare('UPDATE targets SET session_started_at=datetime(:st,"unixepoch"), updated_at=CURRENT_TIMESTAMP WHERE id=:id');
            $fix->bindValue(':st', $startedAt, SQLITE3_INTEGER);
            $fix->bindValue(':id', (int)$t['id'], SQLITE3_INTEGER);
            $fix->execute();
        }
        $endTs = $startedAt + sessionDurationSeconds($dur);
        if ($endTs > $now) continue;
        if ($notifyEnabled) {
            $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
            if (!empty($recipients)) {
                $hours = sessionDurationHours($dur);
                $st = getTargetStatus($t['cat_name'], $t['name']);
                $ut = getTargetUptime($t['cat_name'], $t['name'], $hours);
                $outageSummary = collectSessionOutageSummary($db, (int)$t['id'], $startedAt, $endTs);
                $pingLossSummary = collectSessionPingLossSummary($db, (int)$t['id'], $startedAt, $endTs);
                $subject = 'SmokePing - Sessie afgerond: ' . $t['display_name'];
                $body = buildSessionEndMailBody($t, $dur, $startedAt, $endTs, $st, $ut, $outageSummary, $pingLossSummary);
                logAndSendEmailList($db, $recipients, $subject, $body, 'session_end', $t['display_name']);
            }
        }
        $u = $db->prepare('UPDATE targets SET session_end_notified=1, enabled=0, session_started_at=NULL, session_start_notified=0, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $u->bindValue(':id', (int)$t['id'], SQLITE3_INTEGER);
        $u->execute();
    }
}

function processPingLossNotifications($db): void {
    $settings = $db->query('SELECT ping_loss_notifications, outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    if ((int)($settings['ping_loss_notifications'] ?? 0) !== 1) return;
    $globalInterval = max(1, (int)($settings['outage_mail_interval'] ?? 5));
    $now = time();

    $targets = $db->query('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.enabled=1 AND t.session_notify_enabled=1');
    while ($t = $targets->fetchArray(SQLITE3_ASSOC)) {
        $targetId = (int)($t['id'] ?? 0);
        if ($targetId <= 0) continue;
        $targetInterval = isset($t['outage_mail_interval']) && $t['outage_mail_interval'] !== null
            ? max(1, (int)$t['outage_mail_interval'])
            : $globalInterval;

        $q = $db->prepare('SELECT id, sample_ts, loss_fraction, is_full_loss FROM target_ping_loss_events WHERE target_id=:tid AND notified=0 ORDER BY sample_ts ASC LIMIT 250');
        $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
        $rows = $q->execute();
        $events = [];
        while ($row = $rows->fetchArray(SQLITE3_ASSOC)) $events[] = $row;
        if (empty($events)) continue;

        $firstTs = (int)($events[0]['sample_ts'] ?? 0);
        if ($firstTs <= 0) continue;
        if (($now - $firstTs) < ($targetInterval * 60)) continue;

        $groups = buildPingLossGroups($events);
        if (empty($groups)) continue;

        $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
        if (empty($recipients)) continue;

        $subject = 'SmokePing - Pingverlies: ' . $t['display_name'];
        $body = buildPingLossMailBody($t, $groups, count($events));
        $res = logAndSendEmailList($db, $recipients, $subject, $body, 'ping_loss', $t['display_name']);
        if (!empty($res['success'])) {
            $ids = [];
            foreach ($events as $ev) {
                $id = (int)($ev['id'] ?? 0);
                if ($id > 0) $ids[] = $id;
            }
            if (!empty($ids)) {
                $db->exec('UPDATE target_ping_loss_events SET notified=1, notified_at=CURRENT_TIMESTAMP WHERE id IN (' . implode(',', $ids) . ')');
            }
        }
    }
}
function processOutageNotifications($db): void {
    $settings = $db->query('SELECT batch_outage_notifications, outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    $batchMode = (int)($settings['batch_outage_notifications'] ?? 1) === 1;
    $globalInterval = max(1, (int)($settings['outage_mail_interval'] ?? 5));
    $minOutageSeconds = max(20, (int)getSetting($db, 'outage_min_seconds', '20'));
    $now = time();

    if ($batchMode) {
        $subscriptionCount = [];
        $subTargets = $db->query('SELECT id, session_notify_email FROM targets WHERE session_notify_enabled=1');
        while ($st = $subTargets->fetchArray(SQLITE3_ASSOC)) {
            $tid = (int)($st['id'] ?? 0);
            if ($tid <= 0) continue;
            foreach (resolveNotifyRecipients($db, (string)($st['session_notify_email'] ?? '')) as $rcp) {
                if (!isset($subscriptionCount[$rcp])) $subscriptionCount[$rcp] = [];
                $subscriptionCount[$rcp][$tid] = 1;
            }
        }
        foreach ($subscriptionCount as $rcp => $targetMap) $subscriptionCount[$rcp] = count($targetMap);

        $pendingStart = [];
        $rsStart = $db->query('SELECT o.id, o.started_at, t.id AS target_id, t.display_name, t.host, t.session_notify_email, t.outage_mail_interval AS target_interval, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=1 AND (o.start_notified IS NULL OR o.start_notified=0) AND t.session_notify_enabled=1 AND t.enabled=1');
        while ($row = $rsStart->fetchArray(SQLITE3_ASSOC)) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = $now;
            $effInt = ($row['target_interval'] !== null) ? (int)$row['target_interval'] : $globalInterval;
            if (($now - $startTs) < $minOutageSeconds) continue;
            if (($now - $startTs) < ($effInt * 60)) continue;
            $pendingStart[] = $row;
        }

        $pendingEnd = [];
        $ignoredEndIds = [];
        $rsEnd = $db->query('SELECT o.id, o.started_at, o.ended_at, o.duration_seconds, t.id AS target_id, t.display_name, t.host, t.session_notify_email, t.outage_mail_interval AS target_interval, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=0 AND (o.end_notified IS NULL OR o.end_notified=0) AND t.session_notify_enabled=1');
        while ($row = $rsEnd->fetchArray(SQLITE3_ASSOC)) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs = parseDbDateToTs($row['ended_at'] ?? null);
            if ($startTs <= 0) $startTs = $now;
            if ($endTs <= 0) $endTs = $now;
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            $effInt = ($row['target_interval'] !== null) ? (int)$row['target_interval'] : $globalInterval;
            if ($duration < $minOutageSeconds) {
                $ignoredEndIds[] = (int)$row['id'];
                continue;
            }
            if (($now - $endTs) < ($effInt * 60)) continue;
            $pendingEnd[] = $row;
        }

        $sentStartIds = [];
        $sentEndIds = [];
        $sentTargetIds = [];
        $sentAny = false;

        if (!empty($pendingStart) || !empty($pendingEnd)) {
            $byRecipient = [];
            foreach ($pendingStart as $row) {
                foreach (resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? '')) as $rcp) {
                    if (!isset($byRecipient[$rcp])) $byRecipient[$rcp] = ['start' => [], 'end' => []];
                    $byRecipient[$rcp]['start'][] = $row;
                }
            }
            foreach ($pendingEnd as $row) {
                foreach (resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? '')) as $rcp) {
                    if (!isset($byRecipient[$rcp])) $byRecipient[$rcp] = ['start' => [], 'end' => []];
                    $byRecipient[$rcp]['end'][] = $row;
                }
            }

            foreach ($byRecipient as $rcp => $bucket) {
                $startRows = $bucket['start'];
                $endRows = $bucket['end'];
                $subCount = (int)($subscriptionCount[$rcp] ?? 1);
                $totalEvents = count($startRows) + count($endRows);

                // Bundel alle opgestapelde uitval/herstel-events in 1 mail, ook als de ontvanger
                // maar 1 target heeft (bijv. door een lange e-mailvertraging per target).
                if ($subCount > 1 || $totalEvents > 1) {
                    $subject = 'SmokePing - Uitval/herstel samenvatting (' . count($startRows) . ' nieuw, ' . count($endRows) . ' hersteld)';
                    $body = buildBatchOutageSummaryMail($startRows, $endRows, $now, $globalInterval);
                    $res = logAndSendEmail($db, $rcp, $subject, $body, 'outage_batch', 'recipient:' . $rcp);
                    if (!empty($res['success'])) {
                        foreach ($startRows as $row) {
                            $sentStartIds[(int)$row['id']] = 1;
                            $sentTargetIds[(int)$row['target_id']] = 1;
                        }
                        foreach ($endRows as $row) {
                            $sentEndIds[(int)$row['id']] = 1;
                            $sentTargetIds[(int)$row['target_id']] = 1;
                        }
                        $sentAny = true;
                    }
                    continue;
                }

                foreach ($startRows as $row) {
                    $startTs = parseDbDateToTs($row['started_at'] ?? null);
                    if ($startTs <= 0) $startTs = $now;
                    $subject = 'SmokePing - UITVAL: ' . $row['display_name'];
                    $res = logAndSendEmail($db, $rcp, $subject, buildOutageStartMailBody($row, $startTs), 'outage_start', (string)$row['display_name']);
                    if (!empty($res['success'])) {
                        $sentStartIds[(int)$row['id']] = 1;
                        $sentTargetIds[(int)$row['target_id']] = 1;
                        $sentAny = true;
                    }
                }

                foreach ($endRows as $row) {
                    $startTs = parseDbDateToTs($row['started_at'] ?? null);
                    $endTs = parseDbDateToTs($row['ended_at'] ?? null);
                    if ($startTs <= 0) $startTs = $now;
                    if ($endTs <= 0) $endTs = $now;
                    $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
                    $subject = 'SmokePing - Uitval opgelost: ' . $row['display_name'];
                    $res = logAndSendEmail($db, $rcp, $subject, buildOutageEndMailBody($row, $startTs, $endTs, $duration), 'outage_end', (string)$row['display_name']);
                    if (!empty($res['success'])) {
                        $sentEndIds[(int)$row['id']] = 1;
                        $sentTargetIds[(int)$row['target_id']] = 1;
                        $sentAny = true;
                    }
                }
            }
        }

        if (!empty($ignoredEndIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id IN (' . implode(',', array_map('intval', $ignoredEndIds)) . ')');
        }
        if (!empty($sentStartIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1 WHERE id IN (' . implode(',', array_keys($sentStartIds)) . ')');
        }
        if (!empty($sentEndIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id IN (' . implode(',', array_keys($sentEndIds)) . ')');
        }
        if (!empty($sentTargetIds)) {
            $nowDt = date('Y-m-d H:i:s');
            foreach (array_keys($sentTargetIds) as $tid) {
                $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
                $ut->bindValue(':dt', $nowDt, SQLITE3_TEXT);
                $ut->bindValue(':id', (int)$tid, SQLITE3_INTEGER);
                $ut->execute();
            }
        }
        if ($sentAny) {
            $db->exec("UPDATE email_settings SET last_outage_batch_sent=CURRENT_TIMESTAMP WHERE id=1");
        }
    } else {
        // Individuele mode
        $rows = $db->query('SELECT o.id, o.started_at, t.id AS target_id, t.display_name, t.host, t.session_notify_enabled, t.session_notify_email, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=1 AND (o.start_notified IS NULL OR o.start_notified=0) AND t.session_notify_enabled=1 AND t.enabled=1');
        $sentAnyStart = false;
        while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
            $recipients = resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? ''));
            if (empty($recipients)) continue;
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = $now;
            if (($now - $startTs) < $minOutageSeconds) continue;
            $subject = 'SmokePing - UITVAL: ' . $row['display_name'];
            logAndSendEmailList($db, $recipients, $subject, buildOutageStartMailBody($row, $startTs), 'outage_start', $row['display_name']);
            $u = $db->prepare('UPDATE target_outages SET start_notified=1 WHERE id=:id');
            $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER); $u->execute();
            $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
            $ut->bindValue(':dt', date('Y-m-d H:i:s'), SQLITE3_TEXT); $ut->bindValue(':id', (int)$row['target_id'], SQLITE3_INTEGER); $ut->execute();
            $sentAnyStart = true;
        }
        if ($sentAnyStart) $db->exec("UPDATE email_settings SET last_outage_batch_sent=CURRENT_TIMESTAMP WHERE id=1");
        // Recovery emails in individual mode
        $rows2 = $db->query('SELECT o.id, o.started_at, o.ended_at, o.duration_seconds, t.id AS target_id, t.display_name, t.host, t.session_notify_enabled, t.session_notify_email, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=0 AND o.start_notified=1 AND (o.end_notified IS NULL OR o.end_notified=0) AND t.session_notify_enabled=1');
        while ($row = $rows2->fetchArray(SQLITE3_ASSOC)) {
            $recipients = resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? ''));
            if (empty($recipients)) continue;
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs = parseDbDateToTs($row['ended_at'] ?? null);
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            if ($duration < $minOutageSeconds) {
                $u = $db->prepare('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id=:id');
                $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER);
                $u->execute();
                continue;
            }
            $subject = 'SmokePing - Uitval opgelost: ' . $row['display_name'];
            logAndSendEmailList($db, $recipients, $subject, buildOutageEndMailBody($row, $startTs, $endTs, $duration), 'outage_end', $row['display_name']);
            $u = $db->prepare('UPDATE target_outages SET end_notified=1 WHERE id=:id');
            $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER); $u->execute();
            $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
            $ut->bindValue(':dt', date('Y-m-d H:i:s'), SQLITE3_TEXT); $ut->bindValue(':id', (int)$row['target_id'], SQLITE3_INTEGER); $ut->execute();
        }
    }
}

// === MAIN ===
$db = getDB();
// Uitval tracking bijwerken
foreach (getAllTargets($db) as $target) {
    $status = getTargetStatus($target['cat_name'], $target['name']);
    syncTargetOutageState($db, $target, $status);
    logPingLossSample($db, $target, $status);
}
// Notificaties verwerken
processSessionEndNotifications($db);
processOutageNotifications($db);
processPingLossNotifications($db);
$autoBackup = runAutoBackupIfDue($db);
if (empty($autoBackup['skipped'])) {
    echo date('Y-m-d H:i:s') . ' smokeping-notify: ' . ($autoBackup['msg'] ?? 'Automatische backup uitgevoerd') . "\n";
}
echo date('Y-m-d H:i:s') . " smokeping-notify: sessie+uitval notificaties verwerkt\n";
ENDOFNOTIFYPHP
}

deploy_php() {
cat > "$WEBDIR/index.php" << 'ENDOFPHP'
<?php
session_start();
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
$tz = trim((string)@file_get_contents('/etc/timezone'));
if ($tz === '') $tz = 'Europe/Amsterdam';
@date_default_timezone_set($tz);

define('DB_PATH', __DIR__ . '/data/smokeping_manager.db');
define('BACKUP_DIR', __DIR__ . '/data/backups');
define('SMOKEPING_CONF_DIR', '/etc/smokeping/config.d');
define('SMOKEPING_TARGETS_FILE', SMOKEPING_CONF_DIR . '/Targets');
define('SMOKEPING_PROBES_FILE', SMOKEPING_CONF_DIR . '/Probes');
define('SMOKEPING_DATA_DIR', '/var/lib/smokeping');
define('SMOKEPING_CGI_URL', '/smokeping/smokeping.cgi');
define('APP_TITLE', 'SmokePing Manager');
define('APP_VERSION', '5.9');

define('SECRET_KEY_FILE', __DIR__ . '/data/.secret_key');

function smGetOrCreateSecretKey(): string {
    $f = SECRET_KEY_FILE;
    if (is_file($f)) { $k = trim((string)@file_get_contents($f)); if (strlen($k) === 64) return $k; }
    $k = bin2hex(random_bytes(32));
    @file_put_contents($f, $k); @chmod($f, 0600);
    return $k;
}
function smEncryptPassword(string $plain): string {
    if ($plain === '') return '';
    $key = hex2bin(smGetOrCreateSecretKey());
    $iv = random_bytes(16);
    $cipher = openssl_encrypt($plain, 'AES-256-CBC', $key, OPENSSL_RAW_DATA, $iv);
    return $cipher !== false ? 'enc:' . base64_encode($iv . $cipher) : $plain;
}
function smDecryptPassword(string $stored): string {
    if ($stored === '' || strpos($stored, 'enc:') !== 0) return $stored;
    $key = hex2bin(smGetOrCreateSecretKey());
    $raw = base64_decode(substr($stored, 4));
    if ($raw === false || strlen($raw) < 17) return '';
    $plain = openssl_decrypt(substr($raw, 16), 'AES-256-CBC', $key, OPENSSL_RAW_DATA, substr($raw, 0, 16));
    return $plain !== false ? $plain : '';
}

function redirectToLogin(string $message = ''): void {
    if ($message !== '') {
        $_SESSION['flash'] = ['msg' => $message, 'type' => 'error', 'ts' => time()];
    }
    header('Location:?p=login');
    exit;
}

function detectExistingRrdStep(): int {
    if (!is_dir(SMOKEPING_DATA_DIR)) return 0;
    $cmd = "find " . escapeshellarg(SMOKEPING_DATA_DIR) . " -type f -name '*.rrd' | head -n 10";
    $list = trim((string)@shell_exec($cmd . " 2>/dev/null"));
    if ($list === '') return 0;

    $rrdtool = 'rrdtool';
    foreach (['/usr/bin/rrdtool', '/usr/local/bin/rrdtool'] as $candidate) {
        if (is_file($candidate)) { $rrdtool = $candidate; break; }
    }

    foreach (preg_split('/\r\n|\n|\r/', $list) as $rrdFile) {
        $rrdFile = trim((string)$rrdFile);
        if ($rrdFile === '') continue;
        $info = (string)@shell_exec($rrdtool . ' info ' . escapeshellarg($rrdFile) . " 2>/dev/null");
        if (preg_match('/^step\s*=\s*(\d+)/mi', $info, $m)) {
            return (int)$m[1];
        }
    }
    return 0;
}

class TrackedSQLite3 extends SQLite3 {
    public function query($query) {
        $t0 = microtime(true);
        $res = parent::query($query);
        $GLOBALS['SM_SQL_COUNT'] = (int)($GLOBALS['SM_SQL_COUNT'] ?? 0) + 1;
        $GLOBALS['SM_SQL_MS'] = (float)($GLOBALS['SM_SQL_MS'] ?? 0.0) + ((microtime(true) - $t0) * 1000);
        return $res;
    }
    public function exec($query): bool {
        $t0 = microtime(true);
        $res = parent::exec($query);
        $GLOBALS['SM_SQL_COUNT'] = (int)($GLOBALS['SM_SQL_COUNT'] ?? 0) + 1;
        $GLOBALS['SM_SQL_MS'] = (float)($GLOBALS['SM_SQL_MS'] ?? 0.0) + ((microtime(true) - $t0) * 1000);
        return $res;
    }
    public function prepare($query): SQLite3Stmt|false {
        $t0 = microtime(true);
        $stmt = parent::prepare($query);
        $GLOBALS['SM_SQL_COUNT'] = (int)($GLOBALS['SM_SQL_COUNT'] ?? 0) + 1;
        $GLOBALS['SM_SQL_MS'] = (float)($GLOBALS['SM_SQL_MS'] ?? 0.0) + ((microtime(true) - $t0) * 1000);
        return $stmt;
    }
}

function getDB(): SQLite3 {
    $db = new TrackedSQLite3(DB_PATH);
    $db->busyTimeout(5000);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, email TEXT DEFAULT "", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, display_name TEXT NOT NULL, probe TEXT DEFAULT "FPing",
        remark TEXT DEFAULT "", sort_order INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL, name TEXT NOT NULL, display_name TEXT NOT NULL,
        host TEXT NOT NULL, host_ipv6 TEXT DEFAULT "", probe TEXT DEFAULT "", menu_name TEXT DEFAULT "",
        remark TEXT DEFAULT "", alert TEXT DEFAULT "", session_duration TEXT DEFAULT "unlimited",
        session_notify_enabled INTEGER DEFAULT 0, session_notify_email TEXT DEFAULT "",
        session_started_at DATETIME DEFAULT NULL, session_start_notified INTEGER DEFAULT 0, session_end_notified INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0, submission_source TEXT DEFAULT "",
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE)');
    $db->exec('CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, binary_path TEXT DEFAULT "/usr/bin/fping",
        protocol TEXT DEFAULT "", step INTEGER DEFAULT 300, pings INTEGER DEFAULT 20,
        extra_config TEXT DEFAULT "", enabled INTEGER DEFAULT 1)');
    $db->exec('CREATE TABLE IF NOT EXISTS settings (
        k TEXT PRIMARY KEY, v TEXT)');
    $db->exec('CREATE TABLE IF NOT EXISTS rrd_reset_logs (
        id INTEGER PRIMARY KEY, username TEXT NOT NULL, category_name TEXT NOT NULL, target_name TEXT NOT NULL,
        rrd_file TEXT NOT NULL, ip_address TEXT DEFAULT "", action TEXT DEFAULT "reset", 
        result TEXT DEFAULT "success", details TEXT DEFAULT "", created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS target_outages (
        id INTEGER PRIMARY KEY,
        target_id INTEGER NOT NULL,
        started_at DATETIME NOT NULL,
        ended_at DATETIME DEFAULT NULL,
        duration_seconds INTEGER DEFAULT NULL,
        is_open INTEGER DEFAULT 1,
        start_source_ts INTEGER DEFAULT NULL,
        end_source_ts INTEGER DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_target_outages_target_started ON target_outages(target_id, started_at DESC)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_target_outages_open ON target_outages(target_id, is_open)');
    $db->exec('CREATE TABLE IF NOT EXISTS email_settings (
        id INTEGER PRIMARY KEY, smtp_enabled INTEGER DEFAULT 0, smtp_host TEXT DEFAULT "",
        smtp_port INTEGER DEFAULT 587, smtp_encryption TEXT DEFAULT "tls", smtp_username TEXT DEFAULT "",
        smtp_password TEXT DEFAULT "", smtp_from_email TEXT DEFAULT "", smtp_from_name TEXT DEFAULT "SmokePing Manager",
        alert_enabled INTEGER DEFAULT 0, alert_targets TEXT DEFAULT "all", alert_threshold INTEGER DEFAULT 95,
        alert_interval_minutes INTEGER DEFAULT 15, mail_threshold REAL DEFAULT 5.0,
        alert_recipients TEXT DEFAULT "", updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS mail_log (
        id INTEGER PRIMARY KEY,
        type TEXT DEFAULT "notification",
        target_name TEXT DEFAULT "",
        email_to TEXT DEFAULT "",
        subject TEXT DEFAULT "",
        status TEXT DEFAULT "failed",
        message TEXT DEFAULT "",
        debug_output TEXT DEFAULT "",
        body TEXT DEFAULT "",
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    // migrate: add body column if missing
    @$db->exec('ALTER TABLE mail_log ADD COLUMN body TEXT DEFAULT ""');
    $db->exec('CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY,
        user_id INTEGER DEFAULT 0,
        username TEXT DEFAULT "",
        action_type TEXT DEFAULT "",
        description TEXT DEFAULT "",
        ip_address TEXT DEFAULT "",
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_activity_log_created ON activity_log(created_at DESC)');
    // Ensure email_settings has at least one row
    $s = $db->prepare('SELECT COUNT(*) c FROM email_settings'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) { $db->exec('INSERT INTO email_settings (id) VALUES (1)'); }
    // Create alerts table for alert configurations
    $db->exec('CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, display_name TEXT NOT NULL,
        type TEXT DEFAULT "email", threshold_loss REAL DEFAULT 0.05, threshold_duration INTEGER DEFAULT 300,
        notification_method TEXT DEFAULT "email", recipients TEXT DEFAULT "",
        enabled INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS custom_graphs (
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        group_name TEXT NOT NULL DEFAULT "Samengestelde grafieken",
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS custom_graph_members (
        id INTEGER PRIMARY KEY,
        graph_id INTEGER NOT NULL,
        target_id INTEGER NOT NULL,
        mode TEXT NOT NULL DEFAULT "ipv4",
        sort_order INTEGER DEFAULT 0,
        FOREIGN KEY (graph_id) REFERENCES custom_graphs(id) ON DELETE CASCADE,
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE)');
    // Add default alert if none exist
    $s = $db->prepare('SELECT COUNT(*) c FROM alerts'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) {
        $db->exec("INSERT INTO alerts (name, display_name, type, threshold_loss, recipients) VALUES ('default_alert', 'Standaard Alert (5% loss)', 'email', 0.05, '')");
        $db->exec("INSERT INTO alerts (name, display_name, type, threshold_loss, recipients) VALUES ('critical_alert', 'Kritieke Alert (10% loss)', 'email', 0.10, '')");
    }
    // Migrate existing users table if needed
    try { $db->exec('ALTER TABLE users ADD COLUMN role TEXT DEFAULT "manager"'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN email TEXT DEFAULT ""'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN auth_provider TEXT DEFAULT "local"'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN google_sub TEXT DEFAULT ""'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN google_email TEXT DEFAULT ""'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN approval_status TEXT DEFAULT "active"'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN requested_at DATETIME DEFAULT CURRENT_TIMESTAMP'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN approved_at DATETIME DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN approved_by INTEGER DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE users ADD COLUMN last_login_at DATETIME DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_duration TEXT DEFAULT "unlimited"'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_notify_enabled INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_notify_email TEXT DEFAULT ""'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_started_at DATETIME DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_start_notified INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN session_end_notified INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN alert_interval_minutes INTEGER DEFAULT 15'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN mail_threshold REAL DEFAULT 5.0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN outage_mail_interval INTEGER DEFAULT 5'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN batch_outage_notifications INTEGER DEFAULT 1'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN last_outage_batch_sent DATETIME DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE email_settings ADD COLUMN ping_loss_notifications INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE target_outages ADD COLUMN start_notified INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE target_outages ADD COLUMN end_notified INTEGER DEFAULT 0'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN outage_mail_interval INTEGER DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN last_outage_notified_at DATETIME DEFAULT NULL'); } catch(\Exception $e) {}
    try { $db->exec('ALTER TABLE targets ADD COLUMN user_id INTEGER DEFAULT 0'); } catch(\Exception $e) {}
        try { $db->exec('ALTER TABLE targets ADD COLUMN submission_source TEXT DEFAULT ""'); } catch(\Exception $e) {}
    $db->exec('UPDATE targets SET session_duration="unlimited" WHERE session_duration IS NULL OR TRIM(session_duration)=""');
    // One-time data fill: populate empty/placeholder remarks with target display name.
    $db->exec('UPDATE targets SET remark=display_name WHERE remark IS NULL OR TRIM(remark)="" OR remark="<LEEG>"');
        $db->exec('UPDATE targets SET submission_source="public_queue" WHERE (submission_source IS NULL OR TRIM(submission_source)="") AND enabled=0 AND COALESCE(user_id,0)=0 AND COALESCE(probe,"")="" AND COALESCE(menu_name,"")="" AND COALESCE(session_notify_enabled,0)=0 AND COALESCE(session_notify_email,"")=""');
    
    // Create permissions table for user page visibility control
    $db->exec('CREATE TABLE IF NOT EXISTS user_permissions (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        page_key TEXT NOT NULL,
        is_visible INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, page_key),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)');
    $db->exec('CREATE TABLE IF NOT EXISTS user_invites (
        id INTEGER PRIMARY KEY,
        user_id INTEGER NOT NULL,
        email TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used_at DATETIME DEFAULT NULL,
        created_by INTEGER DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_invites_token_hash ON user_invites(token_hash)');
    $db->exec('CREATE INDEX IF NOT EXISTS idx_user_invites_user_id ON user_invites(user_id)');
    $db->exec('UPDATE targets SET session_started_at=COALESCE(created_at, CURRENT_TIMESTAMP) WHERE session_started_at IS NULL OR TRIM(session_started_at)=""');
    $db->exec('UPDATE email_settings SET alert_interval_minutes=15 WHERE alert_interval_minutes IS NULL OR alert_interval_minutes<=0');
    $db->exec('UPDATE email_settings SET mail_threshold=5.0 WHERE mail_threshold IS NULL OR mail_threshold<0');
    // Remove problematic DNS probe if it exists
    $db->exec('DELETE FROM probes WHERE name="DNS" AND binary_path="/usr/bin/dig"');
    // Clear any target probe references to non-working probes
    $db->exec('UPDATE targets SET probe="" WHERE probe NOT IN ("","FPing","FPing6")');
    
    $s = $db->prepare('SELECT COUNT(*) c FROM users'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) { $s = $db->prepare('INSERT INTO users (username,password,role) VALUES(:u,:p,:r)');
        $s->bindValue(':u','admin'); $s->bindValue(':p',password_hash('admin',PASSWORD_BCRYPT)); $s->bindValue(':r','admin'); $s->execute(); }
    // Ensure admin user has admin role (for existing installations)
    $db->exec('UPDATE users SET role="admin" WHERE id=1');
    $db->exec('UPDATE users SET role="admin" WHERE username="admin" AND (role IS NULL OR role="manager")');
    $db->exec('UPDATE users SET auth_provider="local" WHERE auth_provider IS NULL OR TRIM(auth_provider)=""');
    $db->exec('UPDATE users SET email=google_email WHERE (email IS NULL OR TRIM(email)="") AND google_email IS NOT NULL AND TRIM(google_email)!=""');
    $db->exec('UPDATE users SET approval_status="active" WHERE approval_status IS NULL OR TRIM(approval_status)=""');
    $db->exec('DELETE FROM user_invites WHERE used_at IS NOT NULL AND used_at < datetime("now", "-30 days")');
    $db->exec('DELETE FROM user_invites WHERE expires_at < datetime("now", "-30 days")');
    $s = $db->prepare('SELECT COUNT(*) c FROM probes'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) {
        // Keep defaults aligned with existing RRD history in common installs.
        $db->exec("INSERT INTO probes (name,binary_path,protocol,step,pings) VALUES ('FPing','/usr/bin/fping','',10,5)");
        $db->exec("INSERT INTO probes (name,binary_path,protocol,step,pings) VALUES ('FPing6','/usr/bin/fping','6',10,5)");
    }
    // Do not auto-change existing step/pings values; that can break running RRD history.
    $existingRrdStep = detectExistingRrdStep();
    if ($existingRrdStep > 0) {
        $probeStep = (int)$db->querySingle('SELECT step FROM probes WHERE name="FPing" LIMIT 1');
        if ($probeStep > 0 && $probeStep !== $existingRrdStep) {
            $stmt = $db->prepare('UPDATE probes SET step=:st WHERE name IN ("FPing","FPing6")');
            $stmt->bindValue(':st', $existingRrdStep, SQLITE3_INTEGER);
            $stmt->execute();
        }
    }
    $db->exec('UPDATE probes SET extra_config="packetsize = 56" WHERE name IN ("FPing","FPing6") AND (extra_config IS NULL OR TRIM(extra_config)="")');
    return $db;
}
$db = getDB();

function isLoggedIn(): bool { return isset($_SESSION['uid']); }
function requireLogin() { if (!isLoggedIn()) { redirectToLogin('Je sessie is verlopen. Log opnieuw in.'); } }
function getUserRole($db): string { if (!isLoggedIn()) return ''; $s=$db->prepare('SELECT role FROM users WHERE id=:id'); $s->bindValue(':id',$_SESSION['uid'],SQLITE3_INTEGER); $r=$s->execute()->fetchArray(); return $r['role']??'manager'; }
function isAdmin($db): bool { $role=getUserRole($db); return $role==='admin' || $_SESSION['uid']==1; }
function canManage($db): bool { $r=getUserRole($db); return $r==='admin'||$r==='manager'||$_SESSION['uid']==1; }
function isReadOnly($db): bool { return getUserRole($db)==='readonly'; }
function isUser($db): bool { return getUserRole($db)==='user'; }
function getActionPermissionDefinitions(): array {
    return [
        'act_targets_add' => ['label' => 'Targets toevoegen', 'group' => 'Targets'],
        'act_targets_queue' => ['label' => 'Wachtrij beheren/toepassen', 'group' => 'Targets'],
        'act_targets_edit' => ['label' => 'Targets bewerken', 'group' => 'Targets'],
        'act_targets_delete' => ['label' => 'Targets verwijderen', 'group' => 'Targets'],
        'act_targets_move' => ['label' => 'Targets/categorieen verplaatsen & volgorde', 'group' => 'Targets'],
        'act_targets_toggle' => ['label' => 'Targets activeren/deactiveren', 'group' => 'Targets'],
        'act_categories_manage' => ['label' => 'Categorieen toevoegen/bewerken/verwijderen', 'group' => 'Targets'],
        'act_graphs_manage' => ['label' => 'Samengestelde grafieken beheren', 'group' => 'Targets'],
        'act_rrd_manage' => ['label' => 'RRD data wissen/resetten', 'group' => 'Targets'],
        'act_config_manage' => ['label' => 'Config opslaan/sync/restart/rebuild', 'group' => 'Systeem'],
        'act_backups_manage' => ['label' => 'Backups maken/herstellen/upload/download', 'group' => 'Systeem'],
        'act_mail_use' => ['label' => 'Mailfuncties gebruiken (test/queue/sessie)', 'group' => 'Meldingen'],
        'act_mail_settings' => ['label' => 'Mailinstellingen wijzigen', 'group' => 'Meldingen'],
        'act_alerts_manage' => ['label' => 'Alerts beheren', 'group' => 'Meldingen'],
    ];
}
function getActionPermissionDefaultsForRole(string $role): array {
    $defs = getActionPermissionDefinitions();
    $defaults = [];
    foreach ($defs as $key => $_meta) $defaults[$key] = 0;
    if ($role === 'manager') {
        foreach ($defs as $key => $_meta) $defaults[$key] = 1;
        return $defaults;
    }
    if ($role === 'user') {
        foreach (['act_targets_add','act_targets_edit','act_targets_delete','act_targets_move','act_targets_toggle','act_categories_manage','act_graphs_manage','act_rrd_manage','act_config_manage'] as $k) {
            if (isset($defaults[$k])) $defaults[$k] = 1;
        }
    }
    return $defaults;
}
function getActionPermissions($db, int $userId, string $role): array {
    $defs = getActionPermissionDefinitions();
    $perms = getActionPermissionDefaultsForRole($role);
    if ($userId <= 0 || empty($defs)) return $perms;
    try {
        $s = $db->prepare('SELECT page_key, is_visible FROM user_permissions WHERE user_id=:uid AND page_key LIKE "act_%"');
        if (!$s) return $perms;
        $s->bindValue(':uid', $userId, SQLITE3_INTEGER);
        $r = $s->execute();
        if (!$r) return $perms;
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            $k = (string)($row['page_key'] ?? '');
            if (isset($defs[$k])) $perms[$k] = ((int)($row['is_visible'] ?? 0) === 1) ? 1 : 0;
        }
    } catch (\Exception $e) {
        return $perms;
    }
    return $perms;
}
function hasActionPermission($db, string $permissionKey): bool {
    if (isAdmin($db)) return true;
    if (!isLoggedIn()) return false;
    $defs = getActionPermissionDefinitions();
    if (!isset($defs[$permissionKey])) return false;
    $uid = (int)($_SESSION['uid'] ?? 0);
    $role = getUserRole($db);
    $perms = getActionPermissions($db, $uid, $role);
    return !empty($perms[$permissionKey]);
}
function canCrudTargets($db): bool { return hasActionPermission($db, 'act_targets_add'); }
function canAccessSafeSettings($db): bool { return isAdmin($db) || canManage($db); }

function canEditTarget($db, int $targetId): bool {
    $role = getUserRole($db);
    if ($role === 'admin' || $role === 'manager' || $role === 'user') return true;
    return false;
}

function getPageVisibility($db, int $userId): array {
    $pages = ['targets' => 1, 'dashboard' => 1, 'database' => 0, 'settings' => 0, 'logging' => 0];
    try {
        $s = $db->prepare('SELECT page_key, is_visible FROM user_permissions WHERE user_id=:uid');
        if (!$s) return $pages;
        $s->bindValue(':uid', $userId, SQLITE3_INTEGER);
        $r = $s->execute();
        if (!$r) return $pages;
        $perms = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            $perms[$row['page_key']] = (int)$row['is_visible'];
        }
        return array_merge($pages, $perms);
    } catch (\Exception $e) {
        return $pages;
    }
}

function setPageVisibility($db, int $userId, string $pageKey, int $isVisible): void {
    try {
        $ins = $db->prepare('INSERT OR REPLACE INTO user_permissions(user_id, page_key, is_visible, updated_at) VALUES(:uid, :key, :vis, CURRENT_TIMESTAMP)');
        if (!$ins) return;
        $ins->bindValue(':uid', $userId, SQLITE3_INTEGER);
        $ins->bindValue(':key', $pageKey);
        $ins->bindValue(':vis', $isVisible, SQLITE3_INTEGER);
        $ins->execute();
    } catch (\Exception $e) {
        // Silently ignore permission setting errors
    }
}
function redir(string $p, array $q=[]): void { $u='?p='.urlencode($p); foreach($q as $k=>$v) $u.='&'.urlencode($k).'='.urlencode($v); header("Location:$u"); exit; }
function clearCurrentSession(bool $restartSession = true): void {
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    if ($restartSession) session_start();
}
function getPublicBaseUrl(): string {
    $scheme = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $scheme = strtolower(trim((string)explode(',', (string)$_SERVER['HTTP_X_FORWARDED_PROTO'])[0])) === 'https' ? 'https' : 'http';
    } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $scheme = 'https';
    }
    $host = trim((string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost'));
    if (strpos($host, ',') !== false) $host = trim((string)explode(',', $host)[0]);
    if ($host === '') $host = 'localhost';
    $basePath = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    if ($basePath === '.' || $basePath === '/') $basePath = '';
    return $scheme . '://' . $host . $basePath;
}
function getGoogleAuthSettings($db): array {
    return [
        'enabled' => getSetting($db, 'google_auth_enabled', '0') === '1',
        'client_id' => trim((string)getSetting($db, 'google_client_id', '')),
        'client_secret' => trim((string)smDecryptPassword((string)getSetting($db, 'google_client_secret', ''))),
        'redirect_uri' => trim((string)getSetting($db, 'google_redirect_uri', '')),
    ];
}
function buildGoogleRedirectUri($db): string {
    $settings = getGoogleAuthSettings($db);
    if ($settings['redirect_uri'] !== '') return $settings['redirect_uri'];
    return getPublicBaseUrl() . '/?p=google_callback';
}
function httpRequestJson(string $url, string $method = 'GET', array $headers = [], ?string $body = null): array {
    $headerLines = array_merge(['Accept: application/json'], $headers);
    $context = stream_context_create([
        'http' => [
            'method' => $method,
            'timeout' => 20,
            'ignore_errors' => true,
            'header' => implode("\r\n", $headerLines),
            'content' => $body ?? '',
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ]);
    $response = @file_get_contents($url, false, $context);
    $status = 0;
    if (!empty($http_response_header[0]) && preg_match('/\s(\d{3})\s/', (string)$http_response_header[0], $m)) {
        $status = (int)$m[1];
    }
    return ['ok' => $response !== false, 'status' => $status, 'body' => (string)$response];
}
function buildGoogleAuthUrl($db, string $state): string {
    $settings = getGoogleAuthSettings($db);
    $params = [
        'client_id' => $settings['client_id'],
        'redirect_uri' => buildGoogleRedirectUri($db),
        'response_type' => 'code',
        'scope' => 'openid email profile',
        'state' => $state,
        'access_type' => 'offline',
        'prompt' => 'select_account',
    ];
    return 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
}
function usersTableColumns(SQLite3 $db): array {
    $cols = [];
    $q = @$db->query('PRAGMA table_info(users)');
    if ($q instanceof SQLite3Result) {
        while ($row = $q->fetchArray(SQLITE3_ASSOC)) {
            $name = strtolower((string)($row['name'] ?? ''));
            if ($name !== '') $cols[$name] = true;
        }
    }
    return $cols;
}
function userColumnExists(SQLite3 $db, string $name): bool {
    $cols = usersTableColumns($db);
    return isset($cols[strtolower($name)]);
}
function targetsTableColumns(SQLite3 $db): array {
    $cols = [];
    $q = @$db->query('PRAGMA table_info(targets)');
    if ($q instanceof SQLite3Result) {
        while ($row = $q->fetchArray(SQLITE3_ASSOC)) {
            $name = strtolower((string)($row['name'] ?? ''));
            if ($name !== '') $cols[$name] = true;
        }
    }
    return $cols;
}
function targetColumnExists(SQLite3 $db, string $name): bool {
    $cols = targetsTableColumns($db);
    return isset($cols[strtolower($name)]);
}
function insertPublicSubmittedTarget(SQLite3 $db, array $payload): array {
    $cols = targetsTableColumns($db);
    if (empty($cols)) {
        return ['success' => false, 'message' => 'Targets tabel niet beschikbaar.'];
    }

    $values = [
        'category_id' => [(int)($payload['category_id'] ?? 0), SQLITE3_INTEGER],
        'name' => [(string)($payload['name'] ?? ''), SQLITE3_TEXT],
        'display_name' => [(string)($payload['display_name'] ?? ''), SQLITE3_TEXT],
        'host' => [(string)($payload['host'] ?? ''), SQLITE3_TEXT],
        'host_ipv6' => [(string)($payload['host_ipv6'] ?? ''), SQLITE3_TEXT],
        'probe' => [(string)($payload['probe'] ?? ''), SQLITE3_TEXT],
        'menu_name' => [(string)($payload['menu_name'] ?? ''), SQLITE3_TEXT],
        'remark' => [(string)($payload['remark'] ?? ''), SQLITE3_TEXT],
        'alert' => [(string)($payload['alert'] ?? ''), SQLITE3_TEXT],
        'session_duration' => [(string)($payload['session_duration'] ?? 'unlimited'), SQLITE3_TEXT],
        'session_notify_enabled' => [(int)($payload['session_notify_enabled'] ?? 0), SQLITE3_INTEGER],
        'session_notify_email' => [(string)($payload['session_notify_email'] ?? ''), SQLITE3_TEXT],
        'session_started_at' => [null, SQLITE3_NULL],
        'session_start_notified' => [(int)($payload['session_start_notified'] ?? 0), SQLITE3_INTEGER],
        'session_end_notified' => [(int)($payload['session_end_notified'] ?? 0), SQLITE3_INTEGER],
        'sort_order' => [(int)($payload['sort_order'] ?? 0), SQLITE3_INTEGER],
        'outage_mail_interval' => [null, SQLITE3_NULL],
        'enabled' => [(int)($payload['enabled'] ?? 0), SQLITE3_INTEGER],
        'user_id' => [(int)($payload['user_id'] ?? 0), SQLITE3_INTEGER],
        'submission_source' => [(string)($payload['submission_source'] ?? ''), SQLITE3_TEXT],
    ];

    $insertCols = [];
    $placeholders = [];
    foreach ($values as $name => $_def) {
        if (isset($cols[$name])) {
            $insertCols[] = $name;
            $placeholders[] = ':' . $name;
        }
    }

    if (empty($insertCols)) {
        return ['success' => false, 'message' => 'Geen bruikbare kolommen gevonden voor targets INSERT.'];
    }

    $sql = 'INSERT INTO targets(' . implode(',', $insertCols) . ') VALUES(' . implode(',', $placeholders) . ')';
    $stmt = $db->prepare($sql);
    if (!$stmt) {
        return ['success' => false, 'message' => 'Voorbereiden INSERT mislukt: ' . (string)$db->lastErrorMsg()];
    }

    foreach ($insertCols as $col) {
        [$value, $type] = $values[$col];
        $stmt->bindValue(':' . $col, $value, $type);
    }

    $ok = $stmt->execute();
    if (!$ok) {
        return ['success' => false, 'message' => 'INSERT mislukt: ' . (string)$db->lastErrorMsg()];
    }

    return ['success' => true, 'id' => (int)$db->lastInsertRowID()];
}
function usernameExists(SQLite3 $db, string $username): bool {
    $s = $db->prepare('SELECT id FROM users WHERE username=:u LIMIT 1');
    if (!$s) return false;
    $s->bindValue(':u', $username, SQLITE3_TEXT);
    $res = $s->execute();
    if (!$res) return false;
    return (bool)$res->fetchArray(SQLITE3_ASSOC);
}
function buildGoogleUsername(SQLite3 $db, string $email, string $sub): string {
    $base = strtolower(trim((string)strtok($email, '@')));
    $base = preg_replace('/[^a-z0-9._-]+/i', '-', $base);
    if ($base === '') $base = 'google-user';
    $candidate = trim($email);
    if ($candidate !== '' && !usernameExists($db, $candidate)) return $candidate;
    $candidate = $base;
    $suffix = 2;
    while (usernameExists($db, $candidate)) {
        $candidate = $base . '-' . $suffix;
        $suffix++;
    }
    return $candidate;
}
function getGoogleUserByIdentity(SQLite3 $db, string $sub, string $email): ?array {
    if (userColumnExists($db, 'google_sub') && userColumnExists($db, 'google_email')) {
        $s = $db->prepare('SELECT * FROM users WHERE google_sub=:sub OR google_email=:mail OR username=:mail LIMIT 1');
        if (!$s) return null;
        $s->bindValue(':sub', $sub, SQLITE3_TEXT);
        $s->bindValue(':mail', $email, SQLITE3_TEXT);
    } else {
        $s = $db->prepare('SELECT * FROM users WHERE username=:mail LIMIT 1');
        if (!$s) return null;
        $s->bindValue(':mail', $email, SQLITE3_TEXT);
    }
    $res = $s->execute();
    if (!$res) return null;
    $row = $res->fetchArray(SQLITE3_ASSOC);
    return $row ?: null;
}
function createGooglePendingUser(SQLite3 $db, array $profile): array {
    $email = trim((string)($profile['email'] ?? ''));
    $sub = trim((string)($profile['sub'] ?? ''));
    $name = trim((string)($profile['name'] ?? ''));
    $username = buildGoogleUsername($db, $email, $sub);
    $hasProvider = userColumnExists($db, 'auth_provider');
    $hasGoogleSub = userColumnExists($db, 'google_sub');
    $hasGoogleEmail = userColumnExists($db, 'google_email');
    $hasApproval = userColumnExists($db, 'approval_status');
    $hasRequested = userColumnExists($db, 'requested_at');
    $hasLastLogin = userColumnExists($db, 'last_login_at');

    $columns = ['username', 'password', 'role'];
    $values = [':u', ':p', ':r'];
    if ($hasProvider) { $columns[] = 'auth_provider'; $values[] = ':ap'; }
    if ($hasGoogleSub) { $columns[] = 'google_sub'; $values[] = ':sub'; }
    if ($hasGoogleEmail) { $columns[] = 'google_email'; $values[] = ':mail'; }
    if ($hasApproval) { $columns[] = 'approval_status'; $values[] = ':st'; }
    if ($hasRequested) { $columns[] = 'requested_at'; $values[] = 'CURRENT_TIMESTAMP'; }
    if ($hasLastLogin) { $columns[] = 'last_login_at'; $values[] = 'NULL'; }

    $sql = 'INSERT INTO users(' . implode(',', $columns) . ') VALUES(' . implode(',', $values) . ')';
    $s = $db->prepare($sql);
    if (!$s) throw new RuntimeException('Kan Google-gebruiker niet voorbereiden voor insert.');
    $s->bindValue(':u', $username, SQLITE3_TEXT);
    $s->bindValue(':p', password_hash(bin2hex(random_bytes(24)), PASSWORD_BCRYPT), SQLITE3_TEXT);
    $s->bindValue(':r', 'user', SQLITE3_TEXT);
    if ($hasProvider) $s->bindValue(':ap', 'google', SQLITE3_TEXT);
    if ($hasGoogleSub) $s->bindValue(':sub', $sub, SQLITE3_TEXT);
    if ($hasGoogleEmail) $s->bindValue(':mail', $email, SQLITE3_TEXT);
    if ($hasApproval) $s->bindValue(':st', 'pending', SQLITE3_TEXT);
    if (!$s->execute()) throw new RuntimeException('Kon Google-gebruiker niet opslaan.');
    $q = $db->prepare('SELECT * FROM users WHERE id=:id');
    if (!$q) throw new RuntimeException('Kon nieuwe gebruiker niet teruglezen.');
    $q->bindValue(':id', (int)$db->lastInsertRowID(), SQLITE3_INTEGER);
    $qr = $q->execute();
    if (!$qr) throw new RuntimeException('Kon nieuwe gebruiker niet teruglezen.');
    $row = $qr->fetchArray(SQLITE3_ASSOC);
    if ($row) return $row;
    return ['id' => (int)$db->lastInsertRowID(), 'username' => $username, 'google_email' => $email, 'google_sub' => $sub, 'approval_status' => 'pending', 'auth_provider' => 'google', 'name' => $name];
}
function notifyGoogleRegistration(SQLite3 $db, array $userRow, array $profile): void {
    $recipients = resolveNotifyRecipients($db, getDefaultNotifyRecipientList($db));
    if (empty($recipients)) return;
    $username = (string)($userRow['username'] ?? '');
    $email = trim((string)($profile['email'] ?? ($userRow['google_email'] ?? '')));
    $name = trim((string)($profile['name'] ?? ''));
    $subject = 'Nieuwe Google registratie wacht op goedkeuring';
    $body = '<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937">';
    $body .= '<h2 style="margin:0 0 12px;color:#1d4ed8">Nieuwe Google registratie</h2>';
    $body .= '<p>Er is een nieuwe gebruiker geregistreerd en deze staat nu in de goedkeuringswachtrij.</p>';
    $body .= '<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;border:1px solid #e5e7eb">';
    foreach ([['Gebruikersnaam', $username], ['Google e-mail', $email], ['Naam', $name], ['Status', (string)($userRow['approval_status'] ?? 'pending')], ['Aanvraag tijd', (string)($userRow['requested_at'] ?? date('Y-m-d H:i:s'))]] as $row) {
        $body .= '<tr><td style="border-bottom:1px solid #e5e7eb;background:#f8fafc;font-weight:600">' . htmlspecialchars($row[0]) . '</td><td style="border-bottom:1px solid #e5e7eb">' . htmlspecialchars((string)$row[1]) . '</td></tr>';
    }
    $body .= '</table>';
    $body .= '<p style="margin-top:12px">Log in om de gebruiker goed te keuren in <strong>Instellingen &gt; Beheer</strong>.</p>';
    $body .= '</body></html>';
    logAndSendEmailList($db, $recipients, $subject, $body, 'notification', $username);
}
function updateUserApprovalState(SQLite3 $db, int $userId, string $approvalStatus): array {
    if ($userId <= 0) return ['success' => false, 'message' => 'Ongeldige gebruiker'];
    if (!in_array($approvalStatus, ['active', 'pending', 'rejected'], true)) return ['success' => false, 'message' => 'Ongeldige status'];
    $s = $db->prepare('SELECT id, username, approval_status FROM users WHERE id=:id');
    $s->bindValue(':id', $userId, SQLITE3_INTEGER);
    $user = $s->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$user) return ['success' => false, 'message' => 'Gebruiker niet gevonden'];
    $u = $db->prepare('UPDATE users SET approval_status=:st, approved_at=CASE WHEN :st="active" THEN CURRENT_TIMESTAMP ELSE NULL END, approved_by=CASE WHEN :st="active" THEN :by ELSE NULL END WHERE id=:id');
    $u->bindValue(':st', $approvalStatus, SQLITE3_TEXT);
    $u->bindValue(':by', (int)($_SESSION['uid'] ?? 0), SQLITE3_INTEGER);
    $u->bindValue(':id', $userId, SQLITE3_INTEGER);
    $u->execute();
    return ['success' => true, 'message' => (string)$user['username'], 'status' => $approvalStatus];
}
function buildUserInviteUrl(string $token): string {
    return getPublicBaseUrl() . '/?p=set_password&t=' . urlencode($token);
}
function createUserInvite(SQLite3 $db, int $userId, string $email, int $createdBy = 0, int $validHours = 72): array {
    $token = bin2hex(random_bytes(32));
    $tokenHash = hash('sha256', $token);
    $validHours = max(1, min(24 * 30, $validHours));
    $expiresAt = date('Y-m-d H:i:s', time() + ($validHours * 3600));

    $clear = $db->prepare('UPDATE user_invites SET used_at=CURRENT_TIMESTAMP WHERE user_id=:uid AND used_at IS NULL');
    if ($clear) {
        $clear->bindValue(':uid', $userId, SQLITE3_INTEGER);
        $clear->execute();
    }

    $s = $db->prepare('INSERT INTO user_invites(user_id,email,token_hash,expires_at,created_by) VALUES(:uid,:mail,:tok,:exp,:by)');
    if (!$s) throw new RuntimeException('Kon uitnodiging niet voorbereiden.');
    $s->bindValue(':uid', $userId, SQLITE3_INTEGER);
    $s->bindValue(':mail', $email, SQLITE3_TEXT);
    $s->bindValue(':tok', $tokenHash, SQLITE3_TEXT);
    $s->bindValue(':exp', $expiresAt, SQLITE3_TEXT);
    $s->bindValue(':by', $createdBy > 0 ? $createdBy : null, $createdBy > 0 ? SQLITE3_INTEGER : SQLITE3_NULL);
    if (!$s->execute()) throw new RuntimeException('Kon uitnodiging niet opslaan.');

    return ['token' => $token, 'expires_at' => $expiresAt, 'url' => buildUserInviteUrl($token)];
}
function findValidUserInviteByToken(SQLite3 $db, string $token): ?array {
    $token = trim($token);
    if ($token === '' || strlen($token) < 20) return null;
    $tokenHash = hash('sha256', $token);
    $q = $db->prepare('SELECT i.id AS invite_id, i.user_id, i.email, i.expires_at, u.username, u.role FROM user_invites i JOIN users u ON u.id=i.user_id WHERE i.token_hash=:tok AND i.used_at IS NULL AND i.expires_at > CURRENT_TIMESTAMP LIMIT 1');
    if (!$q) return null;
    $q->bindValue(':tok', $tokenHash, SQLITE3_TEXT);
    $res = $q->execute();
    if (!$res) return null;
    $row = $res->fetchArray(SQLITE3_ASSOC);
    return $row ?: null;
}
function markUserInviteUsed(SQLite3 $db, int $inviteId): void {
    if ($inviteId <= 0) return;
    $u = $db->prepare('UPDATE user_invites SET used_at=CURRENT_TIMESTAMP WHERE id=:id AND used_at IS NULL');
    if (!$u) return;
    $u->bindValue(':id', $inviteId, SQLITE3_INTEGER);
    $u->execute();
}
function sendUserInviteMail(SQLite3 $db, string $username, string $email, string $role, string $inviteUrl, string $expiresAt): array {
    $subject = 'Uitnodiging SmokePing Manager - stel je wachtwoord in';
    $body = '<html><body style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#1f2937">';
    $body .= '<h2 style="margin:0 0 12px;color:#1d4ed8">Welkom bij SmokePing Manager</h2>';
    $body .= '<p>Er is een account voor je aangemaakt.</p>';
    $body .= '<table cellpadding="6" cellspacing="0" style="border-collapse:collapse;border:1px solid #e5e7eb">';
    $body .= '<tr><td style="border-bottom:1px solid #e5e7eb;background:#f8fafc;font-weight:600">Gebruikersnaam</td><td style="border-bottom:1px solid #e5e7eb">' . htmlspecialchars($username) . '</td></tr>';
    $body .= '<tr><td style="border-bottom:1px solid #e5e7eb;background:#f8fafc;font-weight:600">E-mail</td><td style="border-bottom:1px solid #e5e7eb">' . htmlspecialchars($email) . '</td></tr>';
    $body .= '<tr><td style="border-bottom:1px solid #e5e7eb;background:#f8fafc;font-weight:600">Rol</td><td style="border-bottom:1px solid #e5e7eb">' . htmlspecialchars($role) . '</td></tr>';
    $body .= '<tr><td style="background:#f8fafc;font-weight:600">Link geldig tot</td><td>' . htmlspecialchars($expiresAt) . '</td></tr>';
    $body .= '</table>';
    $body .= '<p style="margin-top:14px"><a href="' . htmlspecialchars($inviteUrl) . '" style="display:inline-block;background:#1d4ed8;color:#fff;padding:10px 14px;border-radius:8px;text-decoration:none">Wachtwoord instellen</a></p>';
    $body .= '<p>Als de knop niet werkt, kopieer deze link in je browser:<br><a href="' . htmlspecialchars($inviteUrl) . '">' . htmlspecialchars($inviteUrl) . '</a></p>';
    $body .= '</body></html>';
    return logAndSendEmail($db, $email, $subject, $body, 'user_invite', $username);
}
function startGoogleAuth(SQLite3 $db): void {
    $settings = getGoogleAuthSettings($db);
    if (!$settings['enabled'] || $settings['client_id'] === '' || $settings['client_secret'] === '') {
        flash('Google Auth is nog niet geconfigureerd. Stel dit in via Instellingen > Google Auth.','error');
        redir('login');
    }
    $_SESSION['google_oauth_state'] = bin2hex(random_bytes(16));
    header('Location: ' . buildGoogleAuthUrl($db, $_SESSION['google_oauth_state']));
    exit;
}
function finishGoogleAuth(SQLite3 $db): void {
    try {
    $settings = getGoogleAuthSettings($db);
    if (!$settings['enabled'] || $settings['client_id'] === '' || $settings['client_secret'] === '') {
        flash('Google Auth is nog niet geconfigureerd.','error');
        redir('login');
    }
    $state = (string)($_GET['state'] ?? '');
    $expectedState = (string)($_SESSION['google_oauth_state'] ?? '');
    unset($_SESSION['google_oauth_state']);
    if ($state === '' || $expectedState === '' || !hash_equals($expectedState, $state)) {
        flash('Ongeldige Google inlogsessie. Probeer opnieuw.','error');
        redir('login');
    }
    $code = trim((string)($_GET['code'] ?? ''));
    if ($code === '') {
        flash('Google login geannuleerd of mislukt.','error');
        redir('login');
    }
    $tokenRes = httpRequestJson('https://oauth2.googleapis.com/token', 'POST', ['Content-Type: application/x-www-form-urlencoded'], http_build_query([
        'code' => $code,
        'client_id' => $settings['client_id'],
        'client_secret' => $settings['client_secret'],
        'redirect_uri' => buildGoogleRedirectUri($db),
        'grant_type' => 'authorization_code',
    ], '', '&', PHP_QUERY_RFC3986));
    $tokenData = json_decode($tokenRes['body'], true);
    if (empty($tokenRes['ok']) || (int)$tokenRes['status'] >= 400 || !is_array($tokenData) || empty($tokenData['access_token'])) {
        flash('Google token kon niet worden opgehaald.','error');
        redir('login');
    }
    $profileRes = httpRequestJson('https://openidconnect.googleapis.com/v1/userinfo', 'GET', ['Authorization: Bearer ' . $tokenData['access_token']]);
    $profileData = json_decode($profileRes['body'], true);
    if (empty($profileRes['ok']) || (int)$profileRes['status'] >= 400 || !is_array($profileData)) {
        flash('Google profiel kon niet worden opgehaald.','error');
        redir('login');
    }
    $email = strtolower(trim((string)($profileData['email'] ?? '')));
    $sub = trim((string)($profileData['sub'] ?? ''));
    if ($email === '' || $sub === '') {
        flash('Google-account mist verplichte gegevens.','error');
        redir('login');
    }
    if (isset($profileData['email_verified']) && !$profileData['email_verified']) {
        flash('Je Google e-mailadres is niet geverifieerd.','error');
        redir('login');
    }
    $user = getGoogleUserByIdentity($db, $sub, $email);
    if (!$user) {
        $user = createGooglePendingUser($db, $profileData);
        notifyGoogleRegistration($db, $user, $profileData);
        logActivity($db, 'google_registratie', 'Nieuwe Google registratie wacht op goedkeuring: ' . (string)$user['username']);
        flash('Je registratie is ontvangen en wacht op goedkeuring.','success');
        redir('login');
    }
    $approvalState = strtolower((string)($user['approval_status'] ?? 'active'));
    if ($approvalState !== 'active') {
        flash($approvalState === 'rejected' ? 'Je account is afgewezen door beheer.' : 'Je account wacht nog op goedkeuring door beheer.','error');
        redir('login');
    }
    $setParts = [];
    if (userColumnExists($db, 'google_sub')) $setParts[] = 'google_sub=:sub';
    if (userColumnExists($db, 'google_email')) $setParts[] = 'google_email=:mail';
    if (userColumnExists($db, 'auth_provider')) $setParts[] = 'auth_provider="google"';
    if (userColumnExists($db, 'last_login_at')) $setParts[] = 'last_login_at=CURRENT_TIMESTAMP';
    if (!empty($setParts)) {
        $u = $db->prepare('UPDATE users SET ' . implode(', ', $setParts) . ' WHERE id=:id');
        if ($u) {
            if (in_array('google_sub=:sub', $setParts, true)) $u->bindValue(':sub', $sub, SQLITE3_TEXT);
            if (in_array('google_email=:mail', $setParts, true)) $u->bindValue(':mail', $email, SQLITE3_TEXT);
            $u->bindValue(':id', (int)$user['id'], SQLITE3_INTEGER);
            $u->execute();
        }
    }
    session_regenerate_id(true);
    $_SESSION['uid'] = (int)$user['id'];
    $_SESSION['uname'] = (string)$user['username'];
    $_SESSION['last_activity'] = time();
    logActivity($db, 'login', 'Ingelogd via Google als ' . (string)$user['username']);
    flash('Welkom!');
    redir('dash');
    } catch (\Throwable $e) {
        @error_log('SmokePing Google callback fout: ' . $e->getMessage());
        flash('Google login tijdelijk mislukt. Controleer configuratie en probeer opnieuw.','error');
        redir('login');
    }
}
function flash(string $m,string $t='success') {
    $entry=['msg'=>$m,'type'=>$t,'ts'=>time()];
    $_SESSION['flash']=$entry;
    if(!isset($_SESSION['flash_history']) || !is_array($_SESSION['flash_history'])) $_SESSION['flash_history']=[];
    $_SESSION['flash_history'][]=$entry;
    if(count($_SESSION['flash_history'])>100) $_SESSION['flash_history']=array_slice($_SESSION['flash_history'],-100);
}
function getFlash(): ?array { if(isset($_SESSION['flash'])){$f=$_SESSION['flash'];unset($_SESSION['flash']);return $f;} return null; }
function getFlashHistory(): array {
    $items=$_SESSION['flash_history'] ?? [];
    if(!is_array($items)) return [];
    return array_slice($items,-100);
}
function e(string $s): string { return htmlspecialchars($s,ENT_QUOTES,'UTF-8'); }
function normalizeTargetRemark(?string $remark): string {
    return trim((string)$remark);
}
function normalizeTargetHostValue(?string $value): string {
    $value = str_replace("\xC2\xA0", ' ', (string)$value);
    return trim($value);
}
function csrf(): string { if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function csrfField(bool $asParam = false): string {
    if($asParam) return 'csrf='.csrf();
    return '<input type="hidden" name="csrf" value="'.csrf().'">';
}
function verifyCsrf(): bool { return isset($_POST['csrf'],$_SESSION['csrf'])&&hash_equals($_SESSION['csrf'],$_POST['csrf']); }

function iniSizeToBytes($val): int {
    $raw = trim((string)$val);
    if ($raw === '') return 0;
    $unit = strtolower(substr($raw, -1));
    if ($unit >= '0' && $unit <= '9') return (int)$raw;
    $num = (float)substr($raw, 0, -1);
    switch ($unit) {
        case 'g': return (int)round($num * 1024 * 1024 * 1024);
        case 'm': return (int)round($num * 1024 * 1024);
        case 'k': return (int)round($num * 1024);
        default: return (int)$num;
    }
}

$GLOBALS['SM_CACHE_HITS'] = 0;
$GLOBALS['SM_CACHE_MISSES'] = 0;
$GLOBALS['SM_SQL_COUNT'] = 0;
$GLOBALS['SM_SQL_MS'] = 0.0;
$GLOBALS['SM_REQ_START'] = microtime(true);
$GLOBALS['SM_NOTIF_MS'] = 0.0;

function smPerfStart(string $name): void {
    $marks = $GLOBALS['SM_PERF_MARKS'] ?? [];
    $marks[$name] = microtime(true);
    $GLOBALS['SM_PERF_MARKS'] = $marks;
}

function smPerfStop(string $name): float {
    $marks = $GLOBALS['SM_PERF_MARKS'] ?? [];
    if (!isset($marks[$name])) return 0.0;
    $elapsedMs = (microtime(true) - (float)$marks[$name]) * 1000;
    unset($marks[$name]);
    $GLOBALS['SM_PERF_MARKS'] = $marks;
    $blocks = $GLOBALS['SM_PERF_BLOCKS'] ?? [];
    $blocks[$name] = round((float)($blocks[$name] ?? 0.0) + $elapsedMs, 2);
    $GLOBALS['SM_PERF_BLOCKS'] = $blocks;
    return $elapsedMs;
}

function smPerfSet(string $name, float $ms): void {
    $blocks = $GLOBALS['SM_PERF_BLOCKS'] ?? [];
    $blocks[$name] = round($ms, 2);
    $GLOBALS['SM_PERF_BLOCKS'] = $blocks;
}

function smPerfBlocks(): array {
    $blocks = $GLOBALS['SM_PERF_BLOCKS'] ?? [];
    if (!is_array($blocks)) return [];
    foreach ($blocks as $key => $value) {
        $blocks[$key] = round((float)$value, 2);
    }
    ksort($blocks);
    return $blocks;
}

function smCacheFilePath(string $key): string {
    return sys_get_temp_dir().'/smokeping_mgr_cache_'.sha1($key).'.json';
}

function smApcuEnabled(): bool {
    static $enabled = null;
    if ($enabled !== null) return $enabled;
    if (!function_exists('apcu_fetch') || !function_exists('apcu_store')) {
        $enabled = false;
        return $enabled;
    }
    if (function_exists('apcu_enabled')) {
        $enabled = (bool)@apcu_enabled();
        return $enabled;
    }
    $flags = [];
    foreach (['apc.enabled', 'apcu.enabled'] as $iniKey) {
        $val = ini_get($iniKey);
        if ($val !== false && $val !== '') $flags[] = strtolower(trim((string)$val));
    }
    if (empty($flags)) {
        $enabled = true;
        return $enabled;
    }
    $enabled = in_array('1', $flags, true) || in_array('on', $flags, true) || in_array('true', $flags, true);
    return $enabled;
}

function smCacheGet(string $key, int $ttlSec, &$value = null): bool {
    if ($ttlSec <= 0) return false;
    $now = time();
    $cacheKey = 'smokeping_mgr:'.$key;
    if (smApcuEnabled()) {
        $ok = false;
        $entry = apcu_fetch($cacheKey, $ok);
        if ($ok && is_array($entry) && (int)($entry['exp'] ?? 0) >= $now) {
            $value = $entry['val'] ?? null;
            $GLOBALS['SM_CACHE_HITS'] = (int)$GLOBALS['SM_CACHE_HITS'] + 1;
            return true;
        }
    }

    $fp = smCacheFilePath($key);
    if (!is_file($fp)) return false;
    $raw = @file_get_contents($fp);
    if ($raw === false || $raw === '') return false;
    $entry = json_decode($raw, true);
    if (!is_array($entry)) return false;
    if ((int)($entry['exp'] ?? 0) < $now) return false;

    $value = $entry['val'] ?? null;
    $GLOBALS['SM_CACHE_HITS'] = (int)$GLOBALS['SM_CACHE_HITS'] + 1;
    return true;
}
function smCacheSet(string $key, $value, int $ttlSec): void {
    if ($ttlSec <= 0) return;
    $entry = ['exp' => time() + $ttlSec, 'val' => $value];
    $cacheKey = 'smokeping_mgr:'.$key;
    if (smApcuEnabled()) {
        @apcu_store($cacheKey, $entry, $ttlSec);
    }
    @file_put_contents(smCacheFilePath($key), json_encode($entry, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES), LOCK_EX);
}
function smCacheMiss(): void {
    $GLOBALS['SM_CACHE_MISSES'] = (int)$GLOBALS['SM_CACHE_MISSES'] + 1;
}

function smFetchRemoteInstallerVersion(?string &$remoteUrl = null): array {
    $remoteUrl = 'https://charlesderidder.nl/proxmox/install_smokeping_manager.sh';
    $cacheKey = 'remote_installer_version:' . APP_VERSION;
    $cached = null;
    if (smCacheGet($cacheKey, 21600, $cached) && is_array($cached)) {
        return $cached;
    }

    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 4,
            'ignore_errors' => true,
            'header' => "User-Agent: SmokePingManager/" . APP_VERSION . "\r\n",
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
        ],
    ]);
    $raw = @file_get_contents($remoteUrl, false, $context);
    $latest = '';
    if ($raw !== false && preg_match('/define\(\'APP_VERSION\',\s*\'([^\']+)\'\)/', $raw, $m)) {
        $latest = trim((string)$m[1]);
    }

    $result = [
        'latest' => $latest,
        'current' => APP_VERSION,
        'available' => ($latest !== '' && version_compare($latest, APP_VERSION, '>')),
        'checked_at' => time(),
    ];
    smCacheSet($cacheKey, $result, 21600);
    return $result;
}

function smCacheRemember(string $key, int $ttlSec, callable $producer, ?callable $validator = null) {
    $cached = null;
    if (smCacheGet($key, $ttlSec, $cached)) {
        if ($validator === null || $validator($cached)) {
            return $cached;
        }
    }
    smCacheMiss();
    $value = $producer();
    smCacheSet($key, $value, $ttlSec);
    return $value;
}

function smPathVersion($paths): string {
    $paths = is_array($paths) ? $paths : [$paths];
    $parts = [];
    foreach ($paths as $path) {
        $path = (string)$path;
        if ($path === '') continue;
        clearstatcache(false, $path);
        $parts[] = (string)((int)@filemtime($path));
    }
    return implode(':', $parts);
}

function smDbCacheVersion(): string {
    $paths = [DB_PATH, DB_PATH . '-wal', DB_PATH . '-shm'];
    return smPathVersion($paths);
}

function getPublicTargetToken($db): string {
    $token = trim((string)getSetting($db, 'public_target_token', ''));
    if ($token === '' || strlen($token) < 16) {
        $token = bin2hex(random_bytes(16));
        setSetting($db, 'public_target_token', $token);
    }
    return $token;
}
function isPublicTargetTokenValid($db, ?string $token): bool {
    $given = trim((string)$token);
    if ($given === '') return false;
    $stored = getPublicTargetToken($db);
    return hash_equals($stored, $given);
}

function getPerfMetricsFilePath(): string {
    return dirname(DB_PATH) . '/performance_metrics.log';
}
function writePerformanceMetric($db, array $metric): void {
    if (getSetting($db, 'perf_monitor_enabled', '1') !== '1') return;
    $line = json_encode($metric, JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    if (!is_string($line) || $line === '') return;
    $fp = getPerfMetricsFilePath();
    if (!is_dir(dirname($fp))) return;
    @file_put_contents($fp, $line."\n", FILE_APPEND | LOCK_EX);
}

function finalizePerformanceMetric($db, ?string $pageOverride = null): void {
    if (!empty($GLOBALS['SM_PERF_FINALIZED'])) return;
    $GLOBALS['SM_PERF_FINALIZED'] = 1;

    $reqTotalMs = round((microtime(true) - (float)($GLOBALS['SM_REQ_START'] ?? microtime(true))) * 1000, 2);
    $blocks = smPerfBlocks();
    $metric = [
        'ts' => time(),
        'page' => $pageOverride !== null ? $pageOverride : (string)($GLOBALS['SM_PERF_PAGE'] ?? $GLOBALS['page'] ?? 'unknown'),
        'method' => (string)($_SERVER['REQUEST_METHOD'] ?? 'GET'),
        'uri' => (string)($_SERVER['REQUEST_URI'] ?? ''),
        'total_ms' => $reqTotalMs,
        'notif_ms' => (float)($GLOBALS['SM_NOTIF_MS'] ?? 0.0),
        'cache_hits' => (int)($GLOBALS['SM_CACHE_HITS'] ?? 0),
        'cache_misses' => (int)($GLOBALS['SM_CACHE_MISSES'] ?? 0),
        'sql_count' => (int)($GLOBALS['SM_SQL_COUNT'] ?? 0),
        'sql_ms' => round((float)($GLOBALS['SM_SQL_MS'] ?? 0.0), 2),
        'peak_mem_mb' => round((memory_get_peak_usage(true) / 1048576), 2),
        'load1' => (float)(sys_getloadavg()[0] ?? 0.0),
    ];
    if (!empty($blocks)) $metric['blocks'] = $blocks;

    writePerformanceMetric($db, $metric);
    if (isLoggedIn() && isAdmin($db) && getSetting($db, 'perf_debug_headers', '0') === '1' && !headers_sent()) {
        header('X-Perf-Total-Ms: '.$reqTotalMs);
        header('X-Perf-Cache-Hits: '.(int)($metric['cache_hits'] ?? 0));
        header('X-Perf-Cache-Misses: '.(int)($metric['cache_misses'] ?? 0));
        header('X-Perf-Notif-Ms: '.round((float)($metric['notif_ms'] ?? 0), 2));
        foreach (['maintenance_ms', 'settings_prep_ms', 'targets_prep_ms', 'dash_prep_ms', 'target_status_api_ms'] as $blockKey) {
            if (isset($blocks[$blockKey])) {
                header('X-Perf-'.str_replace('_', '-', ucwords($blockKey, '_')).': '.round((float)$blocks[$blockKey], 2));
            }
        }
    }
}

function summarizePerformanceMetrics(int $windowSec = 86400): array {
    $file = getPerfMetricsFilePath();
    $empty = ['total'=>0,'avg_ms'=>0.0,'p95_ms'=>0.0,'p99_ms'=>0.0,'by_page'=>[],'top_slowest'=>[],'cache'=>['hits'=>0,'misses'=>0],'sql'=>['count'=>0,'ms'=>0.0],'server'=>['max_load1'=>0.0,'max_mem_mb'=>0.0],'blocks'=>[]];
    if (!is_file($file)) return $empty;

    $cutoff = time() - max(60, $windowSec);
    $rows = [];
    $fh = @fopen($file, 'rb');
    if (!$fh) return $empty;
    while (($line = fgets($fh)) !== false) {
        $line = trim($line);
        if ($line === '') continue;
        $row = json_decode($line, true);
        if (!is_array($row)) continue;
        $ts = (int)($row['ts'] ?? 0);
        if ($ts > 0 && $ts < $cutoff) continue;
        $rows[] = $row;
    }
    @fclose($fh);
    if (empty($rows)) return $empty;

    $durations = [];
    $byPageDur = [];
    $cacheHits = 0;
    $cacheMisses = 0;
    $sqlCount = 0;
    $sqlMs = 0.0;
    $maxLoad = 0.0;
    $maxMem = 0.0;
    $blockAgg = [];
    foreach ($rows as $row) {
        $ms = (float)($row['total_ms'] ?? 0.0);
        $durations[] = $ms;
        $p = (string)($row['page'] ?? 'unknown');
        if (!isset($byPageDur[$p])) $byPageDur[$p] = [];
        $byPageDur[$p][] = $ms;
        $cacheHits += (int)($row['cache_hits'] ?? 0);
        $cacheMisses += (int)($row['cache_misses'] ?? 0);
        $sqlCount += (int)($row['sql_count'] ?? 0);
        $sqlMs += (float)($row['sql_ms'] ?? 0.0);
        $maxLoad = max($maxLoad, (float)($row['load1'] ?? 0.0));
        $maxMem = max($maxMem, (float)($row['peak_mem_mb'] ?? 0.0));
        if (!empty($row['blocks']) && is_array($row['blocks'])) {
            foreach ($row['blocks'] as $blockKey => $blockMs) {
                if (!isset($blockAgg[$blockKey])) $blockAgg[$blockKey] = ['count' => 0, 'sum_ms' => 0.0, 'max_ms' => 0.0];
                $blockAgg[$blockKey]['count']++;
                $blockAgg[$blockKey]['sum_ms'] += (float)$blockMs;
                $blockAgg[$blockKey]['max_ms'] = max($blockAgg[$blockKey]['max_ms'], (float)$blockMs);
            }
        }
    }

    sort($durations);
    $count = count($durations);
    $avg = array_sum($durations) / max(1, $count);
    $p95 = $durations[(int)max(0, ceil($count * 0.95) - 1)] ?? 0.0;
    $p99 = $durations[(int)max(0, ceil($count * 0.99) - 1)] ?? 0.0;

    $byPage = [];
    foreach ($byPageDur as $page => $vals) {
        sort($vals);
        $n = count($vals);
        $byPage[$page] = [
            'count' => $n,
            'avg_ms' => array_sum($vals) / max(1, $n),
            'p95_ms' => $vals[(int)max(0, ceil($n * 0.95) - 1)] ?? 0.0,
            'p99_ms' => $vals[(int)max(0, ceil($n * 0.99) - 1)] ?? 0.0,
        ];
    }

    usort($rows, static function(array $a, array $b): int {
        return ((float)($b['total_ms'] ?? 0.0)) <=> ((float)($a['total_ms'] ?? 0.0));
    });

    ksort($blockAgg);
    $blockSummary = [];
    foreach ($blockAgg as $blockKey => $blockData) {
        $blockSummary[$blockKey] = [
            'count' => (int)$blockData['count'],
            'avg_ms' => round(((float)$blockData['sum_ms']) / max(1, (int)$blockData['count']), 2),
            'max_ms' => round((float)$blockData['max_ms'], 2),
        ];
    }

    return [
        'total' => $count,
        'avg_ms' => $avg,
        'p95_ms' => $p95,
        'p99_ms' => $p99,
        'by_page' => $byPage,
        'top_slowest' => array_slice($rows, 0, 10),
        'cache' => ['hits' => $cacheHits, 'misses' => $cacheMisses],
        'sql' => ['count' => $sqlCount, 'ms' => $sqlMs],
        'server' => ['max_load1' => $maxLoad, 'max_mem_mb' => $maxMem],
        'blocks' => $blockSummary,
    ];
}

function safeName(string $s): string { return preg_replace('/[^a-zA-Z0-9_]/','_',$s); }
function normalizeSessionDuration(string $v): string {
    $allowed = ['unlimited','1m','1h','6h','12h','24h','7d','30d'];
    return in_array($v, $allowed, true) ? $v : 'unlimited';
}
function sessionDurationLabel(string $v): string {
    $map = [
        'unlimited' => 'Onbeperkt',
        '1m' => '1 minuut',
        '1h' => '1 uur',
        '6h' => '6 uur',
        '12h' => '12 uur',
        '24h' => '24 uur',
        '7d' => '7 dagen',
        '30d' => '30 dagen'
    ];
    return $map[$v] ?? 'Onbeperkt';
}
function sessionDurationHours(string $v): int {
    $map = ['1m'=>1,'1h'=>1,'6h'=>6,'12h'=>12,'24h'=>24,'7d'=>168,'30d'=>720,'unlimited'=>720];
    return $map[$v] ?? 720;
}
function sessionDurationSeconds(string $v): int {
    $map = ['1m'=>60,'1h'=>3600,'6h'=>21600,'12h'=>43200,'24h'=>86400,'7d'=>604800,'30d'=>2592000,'unlimited'=>0];
    return $map[$v] ?? 0;
}

function getTargetDraftQueue(): array {
    $items = $_SESSION['target_draft_queue'] ?? [];
    if (!is_array($items)) return [];
    return array_values(array_filter($items, static function($item): bool {
        return is_array($item) && !empty($item['queue_id']);
    }));
}

function saveTargetDraftQueue(array $items): void {
    $_SESSION['target_draft_queue'] = array_values($items);
}

function getTargetDraftDefaults($db): array {
    $base = [
        'category_id' => 0,
        'remark' => '',
        'alert' => getDefaultTargetAlertName($db),
        'session_duration' => 'unlimited',
        'session_notify_enabled' => 1,
        'session_notify_email' => getDefaultNotifyRecipientList($db),
        'outage_mail_interval' => ''
    ];
    $saved = $_SESSION['target_draft_defaults'] ?? [];
    if (!is_array($saved)) return $base;
    return array_merge($base, array_intersect_key($saved, $base));
}

function saveTargetDraftDefaults(array $draft): void {
    $_SESSION['target_draft_defaults'] = [
        'category_id' => (int)($draft['category_id'] ?? 0),
        'remark' => '',
        'alert' => (string)($draft['alert'] ?? ''),
        'session_duration' => (string)($draft['session_duration'] ?? 'unlimited'),
        'session_notify_enabled' => (int)($draft['session_notify_enabled'] ?? 0),
        'session_notify_email' => (string)($draft['session_notify_email'] ?? ''),
        'outage_mail_interval' => ($draft['outage_mail_interval'] ?? '') === null ? '' : (string)($draft['outage_mail_interval'] ?? '')
    ];
}

function categoryExists($db, int $categoryId): bool {
    if ($categoryId <= 0) return false;
    $stmt = $db->prepare('SELECT COUNT(*) FROM categories WHERE id=:id');
    $stmt->bindValue(':id', $categoryId, SQLITE3_INTEGER);
    return (int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0] > 0;
}

function normalizeTargetDraftPayload($db, array $input, array $fallback = []): array {
    $allowedTgtIntervals = [5,10,15,30,240,480,1440,2880,10080];
    $payload = array_merge($fallback, $input);
    $categoryId = (int)($payload['category_id'] ?? 0);
    $displayName = trim((string)($payload['display_name'] ?? ''));
    $host = normalizeTargetHostValue($payload['host'] ?? '');
    $hostIpv6 = normalizeTargetHostValue($payload['host_ipv6'] ?? '');
    $remark = normalizeTargetRemark($payload['remark'] ?? null);
    $alert = trim((string)($payload['alert'] ?? ''));
    if ($alert === '') $alert = getDefaultTargetAlertName($db);
    $sessionDuration = normalizeSessionDuration(trim((string)($payload['session_duration'] ?? 'unlimited')));
    $sessionNotifyEnabled = !empty($payload['session_notify_enabled']) ? 1 : 0;
    $sessionNotifyEmail = trim((string)($payload['session_notify_email'] ?? ''));
    if ($sessionNotifyEnabled) {
        if ($sessionNotifyEmail === '') $sessionNotifyEmail = getDefaultNotifyRecipientList($db);
        $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
        if ($sessionNotifyEmail === '') {
            return ['success'=>false,'msg'=>'Vul een geldig notificatie e-mailadres in.'];
        }
    } else {
        $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
    }
    $outageInterval = ($payload['outage_mail_interval'] ?? '') === '' ? null : (int)$payload['outage_mail_interval'];
    if ($outageInterval !== null && !in_array($outageInterval, $allowedTgtIntervals, true)) $outageInterval = null;

    if (!categoryExists($db, $categoryId)) {
        return ['success'=>false,'msg'=>'Kies een geldige categorie.'];
    }
    if ($displayName === '') {
        return ['success'=>false,'msg'=>'Vul een naam in.'];
    }
    if ($host === '' && $hostIpv6 === '') {
        return ['success'=>false,'msg'=>'Vul minimaal een IPv4/hostname of IPv6 adres in.'];
    }

    return ['success'=>true,'data'=>[
        'queue_id' => (string)($payload['queue_id'] ?? ''),
        'category_id' => $categoryId,
        'display_name' => $displayName,
        'host' => $host,
        'host_ipv6' => $hostIpv6,
        'remark' => $remark,
        'alert' => $alert,
        'session_duration' => $sessionDuration,
        'session_notify_enabled' => $sessionNotifyEnabled,
        'session_notify_email' => $sessionNotifyEmail,
        'outage_mail_interval' => $outageInterval,
    ]];
}

function upsertTargetDraftQueueItem($db, array $input): array {
    $normalized = normalizeTargetDraftPayload($db, $input, getTargetDraftDefaults($db));
    if (empty($normalized['success'])) return $normalized;

    $draft = $normalized['data'];
    $queue = getTargetDraftQueue();
    $queueId = trim((string)($input['queue_id'] ?? ''));
    if ($queueId === '') $queueId = bin2hex(random_bytes(6));
    $draft['queue_id'] = $queueId;

    $updated = false;
    foreach ($queue as $idx => $item) {
        if ((string)($item['queue_id'] ?? '') === $queueId) {
            $queue[$idx] = $draft;
            $updated = true;
            break;
        }
    }
    if (!$updated) $queue[] = $draft;
    saveTargetDraftQueue($queue);
    saveTargetDraftDefaults($draft);
    return ['success'=>true,'data'=>$draft,'updated'=>$updated,'count'=>count($queue)];
}

function parseBulkTargetDrafts($db, array $input): array {
    $base = [
        'category_id' => (int)($input['category_id'] ?? 0),
        'alert' => (string)($input['alert'] ?? ''),
        'session_duration' => (string)($input['session_duration'] ?? 'unlimited'),
        'session_notify_enabled' => !empty($input['session_notify_enabled']) ? 1 : 0,
        'session_notify_email' => (string)($input['session_notify_email'] ?? ''),
        'outage_mail_interval' => (string)($input['outage_mail_interval'] ?? '')
    ];
    $raw = trim((string)($input['bulk_targets'] ?? ''));
    if ($raw === '') return ['success'=>false,'msg'=>'Plak eerst een of meer regels in het bulkveld.'];

    $queue = getTargetDraftQueue();
    $added = 0;
    $errors = [];
    foreach (preg_split('/\r\n|\n|\r/', $raw) as $lineNo => $line) {
        $line = trim((string)$line);
        if ($line === '') continue;
        $parts = array_map('trim', explode(';', $line));
        if (count($parts) < 2) {
            $errors[] = 'Regel '.($lineNo + 1).' heeft te weinig velden. Gebruik: weergavenaam;ipv4;ipv6;opmerking';
            continue;
        }
        $normalized = normalizeTargetDraftPayload($db, [
            'display_name' => $parts[0] ?? '',
            'host' => $parts[1] ?? '',
            'host_ipv6' => $parts[2] ?? '',
            'remark' => $parts[3] ?? '',
        ], $base);
        if (empty($normalized['success'])) {
            $errors[] = 'Regel '.($lineNo + 1).': '.$normalized['msg'];
            continue;
        }
        $draft = $normalized['data'];
        $draft['queue_id'] = bin2hex(random_bytes(6));
        $queue[] = $draft;
        $added++;
        saveTargetDraftDefaults($draft);
    }

    saveTargetDraftQueue($queue);
    return ['success'=>$added > 0,'added'=>$added,'errors'=>$errors,'count'=>count($queue)];
}

function removeTargetDraftQueueItem(string $queueId): int {
    $queue = array_values(array_filter(getTargetDraftQueue(), static function(array $item) use ($queueId): bool {
        return (string)($item['queue_id'] ?? '') !== $queueId;
    }));
    saveTargetDraftQueue($queue);
    return count($queue);
}

function clearTargetDraftQueue(): void {
    unset($_SESSION['target_draft_queue']);
}

function prepareQueuedTargetDraftsForApply($db, array $queue): array {
    $prepared = [];
    $errors = [];
    $seen = [];
    foreach ($queue as $draft) {
        $normalized = normalizeTargetDraftPayload($db, $draft, []);
        if (empty($normalized['success'])) {
            $errors[] = ((string)($draft['display_name'] ?? 'Concept')).': '.$normalized['msg'];
            continue;
        }
        $row = $normalized['data'];
        $internalName = buildTargetInternalNameBase($row['display_name']);
        $dupKey = $row['category_id'].'|'.$internalName;
        if (isset($seen[$dupKey])) {
            $errors[] = $row['display_name'].': dubbele technische targetnaam in wachtrij.';
            continue;
        }
        $stmt = $db->prepare('SELECT COUNT(*) FROM targets WHERE category_id=:c AND name=:n');
        $stmt->bindValue(':c', $row['category_id'], SQLITE3_INTEGER);
        $stmt->bindValue(':n', $internalName, SQLITE3_TEXT);
        if ((int)$stmt->execute()->fetchArray(SQLITE3_NUM)[0] > 0) {
            $errors[] = $row['display_name'].': targetnaam bestaat al in deze categorie.';
            continue;
        }
        $row['internal_name'] = $internalName;
        $prepared[] = $row;
        $seen[$dupKey] = true;
    }
    return ['prepared'=>$prepared,'errors'=>$errors];
}

function maybeSendSessionStartMail($db, int $targetId): void {
    $s = $db->prepare('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.id=:id');
    $s->bindValue(':id', $targetId, SQLITE3_INTEGER);
    $t = $s->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$t) return;
    $dur = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
    $notify = (int)($t['session_notify_enabled'] ?? 0) === 1;
    $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
    if (!$notify || empty($recipients)) return;
    if ((int)($t['session_start_notified'] ?? 0) === 1) return;

    $startedAt = !empty($t['session_started_at']) ? strtotime($t['session_started_at']) : time();
    if ($startedAt <= 0) $startedAt = time();
    $isUnlimited = ($dur === 'unlimited');
    $endTs = $startedAt + sessionDurationSeconds($dur);

    $subject = 'SmokePing - Sessie gestart: ' . $t['display_name'];
    $durLabel = htmlspecialchars(sessionDurationLabel($dur));
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#3b82f6 0%,#1d4ed8 100%);padding:28px 32px">';
    $body .= '<div style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-.3px">Smokeping Manager - Sessie gestart</div>';
    $body .= '<div style="color:#bfdbfe;font-size:13px;margin-top:5px">SmokePing Manager &mdash; Sessie melding</div>';
    $body .= '</div>';
    $body .= '<div style="padding:28px 32px">';
    $body .= '<p style="margin:0 0 20px;color:#374151;font-size:15px">Een nieuwe test-sessie is gestart voor <strong style="color:#1d4ed8">' . htmlspecialchars($t['display_name']) . '</strong>.</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $rows_data = [
        ['Categorie',   htmlspecialchars($t['cat_display']),       false],
        ['Target',      '<strong>'.htmlspecialchars($t['display_name']).'</strong>', false],
        ['Host',        '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$t['host']).'</code>', true],
        ['Sessieduur',  $durLabel,                                  false],
        ['Gestart op',  date('d-m-Y H:i:s', $startedAt),          true],
        ['Verwacht einde', $isUnlimited ? 'Sessie loopt onbeperkt door (geen eindtijd)' : date('d-m-Y H:i:s', $endTs), false],
    ];
    foreach ($rows_data as $i => [$label, $val, $mono]) {
        $bg = ($i % 2 === 0) ? '#f9fafb' : '#ffffff';
        $border = ($i < count($rows_data)-1) ? 'border-bottom:1px solid #e5e7eb;' : '';
        $body .= '<tr style="background:'.$bg.'"><td style="padding:10px 14px;font-size:12px;color:#6b7280;width:140px;'.$border.'">'.$label.'</td>';
        $body .= '<td style="padding:10px 14px;font-size:14px;color:#111827;'.$border.'">'.$val.'</td></tr>';
    }
    $body .= '</table>';
    $body .= '<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:14px 16px;margin-top:20px;font-size:13px;color:#1e40af">';
    if ($isUnlimited) {
        $body .= '<strong>Let op:</strong> Deze sessie loopt onbeperkt door totdat je deze handmatig beëindigt.';
    } else {
        $body .= '<strong>Let op:</strong> De sessie stopt automatisch na '.$durLabel.'. Je ontvangt daarna een samenvatting met de meetresultaten.';
    }
    $body .= '</div>';
    $body .= '</div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">';
    $body .= 'SmokePing Manager &mdash; Automatisch gegenereerde melding';
    $body .= '</div></div></body></html>';

    try {
        $res = logAndSendEmailList($db, $recipients, $subject, $body, 'session_start', $t['display_name']);
        if (!empty($res['success'])) {
            $u = $db->prepare('UPDATE targets SET session_start_notified=1 WHERE id=:id');
            $u->bindValue(':id', $targetId, SQLITE3_INTEGER);
            $u->execute();
        }
    } catch (\Throwable $e) {
        try {
            $ml = $db->prepare('INSERT INTO mail_log(type,target_name,email_to,subject,status,message,debug_output) VALUES(:tp,:tn,:to,:sb,:st,:ms,:dbg)');
            $ml->bindValue(':tp', 'session_start');
            $ml->bindValue(':tn', (string)($t['display_name'] ?? ''));
            $ml->bindValue(':to', implode(', ', $recipients));
            $ml->bindValue(':sb', $subject);
            $ml->bindValue(':st', 'failed');
            $ml->bindValue(':ms', 'Exception bij sessiestartmail: ' . get_class($e) . ': ' . $e->getMessage());
            $ml->bindValue(':dbg', $e->getTraceAsString());
            $ml->execute();
        } catch (\Throwable $ignored) {}
    }
}

function processSessionEndNotifications($db): void {
    $last = (int)getSetting($db, 'session_mail_last_check', '0');
    $now = time();
    if ($now - $last < 60) return;
    setSetting($db, 'session_mail_last_check', (string)$now);

    $rows = $db->query('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.enabled=1 AND t.session_duration!="unlimited" AND t.session_end_notified=0');
    while ($t = $rows->fetchArray(SQLITE3_ASSOC)) {
        $dur = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
        if ($dur === 'unlimited') continue;
        $notifyEnabled = (int)($t['session_notify_enabled'] ?? 0) === 1;
        $startedAt = !empty($t['session_started_at']) ? strtotime($t['session_started_at']) : 0;
        if ($startedAt <= 0) {
            $startedAt = parseDbDateToTs($t['created_at'] ?? null);
            if ($startedAt <= 0) continue;
            $fix = $db->prepare('UPDATE targets SET session_started_at=datetime(:st,"unixepoch"), updated_at=CURRENT_TIMESTAMP WHERE id=:id');
            $fix->bindValue(':st', $startedAt, SQLITE3_INTEGER);
            $fix->bindValue(':id', (int)$t['id'], SQLITE3_INTEGER);
            $fix->execute();
        }
        $endTs = $startedAt + sessionDurationSeconds($dur);
        if ($endTs > $now) continue;

        if ($notifyEnabled) {
            $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
            if (!empty($recipients)) {
                $hours = sessionDurationHours($dur);
                $st = getTargetStatus($t['cat_name'], $t['name']);
                $ut = getTargetUptime($t['cat_name'], $t['name'], $hours);
                $outageSummary = collectTargetOutageSummary($db, $t, 24);
                $outageEvents = is_array($outageSummary['events'] ?? null) ? $outageSummary['events'] : [];
                $sessionDowntimeSec = (int)($outageSummary['total_downtime_seconds'] ?? 0);
                $hadOutage = $sessionDowntimeSec > 0 || !empty($outageEvents);

                $subject = 'SmokePing - Sessie afgerond: ' . $t['display_name'];
                $lossFrac = $st['loss'];
                $lossPct  = ($lossFrac !== null) ? round($lossFrac * 100, 1) . '%' : 'n.v.t.';
                $median   = ($st['median'] !== null) ? $st['median'] . ' ms' : 'n.v.t.';
                $uptimePct = ($ut['uptime'] !== null) ? $ut['uptime'] . '%' : 'n.v.t.';
                $durLabel = htmlspecialchars(sessionDurationLabel($dur));

                if ($hadOutage) {
                    $statusLabel = 'Uitval tijdens sessie'; $statusColor = '#dc2626'; $statusBg = '#fee2e2';
                } elseif (!$st['exists']) {
                    $statusLabel = 'Geen RRD data'; $statusColor = '#6b7280'; $statusBg = '#f3f4f6';
                } elseif ($lossFrac !== null && $lossFrac >= 1.0) {
                    $statusLabel = 'Volledige uitval'; $statusColor = '#dc2626'; $statusBg = '#fee2e2';
                } elseif ($lossFrac !== null && $lossFrac > 0) {
                    $statusLabel = 'Gedeeltelijk verlies'; $statusColor = '#d97706'; $statusBg = '#fef3c7';
                } else {
                    $statusLabel = 'Geen uitval'; $statusColor = '#059669'; $statusBg = '#d1fae5';
                }

                $uptimeColor = ($ut['uptime'] === null) ? '#6b7280' : (($ut['uptime'] >= 99) ? '#059669' : (($ut['uptime'] >= 95) ? '#d97706' : '#dc2626'));
                $headerColor = ($hadOutage || ($lossFrac !== null && $lossFrac > 0)) ? 'linear-gradient(135deg,#dc2626 0%,#991b1b 100%)' : 'linear-gradient(135deg,#059669 0%,#047857 100%)';
                $headerTitle = ($hadOutage || ($lossFrac !== null && $lossFrac > 0)) ? 'Sessie afgerond &mdash; Let op' : 'Sessie afgerond';

                $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
                $body .= '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
                $body .= '<div style="background:'.$headerColor.';padding:28px 32px">';
                $body .= '<div style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-.3px">'.$headerTitle.'</div>';
                $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Sessie samenvatting</div>';
                $body .= '</div>';
                $body .= '<div style="background:'.$statusBg.';border-bottom:3px solid '.$statusColor.';padding:14px 32px;display:flex;align-items:center;gap:12px">';
                $body .= '<div style="width:14px;height:14px;border-radius:50%;background:'.$statusColor.';flex-shrink:0"></div>';
                $body .= '<div style="font-size:15px;font-weight:600;color:'.$statusColor.'">'.$statusLabel.'</div>';
                if ($ut['uptime'] !== null) {
                    $body .= '<div style="margin-left:auto;font-size:20px;font-weight:700;color:'.$uptimeColor.'">'.$uptimePct.' uptime</div>';
                }
                $body .= '</div>';
                $body .= '<div style="padding:24px 32px">';
                $actualSeconds = max(0, $endTs - $startedAt);
                $actualH = (int)floor($actualSeconds / 3600);
                $actualM = (int)floor(($actualSeconds % 3600) / 60);
                $actualS = $actualSeconds % 60;
                $actualDurStr = ($actualH > 0 ? $actualH . ' uur ' : '') . ($actualM > 0 || $actualH > 0 ? $actualM . ' min ' : '') . $actualS . ' sec';
                if ($actualSeconds >= 3600) $actualDurStr = $actualH . ' uur ' . $actualM . ' min';
                $body .= '<p style="margin:0 0 18px;color:#374151;font-size:15px">Hieronder de samenvatting van de sessie voor <strong style="color:#1d4ed8">'.htmlspecialchars($t['display_name']).'</strong>.</p>';
                $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px">';
                $info_rows = [
                    ['Categorie',       htmlspecialchars($t['cat_display']),  false],
                    ['Target',          '<strong>'.htmlspecialchars($t['display_name']).'</strong>', false],
                    ['Host',            '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$t['host']).'</code>', true],
                    ['Sessieduur (gepland)', $durLabel,                       false],
                    ['Gestart op',      date('d-m-Y H:i:s', $startedAt),     true],
                    ['Beeindigd op',    date('d-m-Y H:i:s', $endTs),         false],
                    ['Totale duur',     '<strong>'.$actualDurStr.'</strong>', true],
                ];
                foreach ($info_rows as $i => [$label, $val, $alt]) {
                    $bg = ($i % 2 === 0) ? '#f9fafb' : '#ffffff';
                    $border = ($i < count($info_rows)-1) ? 'border-bottom:1px solid #e5e7eb;' : '';
                    $body .= '<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$border.'">'.$label.'</td>';
                    $body .= '<td style="padding:9px 14px;font-size:14px;color:#111827;'.$border.'">'.$val.'</td></tr>';
                }
                $body .= '</table>';
                $body .= '<div style="font-size:13px;font-weight:600;color:#374151;margin-bottom:10px;text-transform:uppercase;letter-spacing:.5px">Meetresultaten</div>';
                $body .= '<div style="display:flex;gap:10px;flex-wrap:wrap">';
                $metrics = [
                    ['Packet Loss', $lossPct, $statusColor],
                    ['Median RTT',  $median,  '#3b82f6'],
                    ['Uptime',      $uptimePct, $uptimeColor],
                ];
                foreach ($metrics as [$mlabel, $mval, $mcol]) {
                    $body .= '<div style="flex:1;min-width:120px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;padding:12px 14px;text-align:center">';
                    $body .= '<div style="font-size:20px;font-weight:700;color:'.$mcol.'">'.$mval.'</div>';
                    $body .= '<div style="font-size:11px;color:#6b7280;margin-top:4px">'.$mlabel.'</div>';
                    $body .= '</div>';
                }
                $body .= '</div>';

                if ($hadOutage) {
                    $body .= '<div style="margin-top:16px;background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px">';
                    $body .= '<div style="font-size:13px;font-weight:700;color:#9a3412;margin-bottom:8px">Uitval tijdens deze sessie</div>';
                    $body .= '<div style="font-size:13px;color:#7c2d12;margin-bottom:6px">Totale uitvaltijd: <strong>'.formatDurationSeconds($sessionDowntimeSec).'</strong></div>';
                    if (!empty($outageEvents)) {
                        $body .= '<ul style="margin:6px 0 0 16px;padding:0;color:#7c2d12;font-size:12px">';
                        foreach (array_slice($outageEvents, 0, 5) as $ev) {
                            $body .= '<li style="margin:3px 0">'.htmlspecialchars((string)($ev['started_at_label'] ?? '-')).' - '.htmlspecialchars((string)($ev['ended_at_label'] ?? '-')).' ('.htmlspecialchars((string)($ev['duration_label'] ?? '-')).')</li>';
                        }
                        $body .= '</ul>';
                    }
                    $body .= '</div>';
                }

                $body .= '</div>';
                $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">';
                $body .= 'SmokePing Manager &mdash; Automatisch gegenereerde samenvatting';
                $body .= '</div></div></body></html>';

                $res = logAndSendEmailList($db, $recipients, $subject, $body, 'session_end', $t['display_name']);
            }
        }

        $u = $db->prepare('UPDATE targets SET session_end_notified=1, enabled=0, session_started_at=NULL, session_start_notified=0, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $u->bindValue(':id', (int)$t['id'], SQLITE3_INTEGER);
        $u->execute();
    }
}
function buildOutageStartMailBody(array $row, int $startTs): string {
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#dc2626 0%,#991b1b 100%);padding:28px 32px">';
    $body .= '<div style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-.3px">&#9888; UITVAL gedetecteerd</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Uitval melding</div>';
    $body .= '</div>';
    $body .= '<div style="background:#fee2e2;border-bottom:3px solid #dc2626;padding:14px 32px">';
    $body .= '<div style="font-size:15px;font-weight:600;color:#991b1b">Volledig pakketverlies gedetecteerd &mdash; host niet bereikbaar</div>';
    $body .= '</div>';
    $body .= '<div style="padding:24px 32px">';
    $body .= '<p style="margin:0 0 18px;color:#374151;font-size:15px">Er is uitval gedetecteerd voor <strong style="color:#dc2626">'.htmlspecialchars($row['display_name']).'</strong>.</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px">';
    $rows_data = [
        ['Categorie',    htmlspecialchars($row['cat_display']),  false],
        ['Target',       '<strong>'.htmlspecialchars($row['display_name']).'</strong>', false],
        ['Host',         '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$row['host']).'</code>', true],
        ['Uitval vanaf', date('d-m-Y H:i:s', $startTs),         false],
    ];
    foreach ($rows_data as $i => [$label, $val, $alt]) {
        $bg = ($i % 2 === 0) ? '#f9fafb' : '#ffffff';
        $border = ($i < count($rows_data)-1) ? 'border-bottom:1px solid #e5e7eb;' : '';
        $body .= '<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$border.'">'.$label.'</td>';
        $body .= '<td style="padding:9px 14px;font-size:14px;color:#111827;'.$border.'">'.$val.'</td></tr>';
    }
    $body .= '</table>';
    $body .= '</div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">';
    $body .= 'SmokePing Manager &mdash; Automatisch gegenereerde uitval melding';
    $body .= '</div></div></body></html>';
    return $body;
}

function buildOutageEndMailBody(array $row, int $startTs, int $endTs, int $duration): string {
    $min = (int)floor($duration / 60);
    $sec = $duration % 60;
    $durStr = ($min > 0 ? $min . ' min ' : '') . $sec . ' sec';
    if ($duration >= 3600) { $h = (int)floor($duration/3600); $m = (int)floor(($duration%3600)/60); $durStr = $h.'u '.$m.'m'; }
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:560px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#059669 0%,#047857 100%);padding:28px 32px">';
    $body .= '<div style="color:#ffffff;font-size:22px;font-weight:700;letter-spacing:-.3px">&#10003; Uitval opgelost</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Herstel melding</div>';
    $body .= '</div>';
    $body .= '<div style="background:#d1fae5;border-bottom:3px solid #059669;padding:14px 32px">';
    $body .= '<div style="font-size:15px;font-weight:600;color:#047857">Host is weer bereikbaar</div>';
    $body .= '</div>';
    $body .= '<div style="padding:24px 32px">';
    $body .= '<p style="margin:0 0 18px;color:#374151;font-size:15px">De verbinding met <strong style="color:#059669">'.htmlspecialchars($row['display_name']).'</strong> is hersteld.</p>';
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;margin-bottom:16px">';
    $rows_data = [
        ['Categorie',    htmlspecialchars($row['cat_display']),  false],
        ['Target',       '<strong>'.htmlspecialchars($row['display_name']).'</strong>', false],
        ['Host',         '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px;font-size:13px">'.htmlspecialchars((string)$row['host']).'</code>', true],
        ['Uitval vanaf', date('d-m-Y H:i:s', $startTs),         false],
        ['Hersteld op',  date('d-m-Y H:i:s', $endTs),           true],
        ['Totale duur',  '<strong>'.$durStr.'</strong>',         false],
    ];
    foreach ($rows_data as $i => [$label, $val, $alt]) {
        $bg = ($i % 2 === 0) ? '#f9fafb' : '#ffffff';
        $border = ($i < count($rows_data)-1) ? 'border-bottom:1px solid #e5e7eb;' : '';
        $body .= '<tr style="background:'.$bg.'"><td style="padding:9px 14px;font-size:12px;color:#6b7280;width:130px;'.$border.'">'.$label.'</td>';
        $body .= '<td style="padding:9px 14px;font-size:14px;color:#111827;'.$border.'">'.$val.'</td></tr>';
    }
    $body .= '</table>';
    $body .= '</div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">';
    $body .= 'SmokePing Manager &mdash; Automatisch gegenereerde herstel melding';
    $body .= '</div></div></body></html>';
    return $body;
}

function buildBatchOutageStartMail(array $outages): string {
    $count = count($outages);
    $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SmokePing</title></head><body style="margin:0;padding:20px;background:#f3f4f6;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif">';
    $body .= '<div style="max-width:600px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $body .= '<div style="background:linear-gradient(135deg,#dc2626 0%,#991b1b 100%);color:#fff;padding:24px 32px">';
    $body .= '<div style="font-size:24px;font-weight:600;margin-bottom:4px">Uitval gedetecteerd</div>';
    $body .= '<div style="font-size:14px;opacity:0.95">' . $count . ' target(s) zijn uitgevallen</div>';
    $body .= '</div>';
    $body .= '<div style="padding:32px">';
    $body .= '<table style="width:100%;border-collapse:collapse;font-size:14px">';
    $body .= '<thead><tr style="background:#f9fafb;border-bottom:2px solid #e5e7eb">';
    $body .= '<th style="padding:12px 8px;text-align:left;font-weight:600;color:#374151">Target</th>';
    $body .= '<th style="padding:12px 8px;text-align:left;font-weight:600;color:#374151">Categorie</th>';
    $body .= '<th style="padding:12px 8px;text-align:left;font-weight:600;color:#374151">Host</th>';
    $body .= '<th style="padding:12px 8px;text-align:left;font-weight:600;color:#374151">Starttijd</th>';
    $body .= '</tr></thead><tbody>';
    foreach ($outages as $o) {
        $body .= '<tr style="border-bottom:1px solid #e5e7eb">';
        $body .= '<td style="padding:12px 8px;color:#111827">' . htmlspecialchars($o['display_name'], ENT_QUOTES, 'UTF-8') . '</td>';
        $body .= '<td style="padding:12px 8px;color:#6b7280">' . htmlspecialchars($o['cat_display'], ENT_QUOTES, 'UTF-8') . '</td>';
        $body .= '<td style="padding:12px 8px;color:#6b7280;font-family:monospace;font-size:12px">' . htmlspecialchars($o['host'], ENT_QUOTES, 'UTF-8') . '</td>';
        $body .= '<td style="padding:12px 8px;color:#6b7280;font-size:13px">' . htmlspecialchars($o['started_at'], ENT_QUOTES, 'UTF-8') . '</td>';
        $body .= '</tr>';
    }
    $body .= '</tbody></table>';
    $body .= '</div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">';
    $body .= 'SmokePing Manager &mdash; Automatisch gegenereerde uitval melding';
    $body .= '</div></div></body></html>';
    return $body;
}

function buildBatchOutageSummaryMail(array $started, array $ended, int $generatedTs, int $intervalMin): string {
    $startCount = count($started);
    $endCount = count($ended);
    $body = '<!DOCTYPE html><html><head><meta charset="utf-8"><title>SmokePing</title></head><body style="margin:0;padding:20px;background:#f3f4f6;font-family:system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif">';
    $body .= '<div style="max-width:760px;margin:0 auto;background:#fff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $body .= '<div style="background:linear-gradient(135deg,#1d4ed8 0%,#1e3a8a 100%);color:#fff;padding:24px 32px">';
    $body .= '<div style="font-size:24px;font-weight:600;margin-bottom:4px">Uitval en herstel samenvatting</div>';
    $body .= '<div style="font-size:14px;opacity:0.95">Interval: elke '.(int)$intervalMin.' minuten | gegenereerd op '.date('d-m-Y H:i:s', $generatedTs).'</div>';
    $body .= '</div><div style="padding:26px 32px">';

    if ($startCount > 0) {
        $body .= '<div style="font-size:16px;font-weight:700;color:#991b1b;margin-bottom:8px">Nieuwe uitval: '.$startCount.'</div>';
        $body .= '<table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:18px">';
        $body .= '<thead><tr style="background:#fef2f2;border-bottom:2px solid #fecaca"><th style="padding:9px 8px;text-align:left">Target</th><th style="padding:9px 8px;text-align:left">Categorie</th><th style="padding:9px 8px;text-align:left">Host</th><th style="padding:9px 8px;text-align:left">Uitval vanaf</th></tr></thead><tbody>';
        foreach ($started as $row) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = $generatedTs;
            $body .= '<tr style="border-bottom:1px solid #e5e7eb">';
            $body .= '<td style="padding:9px 8px">'.htmlspecialchars((string)($row['display_name'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.htmlspecialchars((string)($row['cat_display'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280;font-family:monospace">'.htmlspecialchars((string)($row['host'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $startTs).'</td>';
            $body .= '</tr>';
        }
        $body .= '</tbody></table>';
    }

    if ($endCount > 0) {
        $body .= '<div style="font-size:16px;font-weight:700;color:#065f46;margin:6px 0 8px">Herstelde uitval: '.$endCount.'</div>';
        $body .= '<table style="width:100%;border-collapse:collapse;font-size:13px">';
        $body .= '<thead><tr style="background:#ecfdf5;border-bottom:2px solid #bbf7d0"><th style="padding:9px 8px;text-align:left">Target</th><th style="padding:9px 8px;text-align:left">Categorie</th><th style="padding:9px 8px;text-align:left">Host</th><th style="padding:9px 8px;text-align:left">Uitval vanaf</th><th style="padding:9px 8px;text-align:left">Hersteld op</th><th style="padding:9px 8px;text-align:left">Duur</th></tr></thead><tbody>';
        foreach ($ended as $row) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs = parseDbDateToTs($row['ended_at'] ?? null);
            if ($startTs <= 0) $startTs = $generatedTs;
            if ($endTs <= 0) $endTs = $generatedTs;
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            $body .= '<tr style="border-bottom:1px solid #e5e7eb">';
            $body .= '<td style="padding:9px 8px">'.htmlspecialchars((string)($row['display_name'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.htmlspecialchars((string)($row['cat_display'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280;font-family:monospace">'.htmlspecialchars((string)($row['host'] ?? ''), ENT_QUOTES, 'UTF-8').'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $startTs).'</td>';
            $body .= '<td style="padding:9px 8px;color:#6b7280">'.date('d-m-Y H:i:s', $endTs).'</td>';
            $body .= '<td style="padding:9px 8px"><strong>'.formatDurationSeconds($duration).'</strong></td>';
            $body .= '</tr>';
        }
        $body .= '</tbody></table>';
    }

    if ($startCount === 0 && $endCount === 0) {
        $body .= '<p style="margin:0;color:#6b7280">Geen wijzigingen in deze interval.</p>';
    }

    $body .= '</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Gecombineerde uitval/herstel melding</div></div></body></html>';
    return $body;
}

function processOutageNotifications($db): void {
    $es = $db->query('SELECT batch_outage_notifications, outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    $batchMode = (int)($es['batch_outage_notifications'] ?? 1) === 1;
    $globalInterval = max(1, (int)($es['outage_mail_interval'] ?? 5));
    $minOutageSeconds = max(20, (int)getSetting($db, 'outage_min_seconds', '20'));
    $now = time();

    if ($batchMode) {
        $subscriptionCount = [];
        $subTargets = $db->query('SELECT id, session_notify_email FROM targets WHERE session_notify_enabled=1');
        while ($st = $subTargets->fetchArray(SQLITE3_ASSOC)) {
            $tid = (int)($st['id'] ?? 0);
            if ($tid <= 0) continue;
            foreach (resolveNotifyRecipients($db, (string)($st['session_notify_email'] ?? '')) as $rcp) {
                if (!isset($subscriptionCount[$rcp])) $subscriptionCount[$rcp] = [];
                $subscriptionCount[$rcp][$tid] = 1;
            }
        }
        foreach ($subscriptionCount as $rcp => $targetMap) $subscriptionCount[$rcp] = count($targetMap);

        $pendingStart = [];
        $rsStart = $db->query('SELECT o.id, o.started_at, t.id AS target_id, t.display_name, t.host, t.session_notify_email, t.outage_mail_interval AS target_interval, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=1 AND (o.start_notified IS NULL OR o.start_notified=0) AND t.session_notify_enabled=1 AND t.enabled=1');
        while ($row = $rsStart->fetchArray(SQLITE3_ASSOC)) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = $now;
            $effInt = ($row['target_interval'] !== null) ? (int)$row['target_interval'] : $globalInterval;
            if (($now - $startTs) < $minOutageSeconds) continue;
            if (($now - $startTs) < ($effInt * 60)) continue;
            $pendingStart[] = $row;
        }

        $pendingEnd = [];
        $ignoredEndIds = [];
        $rsEnd = $db->query('SELECT o.id, o.started_at, o.ended_at, o.duration_seconds, t.id AS target_id, t.display_name, t.host, t.session_notify_email, t.outage_mail_interval AS target_interval, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=0 AND (o.end_notified IS NULL OR o.end_notified=0) AND t.session_notify_enabled=1');
        while ($row = $rsEnd->fetchArray(SQLITE3_ASSOC)) {
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs = parseDbDateToTs($row['ended_at'] ?? null);
            if ($startTs <= 0) $startTs = $now;
            if ($endTs <= 0) $endTs = $now;
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            $effInt = ($row['target_interval'] !== null) ? (int)$row['target_interval'] : $globalInterval;
            if ($duration < $minOutageSeconds) {
                $ignoredEndIds[] = (int)$row['id'];
                continue;
            }
            if (($now - $endTs) < ($effInt * 60)) continue;
            $pendingEnd[] = $row;
        }

        $sentStartIds = [];
        $sentEndIds = [];
        $sentTargetIds = [];
        $sentAny = false;

        if (!empty($pendingStart) || !empty($pendingEnd)) {
            $byRecipient = [];
            foreach ($pendingStart as $row) {
                foreach (resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? '')) as $rcp) {
                    if (!isset($byRecipient[$rcp])) $byRecipient[$rcp] = ['start' => [], 'end' => []];
                    $byRecipient[$rcp]['start'][] = $row;
                }
            }
            foreach ($pendingEnd as $row) {
                foreach (resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? '')) as $rcp) {
                    if (!isset($byRecipient[$rcp])) $byRecipient[$rcp] = ['start' => [], 'end' => []];
                    $byRecipient[$rcp]['end'][] = $row;
                }
            }

            foreach ($byRecipient as $rcp => $bucket) {
                $startRows = $bucket['start'];
                $endRows = $bucket['end'];
                $subCount = (int)($subscriptionCount[$rcp] ?? 1);
                $totalEvents = count($startRows) + count($endRows);

                // Bundel alle opgestapelde uitval/herstel-events in 1 mail, ook als de ontvanger
                // maar 1 target heeft (bijv. door een lange e-mailvertraging per target).
                if ($subCount > 1 || $totalEvents > 1) {
                    $subject = 'SmokePing - Uitval/herstel samenvatting (' . count($startRows) . ' nieuw, ' . count($endRows) . ' hersteld)';
                    $body = buildBatchOutageSummaryMail($startRows, $endRows, $now, $globalInterval);
                    $res = logAndSendEmail($db, $rcp, $subject, $body, 'outage_batch', 'recipient:' . $rcp);
                    if (!empty($res['success'])) {
                        foreach ($startRows as $row) {
                            $sentStartIds[(int)$row['id']] = 1;
                            $sentTargetIds[(int)$row['target_id']] = 1;
                        }
                        foreach ($endRows as $row) {
                            $sentEndIds[(int)$row['id']] = 1;
                            $sentTargetIds[(int)$row['target_id']] = 1;
                        }
                        $sentAny = true;
                    }
                    continue;
                }

                foreach ($startRows as $row) {
                    $startTs = parseDbDateToTs($row['started_at'] ?? null);
                    if ($startTs <= 0) $startTs = $now;
                    $subject = 'SmokePing - UITVAL: ' . $row['display_name'];
                    $res = logAndSendEmail($db, $rcp, $subject, buildOutageStartMailBody($row, $startTs), 'outage_start', (string)$row['display_name']);
                    if (!empty($res['success'])) {
                        $sentStartIds[(int)$row['id']] = 1;
                        $sentTargetIds[(int)$row['target_id']] = 1;
                        $sentAny = true;
                    }
                }

                foreach ($endRows as $row) {
                    $startTs = parseDbDateToTs($row['started_at'] ?? null);
                    $endTs = parseDbDateToTs($row['ended_at'] ?? null);
                    if ($startTs <= 0) $startTs = $now;
                    if ($endTs <= 0) $endTs = $now;
                    $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
                    $subject = 'SmokePing - Uitval opgelost: ' . $row['display_name'];
                    $res = logAndSendEmail($db, $rcp, $subject, buildOutageEndMailBody($row, $startTs, $endTs, $duration), 'outage_end', (string)$row['display_name']);
                    if (!empty($res['success'])) {
                        $sentEndIds[(int)$row['id']] = 1;
                        $sentTargetIds[(int)$row['target_id']] = 1;
                        $sentAny = true;
                    }
                }
            }
        }

        if (!empty($ignoredEndIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id IN (' . implode(',', array_map('intval', $ignoredEndIds)) . ')');
        }
        if (!empty($sentStartIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1 WHERE id IN (' . implode(',', array_keys($sentStartIds)) . ')');
        }
        if (!empty($sentEndIds)) {
            $db->exec('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id IN (' . implode(',', array_keys($sentEndIds)) . ')');
        }
        if (!empty($sentTargetIds)) {
            $nowDt = date('Y-m-d H:i:s');
            foreach (array_keys($sentTargetIds) as $tid) {
                $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
                $ut->bindValue(':dt', $nowDt, SQLITE3_TEXT);
                $ut->bindValue(':id', (int)$tid, SQLITE3_INTEGER);
                $ut->execute();
            }
        }
        if ($sentAny) {
            $u = $db->prepare('UPDATE email_settings SET last_outage_batch_sent=:dt WHERE id=1');
            $u->bindValue(':dt', date('Y-m-d H:i:s'));
            $u->execute();
        }
    } else {
        // Individual mode: send separate mail per outage
        $rows = $db->query('SELECT o.id, o.started_at, t.id AS target_id, t.display_name, t.host, t.session_notify_enabled, t.session_notify_email, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=1 AND (o.start_notified IS NULL OR o.start_notified=0) AND t.session_notify_enabled=1 AND t.enabled=1');
        while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
            $recipients = resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? ''));
            if (empty($recipients)) continue;
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            if ($startTs <= 0) $startTs = time();
            if (($now - $startTs) < $minOutageSeconds) continue;
            $subject = 'SmokePing - UITVAL: ' . $row['display_name'];
            $body = buildOutageStartMailBody($row, $startTs);
            logAndSendEmailList($db, $recipients, $subject, $body, 'outage_start', $row['display_name']);
            $u = $db->prepare('UPDATE target_outages SET start_notified=1 WHERE id=:id');
            $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER); $u->execute();
            $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
            $ut->bindValue(':dt', date('Y-m-d H:i:s'), SQLITE3_TEXT); $ut->bindValue(':id', (int)$row['target_id'], SQLITE3_INTEGER); $ut->execute();
        }
        // Stuur mail bij herstelde uitval in individuele modus
        $rows2 = $db->query('SELECT o.id, o.started_at, o.ended_at, o.duration_seconds, t.id AS target_id, t.display_name, t.host, t.session_notify_enabled, t.session_notify_email, c.display_name AS cat_display, c.name AS cat_name FROM target_outages o JOIN targets t ON o.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE o.is_open=0 AND o.start_notified=1 AND (o.end_notified IS NULL OR o.end_notified=0) AND t.session_notify_enabled=1');
        while ($row = $rows2->fetchArray(SQLITE3_ASSOC)) {
            $recipients = resolveNotifyRecipients($db, (string)($row['session_notify_email'] ?? ''));
            if (empty($recipients)) continue;
            $startTs = parseDbDateToTs($row['started_at'] ?? null);
            $endTs   = parseDbDateToTs($row['ended_at'] ?? null);
            $duration = (int)($row['duration_seconds'] ?? max(0, $endTs - $startTs));
            if ($duration < $minOutageSeconds) {
                $u = $db->prepare('UPDATE target_outages SET start_notified=1, end_notified=1 WHERE id=:id');
                $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER);
                $u->execute();
                continue;
            }
            $subject = 'SmokePing - Uitval opgelost: ' . $row['display_name'];
            $body = buildOutageEndMailBody($row, $startTs, $endTs, $duration);
            logAndSendEmailList($db, $recipients, $subject, $body, 'outage_end', $row['display_name']);
            $u = $db->prepare('UPDATE target_outages SET end_notified=1 WHERE id=:id');
            $u->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER); $u->execute();
            $ut = $db->prepare('UPDATE targets SET last_outage_notified_at=:dt WHERE id=:id');
            $ut->bindValue(':dt', date('Y-m-d H:i:s'), SQLITE3_TEXT); $ut->bindValue(':id', (int)$row['target_id'], SQLITE3_INTEGER); $ut->execute();
        }
    }
}

function getCats($db) {
    $key = 'db:getCats:' . smDbCacheVersion();
    return smCacheRemember($key, 300, static function () use ($db): array {
        $r = $db->query('SELECT * FROM categories WHERE LOWER(name)!="multihost_ipv4_ipv6" AND LOWER(name) NOT LIKE "%\\_ipv6" ESCAPE "\\" ORDER BY sort_order,name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getTargetsForCat($db,$cid) {
    $cid = (int)$cid;
    $key = 'db:getTargetsForCat:' . $cid . ':' . smDbCacheVersion();
    return smCacheRemember($key, 180, static function () use ($db, $cid): array {
        $s = $db->prepare('SELECT t.*, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.category_id=:c ORDER BY t.sort_order,t.name');
        $s->bindValue(':c', $cid, SQLITE3_INTEGER);
        $r = $s->execute();
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            if (!isManagerVisibleTargetRow($row)) continue;
            $a[] = $row;
        }
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getAllTargets($db) {
    $key = 'db:getAllTargets:' . smDbCacheVersion();
    return smCacheRemember($key, 180, static function () use ($db): array {
        $r = $db->query('SELECT t.*,c.name as cat_name,c.display_name as cat_display FROM targets t JOIN categories c ON t.category_id=c.id ORDER BY c.sort_order,c.name,t.sort_order,t.name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) {
            if (!isManagerVisibleTargetRow($row)) continue;
            $a[] = $row;
        }
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getPublicPendingTargets($db): array {
    $key = 'db:getPublicPendingTargets:' . smDbCacheVersion();
    return smCacheRemember($key, 180, static function () use ($db): array {
        $rows = [];
        $r = $db->query('SELECT t.*, c.name AS cat_name, c.display_name AS cat_display, datetime(t.created_at, "localtime") AS created_at_local FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.enabled=0 AND LOWER(COALESCE(t.submission_source, ""))="public_queue" ORDER BY c.sort_order, c.name, t.created_at, t.id');
        while ($r && ($row = $r->fetchArray(SQLITE3_ASSOC))) {
            if (!isManagerVisibleTargetRow($row)) continue;
            $rows[] = $row;
        }
        return $rows;
    }, static fn($value): bool => is_array($value));
}
function getCustomGraphs($db): array {
    $key = 'db:getCustomGraphs:' . smDbCacheVersion();
    return smCacheRemember($key, 180, static function () use ($db): array {
        $graphs = [];
        $rows = $db->query('SELECT * FROM custom_graphs ORDER BY group_name, title, id');
        while ($graph = $rows->fetchArray(SQLITE3_ASSOC)) {
            $graph['members'] = [];
            $stmt = $db->prepare('SELECT gm.*, t.display_name AS target_display, t.name AS target_name, t.host, t.host_ipv6, c.display_name AS cat_display, c.name AS cat_name
                                  FROM custom_graph_members gm
                                  JOIN targets t ON gm.target_id=t.id
                                  JOIN categories c ON t.category_id=c.id
                                  WHERE gm.graph_id=:id
                                  ORDER BY gm.sort_order, gm.id');
            $stmt->bindValue(':id', (int)$graph['id'], SQLITE3_INTEGER);
            $members = $stmt->execute();
            while ($member = $members->fetchArray(SQLITE3_ASSOC)) {
                $graph['members'][] = $member;
            }
            $graphs[] = $graph;
        }
        return $graphs;
    }, static fn($value): bool => is_array($value));
}
function buildTargetInternalNameBase(string $displayName): string {
    $base = strtolower(trim((string)$displayName));
    $base = preg_replace('/[^a-z0-9_]+/', '_', $base);
    $base = preg_replace('/_+/', '_', (string)$base);
    $base = trim((string)$base, '_');
    return $base !== '' ? $base : 'target';
}
function generateUniqueTargetName($db, int $categoryId, string $displayName, int $excludeId = 0): string {
    $base = buildTargetInternalNameBase($displayName);
    $name = $base;
    $suffix = 2;
    while (true) {
        $q = $db->prepare('SELECT COUNT(*) FROM targets WHERE category_id=:c AND name=:n' . ($excludeId > 0 ? ' AND id!=:id' : ''));
        $q->bindValue(':c', $categoryId, SQLITE3_INTEGER);
        $q->bindValue(':n', $name, SQLITE3_TEXT);
        if ($excludeId > 0) $q->bindValue(':id', $excludeId, SQLITE3_INTEGER);
        $exists = (int)$q->execute()->fetchArray(SQLITE3_NUM)[0] > 0;
        if (!$exists) return $name;
        $name = $base . '_' . $suffix;
        $suffix++;
    }
}
function getProbes($db) { 
    $key = 'db:getProbes:' . smDbCacheVersion();
    return smCacheRemember($key, 300, static function () use ($db): array {
        $r = $db->query('SELECT * FROM probes WHERE enabled=1 AND name IN ("FPing","FPing6") ORDER BY name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getAllProbes($db) {
    $key = 'db:getAllProbes:' . smDbCacheVersion();
    return smCacheRemember($key, 300, static function () use ($db): array {
        $r = $db->query('SELECT * FROM probes ORDER BY name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getAlerts($db) {
    $key = 'db:getAlerts:' . smDbCacheVersion();
    return smCacheRemember($key, 300, static function () use ($db): array {
        $r = $db->query('SELECT * FROM alerts WHERE enabled=1 ORDER BY display_name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getDefaultTargetAlertName($db): string {
    $key = 'db:getDefaultTargetAlertName:' . smDbCacheVersion();
    $value = smCacheRemember($key, 300, static function () use ($db): string {
        $s = $db->prepare('SELECT name FROM alerts WHERE enabled=1 AND name=:n LIMIT 1');
        $s->bindValue(':n', 'default_alert', SQLITE3_TEXT);
        $row = $s->execute()->fetchArray(SQLITE3_ASSOC);
        if ($row && !empty($row['name'])) return (string)$row['name'];

        $first = $db->query('SELECT name FROM alerts WHERE enabled=1 ORDER BY display_name LIMIT 1')->fetchArray(SQLITE3_ASSOC);
        return (string)($first['name'] ?? '');
    }, static fn($value): bool => is_string($value));
    return $value;
}
function getAllAlerts($db) {
    $key = 'db:getAllAlerts:' . smDbCacheVersion();
    return smCacheRemember($key, 300, static function () use ($db): array {
        $r = $db->query('SELECT * FROM alerts ORDER BY display_name');
        $a = [];
        while ($row = $r->fetchArray(SQLITE3_ASSOC)) $a[] = $row;
        return $a;
    }, static fn($value): bool => is_array($value));
}
function getSetting($db,$k,$d=''){
    static $requestCache = [];
    $cacheKey = smDbCacheVersion() . '|' . (string)$k;
    if (array_key_exists($cacheKey, $requestCache)) {
        return $requestCache[$cacheKey] === "\0__missing__\0" ? $d : $requestCache[$cacheKey];
    }
    $value = smCacheRemember('db:getSetting:' . $cacheKey, 300, static function () use ($db, $k): string {
        $s = $db->prepare('SELECT v FROM settings WHERE k=:k');
        $s->bindValue(':k', $k);
        $r = $s->execute()->fetchArray(SQLITE3_ASSOC);
        return $r ? (string)$r['v'] : "\0__missing__\0";
    }, static fn($value): bool => is_string($value));
    $requestCache[$cacheKey] = $value;
    return $value === "\0__missing__\0" ? $d : $value;
}
function setSetting($db,$k,$v){ $s=$db->prepare('INSERT OR REPLACE INTO settings(k,v) VALUES(:k,:v)'); $s->bindValue(':k',$k); $s->bindValue(':v',$v); $s->execute(); }
function logActivity($db, string $actionType, string $description): void {
    $uid  = (int)($_SESSION['uid'] ?? 0);
    $uname = $_SESSION['uname'] ?? ($_SESSION['un'] ?? 'systeem');
    $ip   = (string)($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '');
    $ip   = substr(trim(explode(',', $ip)[0]), 0, 45);
    $s = $db->prepare('INSERT INTO activity_log (user_id, username, action_type, description, ip_address) VALUES (:uid, :un, :at, :desc, :ip)');
    $s->bindValue(':uid',  $uid,        SQLITE3_INTEGER);
    $s->bindValue(':un',   $uname,      SQLITE3_TEXT);
    $s->bindValue(':at',   $actionType, SQLITE3_TEXT);
    $s->bindValue(':desc', $description,SQLITE3_TEXT);
    $s->bindValue(':ip',   $ip,         SQLITE3_TEXT);
    $s->execute();
    // Auto-mail when log hits a multiple of 100 lines
    if (getSetting($db, 'log_auto_100', '0') === '1') {
        $cnt = (int)$db->querySingle('SELECT COUNT(*) FROM activity_log');
        if ($cnt > 0 && $cnt % 100 === 0) {
            try { sendActivityLogEmail($db, "Automatisch: log heeft $cnt regels bereikt"); } catch (\Throwable $e) {}
        }
    }
}
function sendActivityLogEmail($db, string $reason = ''): array {
    $email = getSetting($db, 'log_email_address', '');
    if (empty($email)) {
        $es = $db->query('SELECT alert_recipients FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
        $email = normalizeEmailListString($es['alert_recipients'] ?? '');
    }
    if (empty($email)) return ['success'=>false,'msg'=>'Geen e-mailadres ingesteld voor logboek mails'];
    $rows = []; $res = $db->query('SELECT * FROM activity_log ORDER BY created_at DESC LIMIT 500');
    while ($r = $res->fetchArray(SQLITE3_ASSOC)) $rows[] = $r;
    $count = count($rows);
    $subject = 'SmokePing Manager – Activiteiten Log'.($reason ? " ($reason)" : '');
    $body  = '<html><body style="font-family:sans-serif;font-size:13px">';
    $body .= '<h2 style="color:#2563eb">📋 Activiteiten Log – SmokePing Manager</h2>';
    if ($reason) $body .= '<p><em>'.htmlspecialchars($reason).'</em></p>';
    $body .= '<p>Laatste <strong>'.htmlspecialchars((string)$count).'</strong> handelingen:</p>';
    $body .= '<table border="1" cellpadding="6" cellspacing="0" style="border-collapse:collapse;width:100%;font-size:12px">';
    $body .= '<tr style="background:#f0f4ff"><th>Datum/Tijd</th><th>Gebruiker</th><th>Actie</th><th>Omschrijving</th><th>IP</th></tr>';
    foreach ($rows as $row) {
        $body .= '<tr><td style="white-space:nowrap;color:#555">'.htmlspecialchars(formatDbDateLocal($row['created_at'] ?? '')).'</td>';
        $body .= '<td>'.htmlspecialchars($row['username']).'</td>';
        $body .= '<td><strong>'.htmlspecialchars($row['action_type']).'</strong></td>';
        $body .= '<td>'.htmlspecialchars($row['description']).'</td>';
        $body .= '<td style="color:#888;font-size:11px">'.htmlspecialchars($row['ip_address']).'</td></tr>';
    }
    $body .= '</table></body></html>';
    return logAndSendEmail($db, $email, $subject, $body, 'activity_log', '');
}
function parseEmailList(?string $raw): array {
    $raw = str_replace(["\r", "\n", ';'], ',', (string)$raw);
    $parts = array_filter(array_map('trim', explode(',', $raw)), static function ($v) { return $v !== ''; });
    $valid = []; $seen = [];
    foreach ($parts as $mail) {
        $m = strtolower($mail);
        if (!filter_var($m, FILTER_VALIDATE_EMAIL)) continue;
        if (isset($seen[$m])) continue;
        $seen[$m] = 1;
        $valid[] = $m;
    }
    return $valid;
}
function normalizeEmailListString(?string $raw): string {
    return implode(', ', parseEmailList($raw));
}
function getDefaultNotifyRecipientList($db): string {
    $row = $db->query('SELECT alert_recipients FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    return normalizeEmailListString($row['alert_recipients'] ?? '');
}
function resolveNotifyRecipients($db, ?string $preferredList): array {
    $preferred = normalizeEmailListString($preferredList);
    if ($preferred !== '') return parseEmailList($preferred);
    return parseEmailList(getDefaultNotifyRecipientList($db));
}
function getDefaultTestEmail($db): string {
    $list = parseEmailList(getDefaultNotifyRecipientList($db));
    if (!empty($list)) return (string)$list[0];
    $row = $db->query('SELECT smtp_from_email, smtp_username FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    $candidate = trim((string)($row['smtp_from_email'] ?? ''));
    if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_EMAIL)) return $candidate;
    $candidate = trim((string)($row['smtp_username'] ?? ''));
    if ($candidate !== '' && filter_var($candidate, FILTER_VALIDATE_EMAIL)) return $candidate;
    return '';
}
$theme = getSetting($db,'theme','auto');
if(!in_array($theme,['auto','light','dark'],true)) $theme='auto';
$fontsize = getSetting($db,'fontsize','14');
if(!in_array($fontsize,['10','12','14','16','18','20','22','24'],true)) $fontsize='14';
$uiSessionTimeoutHours = getSetting($db,'ui_session_timeout_hours','24');
if(!in_array($uiSessionTimeoutHours,['24','168','720'],true)) $uiSessionTimeoutHours='24';
$uiSessionTimeoutLabel = $uiSessionTimeoutHours === '720'
    ? '1 maand'
    : ($uiSessionTimeoutHours === '168' ? '1 week' : '1 dag');

function deepLink(string $catName, string $targetName=''): string {
    $path = safeName($catName);
    if ($targetName) $path .= '.' . safeName($targetName);
    return SMOKEPING_CGI_URL . '?target=' . $path;
}

// RRD data uitlezen voor uptime info
function rrdtoolBin(): string {
    static $bin = null;
    if ($bin === null) {
        foreach (['/usr/bin/rrdtool','/usr/local/bin/rrdtool','/opt/homebrew/bin/rrdtool'] as $p) {
            if (file_exists($p)) { $bin = $p; break; }
        }
        if ($bin === null) $bin = 'rrdtool';
    }
    return $bin;
}
function isRrdUnknownValue($value): bool {
    if ($value === null) return true;
    $v = strtolower(trim((string)$value));
    return $v === '' || $v === 'u' || $v === 'nan' || $v === '-nan';
}
function findRrdColumnIndex(array $lines, string $column, int $default = 0): int {
    $needle = strtolower($column);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) continue;
        if (stripos($line, $column) === false) continue;
        $cols = preg_split('/\s+/', trim($line));
        if (!$cols) continue;
        $idx = array_search($needle, array_map('strtolower', $cols), true);
        if ($idx !== false) return (int)$idx;
    }
    return $default;
}
function getRrdPingColumnCount(array $lines): int {
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) continue;
        $cols = preg_split('/\s+/', trim($line));
        if (!$cols) continue;
        $count = 0;
        foreach ($cols as $col) {
            if (preg_match('/^ping\d+$/i', $col)) $count++;
        }
        if ($count > 0) return $count;
    }
    return 0;
}

function getTargetStatus(string $catName, string $targetName, bool $includeDowntime = false): array {
    static $baseCache = [];
    static $downtimeCache = [];

    $key = safeName($catName) . '|' . safeName($targetName);
    if (!isset($baseCache[$key])) {
        $cacheVal = null;
        if (smCacheGet('target_status:' . $key, 30, $cacheVal) && is_array($cacheVal)) {
            $baseCache[$key] = $cacheVal;
        } else {
            smCacheMiss();
            $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
            $result = ['exists' => false, 'loss' => null, 'median' => null, 'sample_ts' => null, 'last_down' => null, 'downtime_str' => ''];
            if (file_exists($rrdFile)) {
                $result['exists'] = true;
                $out = @shell_exec(rrdtoolBin() . " lastupdate " . escapeshellarg($rrdFile) . " 2>/dev/null");
                if ($out) {
                    $lines = explode("\n", trim($out));
                    $lossIdx = findRrdColumnIndex($lines, 'loss', 0);
                    $medianIdx = findRrdColumnIndex($lines, 'median', 1);
                    $pingCols = getRrdPingColumnCount($lines);
                    $last = end($lines);
                    if (preg_match('/^(\d+):\s+(.+)/', $last, $m)) {
                        $result['sample_ts'] = (int)$m[1];
                        $vals = preg_split('/\s+/', trim($m[2]));
                        $loss = $vals[$lossIdx] ?? null;
                        $median = $vals[$medianIdx] ?? null;
                        if (!isRrdUnknownValue($loss)) {
                            $lossVal = (float)$loss;
                            $result['loss'] = ($pingCols > 0 && $lossVal > 1.0) ? ($lossVal / $pingCols) : $lossVal;
                        } else {
                            $result['loss'] = null;
                        }
                        $result['median'] = !isRrdUnknownValue($median) ? round((float)$median * 1000, 2) : null;
                    }
                }
            }
            $baseCache[$key] = $result;
            smCacheSet('target_status:' . $key, $result, 30);
        }
    }

    if (!$includeDowntime) {
        return $baseCache[$key];
    }

    if (isset($downtimeCache[$key])) {
        return $downtimeCache[$key];
    }

    $result = $baseCache[$key];
    if (!$result['exists']) {
        $downtimeCache[$key] = $result;
        return $result;
    }

    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
    $fetch = @shell_exec(rrdtoolBin() . " fetch " . escapeshellarg($rrdFile) . " AVERAGE -s -3600 2>/dev/null");
    if ($fetch) {
        $fetchLines = explode("\n", $fetch);
        $lossIdx = findRrdColumnIndex($fetchLines, 'loss', 0);
        $downPeriods = [];
        $inDown = false;
        $downStart = 0;
        $lastTs = 0;
        foreach ($fetchLines as $line) {
            if (preg_match('/^(\d+):\s+(.+)/', $line, $m)) {
                $ts = (int)$m[1];
                $lastTs = $ts;
                $vals = preg_split('/\s+/', trim($m[2]));
                $loss = $vals[$lossIdx] ?? null;
                if (isRrdUnknownValue($loss) || (float)$loss >= 1.0) {
                    if (!$inDown) { $inDown = true; $downStart = $ts; }
                } else {
                    if ($inDown) {
                        $dur = $ts - $downStart;
                        $min = floor($dur / 60);
                        $sec = $dur % 60;
                        $downPeriods[] = date('d-m-Y H:i:s', $downStart) . " internet {$min} minuten en {$sec} seconden inactief";
                        $inDown = false;
                    }
                }
            }
        }
        if ($inDown && $downStart > 0) {
            $endTs = $lastTs > $downStart ? $lastTs : time();
            $dur = max(0, $endTs - $downStart);
            $min = floor($dur / 60);
            $sec = $dur % 60;
            $downPeriods[] = date('d-m-Y H:i:s', $downStart) . " internet {$min} minuten en {$sec} seconden inactief (lopend)";
        }
        if (!empty($downPeriods)) {
            $result['downtime_str'] = implode("\n", array_slice($downPeriods, -5));
        }
    }

    $downtimeCache[$key] = $result;
    return $result;
}

// Bereken uptime percentage voor target
function getTargetUptime(string $catName, string $targetName, int $periodHours = 24): array {
    static $cache = [];
    $cacheKey = safeName($catName) . '|' . safeName($targetName) . '|' . $periodHours;
    if (isset($cache[$cacheKey])) return $cache[$cacheKey];

    $cachedVal = null;
    if (smCacheGet('target_uptime:' . $cacheKey, 90, $cachedVal) && is_array($cachedVal)) {
        return $cache[$cacheKey] = $cachedVal;
    }
    smCacheMiss();

    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
    $result = ['uptime' => null, 'loss_avg' => null, 'status' => 'unknown'];
    if (!file_exists($rrdFile)) return $cache[$cacheKey] = $result;

    // Fetch data voor de gegeven periode
    $fetch = @shell_exec(rrdtoolBin() . " fetch " . escapeshellarg($rrdFile) . " AVERAGE -s -" . ($periodHours * 3600) . " 2>/dev/null");
    if (!$fetch) return $cache[$cacheKey] = $result;
    
    $lines = explode("\n", $fetch);
    $lossIdx = findRrdColumnIndex($lines, 'loss', 0);
    $pingCols = getRrdPingColumnCount($lines);
    $dataPoints = 0;
    $downPoints = 0;
    $firstTs = 0;
    $lastTs = 0;
    $prevTs = 0;
    $stepSec = 0;
    $downCount = 0;
    
    foreach ($lines as $line) {
        if (preg_match('/^(\d+):\s+(.+)/', $line, $m)) {
            $ts = (int)$m[1];
            if ($firstTs <= 0) $firstTs = $ts;
            $lastTs = $ts;
            if ($prevTs > 0) {
                $delta = $ts - $prevTs;
                if ($delta > 0 && ($stepSec === 0 || $delta < $stepSec)) $stepSec = $delta;
            }
            $prevTs = $ts;
            $vals = preg_split('/\s+/', trim($m[2]));
            $loss = $vals[$lossIdx] ?? null;
            $isDown = false;
            if (isRrdUnknownValue($loss)) {
                continue;
            } else {
                $lossVal = (float)$loss;
                $lossFrac = ($pingCols > 0 && $lossVal > 1.0) ? ($lossVal / $pingCols) : $lossVal;
                if ($lossFrac >= 1.0) $isDown = true;
            }
            if ($isDown) {
                $downCount++;
                $downPoints++;
            }
            $dataPoints++;
        }
    }
    
    if ($dataPoints > 0) {
        if ($stepSec <= 0) $stepSec = 10;
        $dataDuration = max($stepSec, ($lastTs - $firstTs) + $stepSec);
        $downDuration = min($dataDuration, $downPoints * $stepSec);
        $outagePct = ($dataDuration > 0) ? (($downDuration / $dataDuration) * 100) : 0;
        $uptime = 100 - $outagePct;
        $result['uptime'] = max(0, min(100, round($uptime, 2)));
        $result['loss_avg'] = round($outagePct, 2);
        
        // Status bepaling
        if ($uptime >= 99) {
            $result['status'] = 'ok';
        } elseif ($uptime >= 95) {
            $result['status'] = 'warning';
        } else {
            $result['status'] = 'down';
        }
    }

    smCacheSet('target_uptime:' . $cacheKey, $result, 90);
    return $cache[$cacheKey] = $result;
}

function parseDbDateToTs(?string $value): int {
    if ($value === null || trim($value) === '') return 0;
    // Parse database datetime strings as UTC, not local timezone
    $value = trim($value);
    if (preg_match('/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})$/', $value, $m)) {
        return (int)gmmktime((int)$m[4], (int)$m[5], (int)$m[6], (int)$m[2], (int)$m[3], (int)$m[1]);
    }
    return 0;
}

function formatDbDateLocal(?string $value, string $format = 'd-m-Y H:i:s'): string {
    $ts = parseDbDateToTs($value);
    if ($ts <= 0) return (string)($value ?? '');
    return date($format, $ts);
}

function formatDurationSeconds(int $seconds): string {
    if ($seconds <= 0) return '0s';
    $hours = (int)floor($seconds / 3600);
    $minutes = (int)floor(($seconds % 3600) / 60);
    $secs = (int)($seconds % 60);
    $parts = [];
    if ($hours > 0) $parts[] = $hours . 'u';
    if ($minutes > 0 || $hours > 0) $parts[] = $minutes . 'm';
    $parts[] = $secs . 's';
    return implode(' ', $parts);
}

function formatDateTimeNl(int $ts): string {
    if ($ts <= 0) return '-';
    return date('d-m-Y H:i:s', $ts);
}

function getTargetSessionStartTs(array $target): int {
    $sessionStart = parseDbDateToTs($target['session_started_at'] ?? null);
    if ($sessionStart > 0) return $sessionStart;
    $created = parseDbDateToTs($target['created_at'] ?? null);
    if ($created > 0) return $created;
    return time();
}

function syncTargetOutageState($db, array $target, array $status): void {
    $targetId = (int)($target['id'] ?? 0);
    if ($targetId <= 0) return;

    $sampleTs = (int)($status['sample_ts'] ?? 0);
    if ($sampleTs <= 0) $sampleTs = time();

    $openQ = $db->prepare('SELECT id, started_at FROM target_outages WHERE target_id=:tid AND is_open=1 ORDER BY id DESC LIMIT 1');
    $openQ->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $openRow = $openQ->execute()->fetchArray(SQLITE3_ASSOC);

    // Check: target is down if either:
    // 1) Has measurement AND full packet loss
    // 2) Has RRD file but data is stale beyond configured threshold
    $hasMeasure = ((int)($target['enabled'] ?? 0) === 1) && !empty($status['exists']) && $status['loss'] !== null;
    static $staleThresholdSec = null;
    if ($staleThresholdSec === null) {
        $cfgStale = max(20, (int)getSetting($db, 'outage_stale_seconds', '20'));
        $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes WHERE enabled=1');
        if ($probeStepSec <= 0) $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes');
        if ($probeStepSec <= 0) $probeStepSec = 300;
        $staleThresholdSec = max($cfgStale, 120, $probeStepSec * 2);
    }
    $isStaleData = ((int)($target['enabled'] ?? 0) === 1) && !empty($status['exists']) && (time() - $sampleTs > $staleThresholdSec);
    $isDown = ($hasMeasure && ((float)$status['loss'] >= 1.0)) || $isStaleData;

    if ($isDown) {
        if (!$openRow) {
            $ins = $db->prepare('INSERT INTO target_outages(target_id, started_at, is_open, start_source_ts, updated_at) VALUES(:tid, datetime(:st, "unixepoch"), 1, :st, CURRENT_TIMESTAMP)');
            $ins->bindValue(':tid', $targetId, SQLITE3_INTEGER);
            $ins->bindValue(':st', $sampleTs, SQLITE3_INTEGER);
            $ins->execute();
        }
        return;
    }

    // Keep outage open when measurement is uncertain (fresh sample but unknown loss) to avoid open/close flapping.
    if ($openRow && $status['loss'] === null && !$isStaleData) {
        return;
    }

    if ($openRow) {
        $startTs = parseDbDateToTs($openRow['started_at'] ?? null);
        if ($startTs <= 0) $startTs = $sampleTs;
        $endTs = max($sampleTs, $startTs);
        $duration = max(0, $endTs - $startTs);
        $upd = $db->prepare('UPDATE target_outages SET ended_at=datetime(:et, "unixepoch"), duration_seconds=:dur, is_open=0, end_source_ts=:et, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $upd->bindValue(':et', $endTs, SQLITE3_INTEGER);
        $upd->bindValue(':dur', $duration, SQLITE3_INTEGER);
        $upd->bindValue(':id', (int)$openRow['id'], SQLITE3_INTEGER);
        $upd->execute();
    }
}

function collectTargetOutageSummary($db, array $target): array {
    $targetId = (int)($target['id'] ?? 0);
    $sessionStartTs = getTargetSessionStartTs($target);
    $result = ['session_started_at' => $sessionStartTs, 'total_downtime_seconds' => 0, 'events' => []];
    
    if ($targetId <= 0) return $result;
    
    $q = $db->prepare('SELECT id, started_at, ended_at, duration_seconds, is_open FROM target_outages WHERE target_id=:tid ORDER BY started_at DESC LIMIT 50');
    $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $result_set = $q->execute();
    
    while ($row = $result_set->fetchArray(SQLITE3_ASSOC)) {
        $isOpen = (int)($row['is_open'] ?? 0) === 1;
        $startTs = parseDbDateToTs($row['started_at'] ?? null);
        if ($startTs <= 0) continue;
        if ($startTs < $sessionStartTs) continue;
        
        $rawEndTs = parseDbDateToTs($row['ended_at'] ?? null);
        $endTs = $isOpen ? time() : $rawEndTs;
        if ($endTs <= 0) $endTs = time();
        
        $clipStart = max($startTs, $sessionStartTs);
        $clipEnd = max($clipStart, $endTs);
        $durationForTotal = max(0, $clipEnd - $clipStart);
        $result['total_downtime_seconds'] += $durationForTotal;
        
        $displayDuration = (int)($row['duration_seconds'] ?? 0);
        if ($isOpen || $displayDuration <= 0) $displayDuration = max(0, $endTs - $startTs);
        
        $result['events'][] = [
            'id' => (int)$row['id'],
            'is_open' => $isOpen,
            'started_at_ts' => $startTs,
            'ended_at_ts' => $isOpen ? null : $rawEndTs,
            'duration_seconds' => $displayDuration,
            'duration_label' => formatDurationSeconds($displayDuration),
            'started_at_label' => formatDateTimeNl($startTs),
            'ended_at_label' => $isOpen ? 'Lopend' : formatDateTimeNl($rawEndTs),
        ];
    }
    return $result;
}

function logPingLossSample($db, array $target, array $status): void {
    $targetId = (int)($target['id'] ?? 0);
    if ($targetId <= 0) return;
    if ((int)($target['enabled'] ?? 0) !== 1) return;

    $sampleTs = (int)($status['sample_ts'] ?? 0);
    $lossFrac = $status['loss'] ?? null;
    if ($sampleTs <= 0 || $lossFrac === null) return;
    $lossFrac = (float)$lossFrac;
    if ($lossFrac <= 0.0) return;

    $ins = $db->prepare('INSERT OR IGNORE INTO target_ping_loss_events(target_id, sample_ts, loss_fraction, is_full_loss, notified, created_at) VALUES(:tid, :ts, :loss, :full, 0, CURRENT_TIMESTAMP)');
    $ins->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $ins->bindValue(':ts', $sampleTs, SQLITE3_INTEGER);
    $ins->bindValue(':loss', $lossFrac, SQLITE3_FLOAT);
    $ins->bindValue(':full', $lossFrac >= 1.0 ? 1 : 0, SQLITE3_INTEGER);
    $ins->execute();
}

function buildPingLossGroups(array $events, int $gapSeconds = 120): array {
    if (empty($events)) return [];
    usort($events, static function ($a, $b) {
        return ((int)($a['sample_ts'] ?? 0)) <=> ((int)($b['sample_ts'] ?? 0));
    });

    $groups = [];
    $current = null;
    foreach ($events as $ev) {
        $ts = (int)($ev['sample_ts'] ?? 0);
        if ($ts <= 0) continue;
        $loss = max(0.0, min(1.0, (float)($ev['loss_fraction'] ?? 0)));
        if ($current === null) {
            $current = ['start_ts' => $ts, 'end_ts' => $ts, 'count' => 1, 'max_loss' => $loss, 'ids' => [(int)($ev['id'] ?? 0)]];
            continue;
        }
        if (($ts - (int)$current['end_ts']) <= $gapSeconds) {
            $current['end_ts'] = $ts;
            $current['count']++;
            if ($loss > (float)$current['max_loss']) $current['max_loss'] = $loss;
            $current['ids'][] = (int)($ev['id'] ?? 0);
        } else {
            $groups[] = $current;
            $current = ['start_ts' => $ts, 'end_ts' => $ts, 'count' => 1, 'max_loss' => $loss, 'ids' => [(int)($ev['id'] ?? 0)]];
        }
    }
    if ($current !== null) $groups[] = $current;
    return $groups;
}

function collectSessionPingLossSummary($db, int $targetId, int $sessionStartTs, int $sessionEndTs, int $limit = 200): array {
    $summary = ['total_samples' => 0, 'groups' => [], 'event_ids' => []];
    if ($targetId <= 0 || $sessionEndTs <= $sessionStartTs) return $summary;

    $q = $db->prepare('SELECT id, sample_ts, loss_fraction, is_full_loss FROM target_ping_loss_events WHERE target_id=:tid AND sample_ts>=:st AND sample_ts<=:et ORDER BY sample_ts ASC LIMIT :lim');
    $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
    $q->bindValue(':st', $sessionStartTs, SQLITE3_INTEGER);
    $q->bindValue(':et', $sessionEndTs, SQLITE3_INTEGER);
    $q->bindValue(':lim', $limit, SQLITE3_INTEGER);
    $rows = $q->execute();

    $events = [];
    while ($row = $rows->fetchArray(SQLITE3_ASSOC)) {
        $events[] = $row;
        $summary['event_ids'][] = (int)($row['id'] ?? 0);
    }
    $summary['total_samples'] = count($events);
    $summary['groups'] = buildPingLossGroups($events);
    return $summary;
}

function buildPingLossMailBody(array $target, array $groups, int $sampleCount): string {
    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:620px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#d97706 0%,#92400e 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">Pingverlies gedetecteerd</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Pingverlies rapport</div></div>';
    $body .= '<div style="padding:24px 32px">';
    $body .= '<p style="margin:0 0 14px;color:#374151;font-size:15px">Target <strong style="color:#92400e">'.htmlspecialchars((string)$target['display_name']).'</strong> had pingverlies.</p>';
    $body .= '<p style="margin:0 0 14px;color:#78350f;font-size:13px">Meetmomenten met verlies: <strong>'.(int)$sampleCount.'</strong></p>';
    $body .= '<ul style="margin:8px 0 0 16px;padding:0;color:#78350f;font-size:13px">';
    foreach (array_slice($groups, 0, 12) as $pg) {
        $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
        $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
        if ($gCount <= 1) {
            $body .= '<li style="margin:4px 0">'.date('d-m-Y H:i:s', $gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
        } else {
            $body .= '<li style="margin:4px 0">Van '.date('d-m-Y H:i:s', $gStart).' t/m '.date('d-m-Y H:i:s', $gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
        }
    }
    $body .= '</ul></div>';
    $body .= '<div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatische pingverlies melding</div>';
    $body .= '</div></body></html>';
    return $body;
}

function buildSessionSnapshotMailBody(array $t, string $dur, int $startedAt, int $snapshotTs, array $st, array $ut, array $outageSummary, array $pingSummary, string $modeLabel = 'Tussenstand'): string {
    $lossPct = $st['loss'] !== null ? round(((float)$st['loss']) * 100, 1) . '%' : 'n.v.t.';
    $median = $st['median'] !== null ? $st['median'] . ' ms' : 'n.v.t.';
    $uptime = $ut['uptime'] !== null ? $ut['uptime'] . '%' : 'n.v.t.';

    $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
    $body .= '<div style="max-width:660px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
    $body .= '<div style="background:linear-gradient(135deg,#2563eb 0%,#1e3a8a 100%);padding:28px 32px">';
    $body .= '<div style="color:#fff;font-size:22px;font-weight:700">Sessie '.$modeLabel.'</div>';
    $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Sessie samenvatting</div></div>';
    $body .= '<div style="padding:24px 32px">';
    if ($dur === 'unlimited') {
        $body .= '<p style="margin:0 0 12px;color:#1e3a8a;font-size:14px"><strong>Deze sessie loopt onbeperkt door.</strong></p>';
    }
    $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
    $rows = [
        ['Categorie', htmlspecialchars((string)$t['cat_display'])],
        ['Target', '<strong>'.htmlspecialchars((string)$t['display_name']).'</strong>'],
        ['Host', '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px">'.htmlspecialchars((string)$t['host']).'</code>'],
        ['Sessieduur', htmlspecialchars(sessionDurationLabel($dur))],
        ['Gestart op', date('d-m-Y H:i:s', $startedAt)],
        ['Snapshot op', date('d-m-Y H:i:s', $snapshotTs)],
        ['Packet loss', htmlspecialchars($lossPct)],
        ['Median RTT', htmlspecialchars($median)],
        ['Uptime', htmlspecialchars($uptime)],
    ];
    foreach ($rows as $i => $rowInfo) {
        $bg = ($i % 2 === 0) ? '#f9fafb' : '#fff';
        $body .= '<tr style="background:'.$bg.'"><td style="padding:8px 12px;font-size:12px;color:#6b7280;width:150px">'.$rowInfo[0].'</td><td style="padding:8px 12px;font-size:14px;color:#111827">'.$rowInfo[1].'</td></tr>';
    }
    $body .= '</table>';

    $events = is_array($outageSummary['events'] ?? null) ? $outageSummary['events'] : [];
    if (!empty($events)) {
        $body .= '<div style="margin-top:14px;background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px">';
        $body .= '<div style="font-size:13px;font-weight:700;color:#9a3412;margin-bottom:8px">Uitval tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#7c2d12;font-size:12px">';
        foreach (array_slice($events, 0, 10) as $ev) {
            $sTs = (int)($ev['started_at_ts'] ?? 0);
            $eTsRaw = (int)($ev['ended_at_ts'] ?? 0);
            $eTs = $eTsRaw > 0 ? $eTsRaw : $snapshotTs;
            $durSec = max(0, $eTs - $sTs);
            if ($durSec >= 60) {
                $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $sTs).' t/m '.date('d-m-Y H:i:s', $eTs).' ('.formatDurationSeconds($durSec).')</li>';
            } else {
                $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $sTs).' ('.formatDurationSeconds($durSec).')</li>';
            }
        }
        $body .= '</ul></div>';
    }

    $pingGroups = is_array($pingSummary['groups'] ?? null) ? $pingSummary['groups'] : [];
    if (!empty($pingGroups)) {
        $body .= '<div style="margin-top:14px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px">';
        $body .= '<div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:8px">Pingverlies tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#78350f;font-size:12px">';
        foreach (array_slice($pingGroups, 0, 12) as $pg) {
            $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
            $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
            if ($gCount <= 1) {
                $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
            } else {
                $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $gStart).' t/m '.date('d-m-Y H:i:s', $gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
            }
        }
        $body .= '</ul></div>';
    }

    $body .= '</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Automatisch gegenereerde sessie samenvatting</div></div></body></html>';
    return $body;
}

function processPingLossNotifications($db): void {
    $settings = $db->query('SELECT ping_loss_notifications, outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    if ((int)($settings['ping_loss_notifications'] ?? 0) !== 1) return;
    $globalInterval = max(1, (int)($settings['outage_mail_interval'] ?? 5));
    $now = time();

    $targets = $db->query('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.enabled=1 AND t.session_notify_enabled=1');
    while ($t = $targets->fetchArray(SQLITE3_ASSOC)) {
        $targetId = (int)($t['id'] ?? 0);
        if ($targetId <= 0) continue;
        $targetInterval = isset($t['outage_mail_interval']) && $t['outage_mail_interval'] !== null
            ? max(1, (int)$t['outage_mail_interval'])
            : $globalInterval;

        $q = $db->prepare('SELECT id, sample_ts, loss_fraction, is_full_loss FROM target_ping_loss_events WHERE target_id=:tid AND notified=0 ORDER BY sample_ts ASC LIMIT 250');
        $q->bindValue(':tid', $targetId, SQLITE3_INTEGER);
        $rows = $q->execute();
        $events = [];
        while ($row = $rows->fetchArray(SQLITE3_ASSOC)) $events[] = $row;
        if (empty($events)) continue;

        $firstTs = (int)($events[0]['sample_ts'] ?? 0);
        if ($firstTs <= 0) continue;
        if (($now - $firstTs) < ($targetInterval * 60)) continue;

        $groups = buildPingLossGroups($events);
        if (empty($groups)) continue;

        $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
        if (empty($recipients)) continue;

        $subject = 'SmokePing - Pingverlies: ' . $t['display_name'];
        $body = buildPingLossMailBody($t, $groups, count($events));
        $res = logAndSendEmailList($db, $recipients, $subject, $body, 'ping_loss', $t['display_name']);
        if (!empty($res['success'])) {
            $ids = [];
            foreach ($events as $ev) {
                $id = (int)($ev['id'] ?? 0);
                if ($id > 0) $ids[] = $id;
            }
            if (!empty($ids)) {
                $db->exec('UPDATE target_ping_loss_events SET notified=1, notified_at=CURRENT_TIMESTAMP WHERE id IN (' . implode(',', $ids) . ')');
            }
        }
    }
}

function updateOutageTracking($db): void {
    static $lastRun = 0;
    $now = time();
    if (($now - $lastRun) < 3) return;
    $lastRun = $now;

    foreach (getAllTargets($db) as $target) {
        $status = getTargetStatus($target['cat_name'], $target['name']);
        syncTargetOutageState($db, $target, $status);
        logPingLossSample($db, $target, $status);
    }
}

// Email Sending Function (Pure PHP SMTP Implementation)
function sendEmail($db, $to, $subject, $body, &$debug_output = null): array {
    $result = ['success' => false, 'message' => ''];
    $debug = [];
    
    // Get SMTP settings from database
    $settings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    if (!$settings || !$settings['smtp_enabled']) {
        $result['message'] = 'SMTP is niet ingeschakeld';
        return $result;
    }
    
    // Validate required settings
    if (empty($settings['smtp_host']) || empty($settings['smtp_username']) || empty($settings['smtp_password'])) {
        $result['message'] = 'SMTP configuratie is niet volledig';
        return $result;
    }
    
    $host = $settings['smtp_host'];
    $port = (int)$settings['smtp_port'];
    $username = $settings['smtp_username'];
    $password = smDecryptPassword($settings['smtp_password']);
    $encryption = $settings['smtp_encryption']; // 'none', 'tls', 'ssl'
    $from_email = !empty($settings['smtp_from_email']) ? $settings['smtp_from_email'] : $username;
    $from_name = !empty($settings['smtp_from_name']) ? $settings['smtp_from_name'] : 'SmokePing Manager';
    
    // Validate recipient email
    if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
        $result['message'] = 'Ongeldig e-mailadres: ' . $to;
        return $result;
    }
    
    try {
        // Determine connection type
        $remote = $host . ':' . $port;
        if ($encryption === 'ssl') {
            $remote = 'ssl://' . $remote;
        }
        
        $debug[] = "Connecting to: $remote";
        
        // Open socket connection
        $errno = 0;
        $errstr = '';
        $socket = @stream_socket_client($remote, $errno, $errstr, 30, STREAM_CLIENT_CONNECT);
        
        if (!$socket) {
            $result['message'] = "Kan geen verbinding maken: $errstr ($errno)";
            $debug[] = "ERROR: " . $result['message'];
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // Set timeout
        stream_set_timeout($socket, 30);
        
        // Read server greeting
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '220') {
            $result['message'] = 'SMTP server antwoordt niet correct: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // Send EHLO
        $cmd = "EHLO " . $host . "\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = '';
        while ($line = fgets($socket, 515)) {
            $response .= $line;
            $debug[] = "< " . trim($line);
            if (substr($line, 3, 1) == ' ') break; // Last line of response
        }
        
        // STARTTLS if needed
        if ($encryption === 'tls') {
            $cmd = "STARTTLS\r\n";
            $debug[] = "> " . trim($cmd);
            fputs($socket, $cmd);
            $response = fgets($socket, 515);
            $debug[] = "< " . trim($response);
            if (substr($response, 0, 3) != '220') {
                $result['message'] = 'STARTTLS mislukt: ' . trim($response);
                $debug[] = "ERROR: " . $result['message'];
                fclose($socket);
                $debug_output = implode("\n", $debug);
                return $result;
            }
            
            // Enable TLS encryption
            if (!stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                $result['message'] = 'TLS encryptie activeren mislukt';
                $debug[] = "ERROR: " . $result['message'];
                fclose($socket);
                $debug_output = implode("\n", $debug);
                return $result;
            }
            $debug[] = "TLS encryption enabled";
            
            // Send EHLO again after STARTTLS
            $cmd = "EHLO " . $host . "\r\n";
            $debug[] = "> " . trim($cmd);
            fputs($socket, $cmd);
            $response = '';
            while ($line = fgets($socket, 515)) {
                $response .= $line;
                $debug[] = "< " . trim($line);
                if (substr($line, 3, 1) == ' ') break;
            }
        }
        
        // AUTH LOGIN
        $cmd = "AUTH LOGIN\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '334') {
            $result['message'] = 'AUTH LOGIN niet ondersteund: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // Send username (base64 encoded)
        $cmd = base64_encode($username) . "\r\n";
        $debug[] = "> " . base64_encode($username);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '334') {
            $result['message'] = 'Username niet geaccepteerd: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // Send password (base64 encoded)
        $cmd = base64_encode($password) . "\r\n";
        $debug[] = "> [PASSWORD HIDDEN]";
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '235') {
            $result['message'] = 'Authenticatie mislukt. Controleer username/password: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        $debug[] = "Authentication successful";
        
        // MAIL FROM
        $cmd = "MAIL FROM: <$from_email>\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '250') {
            $result['message'] = 'MAIL FROM mislukt: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // RCPT TO
        $cmd = "RCPT TO: <$to>\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '250') {
            $result['message'] = 'RCPT TO mislukt: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // DATA
        $cmd = "DATA\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '354') {
            $result['message'] = 'DATA commando mislukt: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        // Build email headers and body
        $email_data = "From: $from_name <$from_email>\r\n";
        $email_data .= "To: $to\r\n";
        $email_data .= "Subject: $subject\r\n";
        $email_data .= "Date: " . date('r') . "\r\n";
        $email_data .= "MIME-Version: 1.0\r\n";
        $email_data .= "Content-Type: text/html; charset=UTF-8\r\n";
        $email_data .= "Content-Transfer-Encoding: 8bit\r\n";
        $email_data .= "\r\n";
        $email_data .= $body . "\r\n";
        $email_data .= ".\r\n"; // End of data marker
        
        $debug[] = "> [EMAIL HEADERS + BODY]";
        fputs($socket, $email_data);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        if (substr($response, 0, 3) != '250') {
            $result['message'] = 'Email verzenden mislukt: ' . trim($response);
            $debug[] = "ERROR: " . $result['message'];
            fclose($socket);
            $debug_output = implode("\n", $debug);
            return $result;
        }
        
        $debug[] = "Email sent successfully!";
        
        // QUIT
        $cmd = "QUIT\r\n";
        $debug[] = "> " . trim($cmd);
        fputs($socket, $cmd);
        $response = fgets($socket, 515);
        $debug[] = "< " . trim($response);
        
        fclose($socket);
        
        $result['success'] = true;
        $result['message'] = 'Email succesvol verzonden naar ' . $to;
        $debug[] = "Connection closed";
        
    } catch (Exception $e) {
        $result['message'] = 'Exception: ' . $e->getMessage();
        $debug[] = "EXCEPTION: " . $e->getMessage();
    }
    
    $debug_output = implode("\n", $debug);
    return $result;
}

// Mail Logging Wrapper — slaat elke send-poging op in mail_log
function trimMailLog($db, int $limit = 500): void {
    try {
        $db->exec('DELETE FROM mail_log WHERE id NOT IN (SELECT id FROM mail_log ORDER BY id DESC LIMIT '.max(1, $limit).')');
    } catch (\Exception $e) {}
}

function insertMailLogEntry($db, string $type, string $targetName, string $to, string $subject, string $status, string $message, string $debug, string $body): int {
    $s = $db->prepare('INSERT INTO mail_log(type,target_name,email_to,subject,status,message,debug_output,body)
                       VALUES(:tp,:tn,:to,:sb,:st,:ms,:dbg,:bd)');
    $s->bindValue(':tp', $type);
    $s->bindValue(':tn', $targetName);
    $s->bindValue(':to', $to);
    $s->bindValue(':sb', $subject);
    $s->bindValue(':st', $status);
    $s->bindValue(':ms', $message);
    $s->bindValue(':dbg', $debug);
    $s->bindValue(':bd', $body);
    $s->execute();
    trimMailLog($db);
    return (int)$db->lastInsertRowID();
}

function canQueueEmail($db, string $to): array {
    if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Ongeldig e-mailadres: ' . $to];
    }
    $settings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    if (!$settings || (int)($settings['smtp_enabled'] ?? 0) !== 1) {
        return ['success' => false, 'message' => 'SMTP is niet ingeschakeld'];
    }
    if (empty($settings['smtp_host']) || empty($settings['smtp_username']) || empty($settings['smtp_password'])) {
        return ['success' => false, 'message' => 'SMTP configuratie is niet volledig'];
    }
    return ['success' => true, 'message' => 'ok'];
}

function queueEmailForSending($db, string $to, string $subject, string $body,
                              string $type = 'notification', string $targetName = ''): array {
    $check = canQueueEmail($db, $to);
    if (empty($check['success'])) {
        try {
            insertMailLogEntry($db, $type, $targetName, $to, $subject, 'failed', (string)($check['message'] ?? 'Mail validatie mislukt'), '', $body);
        } catch (\Exception $e) {}
        return ['success' => false, 'message' => (string)($check['message'] ?? 'Mail validatie mislukt')];
    }
    try {
        $mailLogId = insertMailLogEntry($db, $type, $targetName, $to, $subject, 'pending', 'In wachtrij voor verzending', '', $body);
        return ['success' => true, 'queued' => true, 'mail_log_id' => $mailLogId, 'message' => 'Mail in wachtrij geplaatst'];
    } catch (\Exception $e) {
        return ['success' => false, 'message' => 'Mail kon niet in wachtrij worden geplaatst'];
    }
}

function processPendingMailQueue($db, int $limit = 10): array {
    $processed = 0;
    $rows = [];
    $q = $db->query('SELECT id, type, target_name, email_to, subject, body FROM mail_log WHERE status="pending" ORDER BY id ASC LIMIT '.max(1, (int)$limit));
    while ($q && ($row = $q->fetchArray(SQLITE3_ASSOC))) {
        $rows[] = $row;
    }
    foreach ($rows as $row) {
        try {
            $lock = $db->prepare('UPDATE mail_log SET status="sending", message="Bezig met verzenden..." WHERE id=:id AND status="pending"');
            $lock->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER);
            $lock->execute();
            if ((int)$db->changes() < 1) {
                continue;
            }

            $debug = '';
            $res = sendEmail($db, (string)($row['email_to'] ?? ''), (string)($row['subject'] ?? ''), (string)($row['body'] ?? ''), $debug);
            $up = $db->prepare('UPDATE mail_log SET status=:st, message=:ms, debug_output=:dbg WHERE id=:id');
            $up->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER);
            $up->bindValue(':st', !empty($res['success']) ? 'success' : 'failed', SQLITE3_TEXT);
            $up->bindValue(':ms', (string)($res['message'] ?? ''), SQLITE3_TEXT);
            $up->bindValue(':dbg', (string)$debug, SQLITE3_TEXT);
            $up->execute();
            $processed++;
        } catch (\Exception $e) {
            try {
                $up = $db->prepare('UPDATE mail_log SET status="failed", message=:ms WHERE id=:id');
                $up->bindValue(':id', (int)($row['id'] ?? 0), SQLITE3_INTEGER);
                $up->bindValue(':ms', 'Queue verwerking mislukt: ' . $e->getMessage(), SQLITE3_TEXT);
                $up->execute();
            } catch (\Exception $inner) {}
        }
    }
    if ($processed > 0) {
        trimMailLog($db);
    }
    return ['processed' => $processed, 'queued' => count($rows)];
}

function logAndSendEmail($db, string $to, string $subject, string $body,
                          string $type = 'notification', string $targetName = '', bool $queue = true): array {
    if ($queue) {
        return queueEmailForSending($db, $to, $subject, $body, $type, $targetName);
    }

    $debug = '';
    $res = sendEmail($db, $to, $subject, $body, $debug);
    try {
        insertMailLogEntry($db, $type, $targetName, $to, $subject, $res['success'] ? 'success' : 'failed', (string)($res['message'] ?? ''), (string)$debug, $body);
    } catch (\Exception $e) { /* log mag nooit de applicatie crashen */ }
    return $res;
}

// Multi-recipient wrapper voor sessie/outage mails (index.php runtime)
function logAndSendEmailList($db, array $recipients, string $subject, string $body,
                             string $type = 'notification', string $targetName = ''): array {
    if (empty($recipients)) {
        try {
            insertMailLogEntry($db, $type, $targetName, '', $subject, 'failed', 'Geen geldige ontvangers geconfigureerd', '', $body);
        } catch (\Exception $e) {}
        return ['success' => false, 'message' => 'Geen geldige ontvangers geconfigureerd'];
    }

    $ok = 0;
    $fail = 0;
    $last = 'OK';
    foreach ($recipients as $to) {
        $res = logAndSendEmail($db, $to, $subject, $body, $type, $targetName);
        if (!empty($res['success'])) {
            $ok++;
        } else {
            $fail++;
            $last = (string)($res['message'] ?? 'onbekende fout');
        }
    }
    return ['success' => $ok > 0, 'message' => "success={$ok}, failed={$fail}, last={$last}"];
}

// RRD Management Functions
function getRRDFiles($db): array {
    $rrdFiles = [];
    $baseDir = SMOKEPING_DATA_DIR;
    if (!is_dir($baseDir)) return [];
    
    $categories = getCats($db);
    foreach ($categories as $cat) {
        $catPath = $baseDir . '/' . safeName($cat['name']);
        if (!is_dir($catPath)) continue;
        
        $targets = getTargetsForCat($db, $cat['id']);
        foreach ($targets as $tgt) {
            $rrdFile = $catPath . '/' . safeName($tgt['name']) . '.rrd';
            if (file_exists($rrdFile)) {
                $rrdFiles[] = [
                    'id' => $tgt['id'],
                    'category_id' => $cat['id'],
                    'category_name' => $cat['name'],
                    'category_display' => $cat['display_name'],
                    'target_name' => $tgt['name'],
                    'target_display' => $tgt['display_name'],
                    'path' => $rrdFile,
                    'size' => filesize($rrdFile),
                    'mtime' => filemtime($rrdFile),
                    'writable' => is_writable($rrdFile)
                ];
            }
        }
    }
    return $rrdFiles;
}

function getRRDFileForTarget($db, int $targetId): ?array {
    $s = $db->prepare('SELECT t.*,c.name as cat_name,c.display_name as cat_display FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.id=:id');
    $s->bindValue(':id', $targetId, SQLITE3_INTEGER);
    $target = $s->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$target) return null;
    
    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($target['cat_name']) . '/' . safeName($target['name']) . '.rrd';
    
    // Veiligheidschecks
    $realPath = realpath($rrdFile);
    if (!$realPath || strpos($realPath, SMOKEPING_DATA_DIR) !== 0) {
        return null; // Directory traversal attempt
    }
    
    if (!file_exists($rrdFile)) return null;
    
    return [
        'target_id' => $targetId,
        'category_name' => $target['cat_name'],
        'category_display' => $target['cat_display'],
        'target_name' => $target['name'],
        'target_display' => $target['display_name'],
        'host_ipv6' => (string)($target['host_ipv6'] ?? ''),
        'path' => $rrdFile,
        'real_path' => $realPath,
        'size' => filesize($rrdFile),
        'mtime' => filemtime($rrdFile),
        'writable' => is_writable($rrdFile)
    ];
}

function logRRDReset($db, string $username, string $catName, string $targetName, string $rrdFile, string $action, string $result, string $details = ''): void {
    $userIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $s = $db->prepare('INSERT INTO rrd_reset_logs (username,category_name,target_name,rrd_file,ip_address,action,result,details,created_at) 
                       VALUES(:u,:c,:t,:f,:ip,:a,:r,:d,CURRENT_TIMESTAMP)');
    $s->bindValue(':u', $username);
    $s->bindValue(':c', $catName);
    $s->bindValue(':t', $targetName);
    $s->bindValue(':f', $rrdFile);
    $s->bindValue(':ip', $userIp);
    $s->bindValue(':a', $action);
    $s->bindValue(':r', $result);
    $s->bindValue(':d', $details);
    $s->execute();
}

function resetTargetRRD($db, int $targetId, string $username): array {
    // Vind het RRD bestand
    $rrdInfo = getRRDFileForTarget($db, $targetId);
    if (!$rrdInfo) {
        return ['success' => false, 'message' => 'RRD bestand niet gevonden of ongeldig target ID'];
    }
    
    $rrdFile = $rrdInfo['real_path'];
    $catName = $rrdInfo['category_name'];
    $targetName = $rrdInfo['target_name'];

    // Create backup file
    $backupFile = $rrdFile . '.bak-' . date('Ymd-His');
    $backupCreated = @copy($rrdFile, $backupFile);
    
    // Stop SmokePing
    $stopCmd = 'sudo /usr/bin/systemctl stop smokeping 2>&1';
    $stopOutput = shell_exec($stopCmd);
    usleep(500000); // 500ms wacht voor gracefully shutdown
    
    // Delete RRD file via privileged helper first (works even when file is not writable for www-data).
    $safeCat = safeName($catName);
    $safeTarget = safeName($targetName);
    $deleteOutput = [];
    $deleteRc = 1;
    @exec('sudo -n /usr/local/bin/smokeping-clear-rrd target ' . escapeshellarg($safeCat) . ' ' . escapeshellarg($safeTarget) . ' 2>&1', $deleteOutput, $deleteRc);

    // Ook IPv6 companion RRD verwijderen als het target een IPv6 adres heeft.
    $hostIpv6 = trim((string)($rrdInfo['host_ipv6'] ?? ''));
    if ($hostIpv6 !== '') {
        $ipv6SafeCat = safeName($catName . '_IPv6');
        $ipv6SafeTarget = $safeTarget . '_v6';
        @exec('sudo -n /usr/local/bin/smokeping-clear-rrd target ' . escapeshellarg($ipv6SafeCat) . ' ' . escapeshellarg($ipv6SafeTarget) . ' 2>&1');
        // Legacy: IPv6 target in dezelfde categorie
        @exec('sudo -n /usr/local/bin/smokeping-clear-rrd target ' . escapeshellarg($safeCat) . ' ' . escapeshellarg($ipv6SafeTarget) . ' 2>&1');
    }

    if (file_exists($rrdFile) && !@unlink($rrdFile)) {
        $helperOut = trim(implode("\n", $deleteOutput));
        logRRDReset($db, $username, $catName, $targetName, $rrdFile, 'reset', 'failed', 'File deletion failed | helper_rc=' . $deleteRc . ' | helper_out=' . $helperOut);
        return ['success' => false, 'message' => 'RRD bestand kon niet worden verwijderd (rechtenprobleem). Controleer sudo helper en bestandsrechten.'];
    }
    
    // Start SmokePing
    $startCmd = 'sudo /usr/bin/systemctl start smokeping 2>&1';
    $startOutput = shell_exec($startCmd);
    sleep(2); // Wacht tot SmokePing is opgestart
    
    // Verify file is recreated
    $maxWait = 10;
    $waited = 0;
    while (!file_exists($rrdFile) && $waited < $maxWait) {
        usleep(500000);
        $waited += 0.5;
    }
    
    if (!file_exists($rrdFile)) {
        logRRDReset($db, $username, $catName, $targetName, $rrdFile, 'reset', 'failed', 'File not recreated after start');
        return ['success' => false, 'message' => 'RRD bestand is niet opnieuw aangemaakt'];
    }
    
    // Log success
    $detailsParts = [];
    if ($backupCreated) $detailsParts[] = 'Backup: ' . basename($backupFile);
    if ($deleteRc !== 0) $detailsParts[] = 'DelHelperRC: ' . $deleteRc;
    $stopOut = trim((string)$stopOutput);
    $startOut = trim((string)$startOutput);
    if ($stopOut !== '') $detailsParts[] = 'Stop: ' . $stopOut;
    if ($startOut !== '') $detailsParts[] = 'Start: ' . $startOut;
    $details = !empty($detailsParts) ? implode(' | ', $detailsParts) : 'Reset uitgevoerd';
    logRRDReset($db, $username, $catName, $targetName, $rrdFile, 'reset', 'success', $details);

    return ['success' => true, 'message' => 'Target RRD succesvol gereset' . ($backupCreated ? '' : ' (zonder backup: bestand niet leesbaar voor webgebruiker)'), 'backup' => ($backupCreated ? $backupFile : null)];
}

// Config generatie
function generateProbesConfig($db): string {
    $c = "*** Probes ***\n\n";
    $probes = getAllProbes($db);
    foreach ($probes as $p) {
        if (!$p['enabled']) continue;
        $c .= "+ {$p['name']}\n";
        $c .= "binary = {$p['binary_path']}\n";
        if (!empty($p['protocol'])) $c .= "protocol = {$p['protocol']}\n";
        if ($p['step']) $c .= "step = {$p['step']}\n";
        if ($p['pings']) $c .= "pings = {$p['pings']}\n";
        $extra = trim((string)($p['extra_config'] ?? ''));
        if (($p['name'] === 'FPing' || $p['name'] === 'FPing6') && stripos($extra, 'packetsize') === false) {
            $extra = trim($extra . "\npacketsize = 56");
        }
        if ($extra !== '') $c .= $extra . "\n";
        $c .= "\n";
    }
    return $c;
}

function generateTargetsConfig($db): string {
    $c = "# Auto-generated by SmokePing Manager v5.6\n# " . date('Y-m-d H:i:s') . "\n\n";
    $c .= "*** Targets ***\n\nprobe = FPing\nmenu = Top\ntitle = Netwerk Latency Monitor\nremark = Beheerd via SmokePing Manager\n\n";

    $catRows = [];
    $cats = $db->query('SELECT * FROM categories WHERE enabled=1 ORDER BY sort_order,name');
    while ($cat = $cats->fetchArray(SQLITE3_ASSOC)) {
        $catRows[] = $cat;
    }

    $existingCategoryNames = [];
    foreach ($catRows as $cat) {
        $existingCategoryNames[safeName($cat['name'])] = true;
    }

    $processedTargetsByCategory = [];
    $targetNamesByCategory = [];
    $dualStackIpv6Targets = [];
    $multiHosts = [];
    $addedTargets = [];

    // Pass 1: collect/sanitize all target data and build dual-stack maps.
    foreach ($catRows as $cat) {
        $cn = safeName($cat['name']);
        $processedTargetsByCategory[$cn] = [];
        $targetNamesByCategory[$cn] = [];

        $st = $db->prepare('SELECT * FROM targets WHERE category_id=:c AND enabled=1 ORDER BY sort_order,name');
        $st->bindValue(':c', $cat['id'], SQLITE3_INTEGER);
        $tgts = $st->execute();
        while ($t = $tgts->fetchArray(SQLITE3_ASSOC)) {
            $tn = safeName($t['name']);
            $menu = !empty($t['menu_name']) ? (string)$t['menu_name'] : (string)$t['display_name'];
            $display = (string)$t['display_name'];
            $remark = (string)($t['remark'] ?? '');
            $hostV4 = trim((string)($t['host'] ?? ''));
            $hostV6 = trim((string)($t['host_ipv6'] ?? ''));

            if (empty($hostV4) && empty($hostV6)) {
                error_log('WARNING: Target ' . $t['name'] . ' has no host addresses, skipping');
                continue;
            }
            if (!empty($hostV4) && (strpos($hostV4, '..') !== false || preg_match('/[`$;|&]/', $hostV4))) {
                error_log('WARNING: Target ' . $t['name'] . ' has invalid IPv4 host characters, skipping');
                $hostV4 = '';
            }
            if (!empty($hostV6) && (strpos($hostV6, '..') !== false || preg_match('/[`$;|&]/', $hostV6))) {
                error_log('WARNING: Target ' . $t['name'] . ' has invalid IPv6 host characters, skipping');
                $hostV6 = '';
            }

            $hasV4 = $hostV4 !== '';
            $hasV6 = $hostV6 !== '';
            if (!$hasV4 && !$hasV6) {
                error_log('WARNING: Target ' . $t['name'] . ' has no valid hosts after sanitization, skipping');
                continue;
            }

            $processedTargetsByCategory[$cn][] = [
                'tn' => $tn,
                'menu' => $menu,
                'display' => $display,
                'remark' => $remark,
                'probe' => (string)($t['probe'] ?? ''),
                'host_v4' => $hostV4,
                'host_v6' => $hostV6,
                'has_v4' => $hasV4,
                'has_v6' => $hasV6,
            ];
            $targetNamesByCategory[$cn][$tn] = true;

            if ($hasV4 && $hasV6) {
                $ipv6CatName = safeName((string)$cat['name'] . '_IPv6');
                $ipv6CatDisplay = (string)($cat['display_name'] ?: $cat['name']) . ' IPv6';
                if (!isset($dualStackIpv6Targets[$ipv6CatName])) {
                    $dualStackIpv6Targets[$ipv6CatName] = [
                        'display_name' => $ipv6CatDisplay,
                        'targets' => []
                    ];
                }
                $dualStackIpv6Targets[$ipv6CatName]['targets'][] = [
                    'tn' => $tn,
                    'menu' => $menu,
                    'display' => $display,
                    'host_v6' => $hostV6,
                    'remark' => $remark,
                ];

                $key = $cn . '/' . $tn;
                if (!isset($addedTargets[$key])) {
                    $multiHosts[] = [
                        'cat_v4' => $cn,
                        'cat_v6' => $ipv6CatName,
                        'name' => $display,
                        'v4' => $tn,
                        'v6' => $tn . '_v6',
                        'remark' => $remark,
                    ];
                    $addedTargets[$key] = true;
                }
            }
        }
    }

    // Pass 2: emit existing categories, including auto-generated IPv6 targets in already-existing companion categories.
    foreach ($catRows as $cat) {
        $cn = safeName($cat['name']);
        $c .= "+ {$cn}\nmenu = {$cat['display_name']}\ntitle = {$cat['display_name']}\n";
        if (!empty($cat['remark'])) $c .= "remark = {$cat['remark']}\n";
        $c .= "\n";

        foreach (($processedTargetsByCategory[$cn] ?? []) as $pt) {
            if ($pt['has_v4']) {
                $titleText = str_replace(["\r","\n","\t"], ' ', $pt['display']);
                $c .= "++ {$pt['tn']}\nmenu = {$pt['menu']}\ntitle = {$titleText}\n";
                if ($pt['probe'] !== '') $c .= "probe = {$pt['probe']}\n";
                $c .= "host = {$pt['host_v4']}\n";
                if ($pt['remark'] !== '') {
                    $remarkClean = str_replace(["\r","\n","\t"], ' ', $pt['remark']);
                    $c .= "remark = {$remarkClean}\n";
                }
                $c .= "\n";
            }

            if ($pt['has_v6'] && !$pt['has_v4']) {
                $titleTextV6Only = str_replace(["\r","\n","\t"], ' ', $pt['display']) . ' IPv6';
                $c .= "++ {$pt['tn']}\nmenu = {$pt['menu']} (IPv6)\ntitle = {$titleTextV6Only}\nprobe = FPing6\nhost = {$pt['host_v6']}\n";
                if ($pt['remark'] !== '') {
                    $remarkClean = str_replace(["\r","\n","\t"], ' ', $pt['remark']);
                    $c .= "remark = {$remarkClean}\n";
                }
                $c .= "\n";
            }
        }

        // If this companion IPv6 category already exists, append generated dual-stack IPv6 targets here (without creating a duplicate category block).
        if (isset($dualStackIpv6Targets[$cn])) {
            $seenV6Names = [];
            foreach (($dualStackIpv6Targets[$cn]['targets'] ?? []) as $v6t) {
                $v6Name = (string)$v6t['tn'] . '_v6';
                if (isset($targetNamesByCategory[$cn][$v6Name])) continue;
                if (isset($seenV6Names[$v6Name])) continue;
                $seenV6Names[$v6Name] = true;

                $v6Menu = str_replace(["\r","\n","\t"], ' ', (string)$v6t['menu']) . ' (IPv6)';
                $v6Title = str_replace(["\r","\n","\t"], ' ', (string)$v6t['display']) . ' IPv6';
                $c .= "++ {$v6Name}\nmenu = {$v6Menu}\ntitle = {$v6Title}\nprobe = FPing6\nhost = {$v6t['host_v6']}\n";
                $v6Remark = trim((string)($v6t['remark'] ?? ''));
                if ($v6Remark !== '') {
                    $v6Remark = str_replace(["\r","\n","\t"], ' ', $v6Remark);
                    $c .= "remark = {$v6Remark}\n";
                }
                $c .= "\n";
            }
            unset($dualStackIpv6Targets[$cn]);
        }
    }

    // Emit only missing companion IPv6 categories (avoid duplicates with already existing categories).
    foreach ($dualStackIpv6Targets as $ipv6CatName => $ipv6CatData) {
        if (isset($existingCategoryNames[$ipv6CatName])) continue;
        $ipv6Display = str_replace(["\r","\n","\t"], ' ', (string)$ipv6CatData['display_name']);
        $c .= "+ {$ipv6CatName}\nmenu = {$ipv6Display}\ntitle = {$ipv6Display}\n\n";

        $seenV6Names = [];
        foreach (($ipv6CatData['targets'] ?? []) as $v6t) {
            $v6Name = (string)$v6t['tn'] . '_v6';
            if (isset($seenV6Names[$v6Name])) continue;
            $seenV6Names[$v6Name] = true;

            $v6Menu = str_replace(["\r","\n","\t"], ' ', (string)$v6t['menu']) . ' (IPv6)';
            $v6Title = str_replace(["\r","\n","\t"], ' ', (string)$v6t['display']) . ' IPv6';
            $c .= "++ {$v6Name}\nmenu = {$v6Menu}\ntitle = {$v6Title}\nprobe = FPing6\nhost = {$v6t['host_v6']}\n";
            $v6Remark = trim((string)($v6t['remark'] ?? ''));
            if ($v6Remark !== '') {
                $v6Remark = str_replace(["\r","\n","\t"], ' ', $v6Remark);
                $c .= "remark = {$v6Remark}\n";
            }
            $c .= "\n";
        }
    }

    // MultiHost grafieken voor IPv4+IPv6 combinaties
    if (!empty($multiHosts)) {
        $c .= "+ Multihost_IPv4_IPv6\nmenu = IPv4 vs IPv6\ntitle = IPv4 vs IPv6 Vergelijking\n\n";
        $seenCombined = [];
        foreach ($multiHosts as $mh) {
            $baseName = safeName($mh['cat_v4'] . '_' . $mh['v4']);
            $key = $baseName . '_combined';
            if (isset($seenCombined[$key])) continue;
            $seenCombined[$key] = true;
            $display = str_replace(["\r","\n","\t"], ' ', (string)$mh['name']);

            // Combined MultiHost entry with both IPv4 and IPv6 references in one graph.
            $c .= "++ {$mh['v4']}_v4_v6\nmenu = {$mh['v4']}_v4_v6\ntitle = {$display} IPv6 (naast IPv4 in broncategorie)\n";
            $c .= "host = /{$mh['cat_v4']}/{$mh['v4']} /{$mh['cat_v6']}/{$mh['v6']}\n";
            $remarkCombined = trim((string)($mh['remark'] ?? ''));
            if ($remarkCombined !== '') {
                $remarkCombined = str_replace(["\r","\n","\t"], ' ', $remarkCombined);
                $c .= "remark = {$remarkCombined}\n";
            }
            $c .= "\n";
        }
    }

    $customGraphs = getCustomGraphs($db);
    if (!empty($customGraphs)) {
        $groupedGraphs = [];
        foreach ($customGraphs as $graph) {
            $groupName = trim((string)($graph['group_name'] ?? ''));
            if ($groupName === '') $groupName = 'Samengestelde grafieken';
            $groupKey = 'CustomGraphGroup_' . buildTargetInternalNameBase($groupName);
            if (!isset($groupedGraphs[$groupKey])) {
                $groupedGraphs[$groupKey] = ['label' => $groupName, 'graphs' => []];
            }
            $groupedGraphs[$groupKey]['graphs'][] = $graph;
        }
        foreach ($groupedGraphs as $groupKey => $groupData) {
            $groupLabel = str_replace(["\r","\n","\t"], ' ', (string)$groupData['label']);
            $c .= "+ {$groupKey}\nmenu = {$groupLabel}\ntitle = {$groupLabel}\n\n";
            foreach ($groupData['graphs'] as $graph) {
                $hostRefs = [];
                foreach (($graph['members'] ?? []) as $member) {
                    $catSafe = safeName((string)($member['cat_name'] ?? ''));
                    $targetSafe = safeName((string)($member['target_name'] ?? ''));
                    $mode = (string)($member['mode'] ?? 'ipv4');
                    $hasV4 = trim((string)($member['host'] ?? '')) !== '';
                    $hasV6 = trim((string)($member['host_ipv6'] ?? '')) !== '';
                    if (($mode === 'ipv4' || $mode === 'both') && $hasV4) $hostRefs[] = "/{$catSafe}/{$targetSafe}";
                    if (($mode === 'ipv6' || $mode === 'both') && $hasV6) {
                        $hostRefs[] = '/' . safeName((string)($member['cat_name'] ?? '') . '_IPv6') . '/' . $targetSafe . '_v6';
                    }
                }
                $hostRefs = array_values(array_unique($hostRefs));
                if (empty($hostRefs)) continue;
                $graphKey = 'custom_graph_' . buildTargetInternalNameBase((string)($graph['title'] ?? 'graph')) . '_' . (int)$graph['id'];
                $graphTitle = str_replace(["\r","\n","\t"], ' ', (string)($graph['title'] ?? 'Samengestelde grafiek'));
                $c .= "++ {$graphKey}\nmenu = {$graphTitle}\ntitle = {$graphTitle}\nhost = " . implode(' ', $hostRefs) . "\n";
                $c .= 'remark = Samengestelde grafiek met ' . count($hostRefs) . " pad(en)\n\n";
            }
        }
    }
    return $c;
}

function ensureRunDir(): void {
    // Ensure /run/smokeping exists - this is usually handled by systemd-tmpfiles
    // If it doesn't exist, create it with correct permissions
    $runtimeDir = '/run/smokeping';
    
    // Create if missing
    if (!is_dir($runtimeDir)) {
        @mkdir($runtimeDir, 0755, true);
        // Set permissions
        @chown($runtimeDir, 'smokeping');
        @chgrp($runtimeDir, 'smokeping');
        @chmod($runtimeDir, 0755);
    }
    
    // Ensure log dir exists
    $logDir = '/var/log/smokeping';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
        @chown($logDir, 'smokeping');
        @chgrp($logDir, 'smokeping');
        @chmod($logDir, 0755);
    }
    
    // Ensure data dir writable by smokeping
    if (is_dir(SMOKEPING_DATA_DIR)) {
        @chown(SMOKEPING_DATA_DIR, 'smokeping');
        @chgrp(SMOKEPING_DATA_DIR, 'smokeping');
        @chmod(SMOKEPING_DATA_DIR, 0755);
    }
}

function getSmokePingMainPid(): int {
    $statusOut = (string)@shell_exec('/usr/bin/sudo -n /usr/bin/systemctl status smokeping 2>&1');
    if (preg_match('/Main PID:\s*(\d+)/i', $statusOut, $m)) {
        return (int)$m[1];
    }
    return 0;
}

function getSmokePingActiveStatus(): string {
    $statusOut = (string)@shell_exec('/usr/bin/sudo -n /usr/bin/systemctl status smokeping 2>&1');
    if (stripos($statusOut, 'Active: active') !== false) return 'active';
    if (stripos($statusOut, 'inactive') !== false) return 'inactive';
    if (stripos($statusOut, 'failed') !== false) return 'failed';
    if (stripos($statusOut, 'not found') !== false) return 'not-found';
    return trim($statusOut) !== '' ? 'unknown' : '';
}

function getLatestRrdMtimeTs(): int {
    static $cacheTs = 0;
    static $cacheAt = 0;
    $now = time();
    if (($now - $cacheAt) < 30) {
        return $cacheTs;
    }

    $dir = escapeshellarg(SMOKEPING_DATA_DIR);
    $cmd = '/usr/bin/find ' . $dir . ' -type f -name "*.rrd" -printf "%T@\\n" 2>/dev/null | /usr/bin/sort -nr | /usr/bin/head -n 1';
    $out = trim((string)@shell_exec($cmd));
    $ts = 0;
    if ($out !== '') {
        $ts = (int)floor((float)$out);
    }
    $cacheTs = $ts;
    $cacheAt = $now;
    return $ts;
}

function autoRecoverSmokePingStaleData($db): array {
    if (getSetting($db, 'smokeping_stale_autorecover', '1') !== '1') {
        return ['checked' => false, 'reason' => 'disabled'];
    }

    $now = time();
    $lastCheck = (int)getSetting($db, 'perf_last_stale_rrd_check', '0');
    if (($now - $lastCheck) < 60) {
        return ['checked' => false, 'reason' => 'throttled'];
    }
    setSetting($db, 'perf_last_stale_rrd_check', (string)$now);

    $latestTs = getLatestRrdMtimeTs();
    if ($latestTs <= 0) {
        return ['checked' => true, 'stale' => false, 'reason' => 'no_rrd'];
    }

    $probeStep = (int)$db->querySingle('SELECT MAX(step) FROM probes WHERE enabled=1');
    if ($probeStep <= 0) $probeStep = (int)$db->querySingle('SELECT MAX(step) FROM probes');
    if ($probeStep <= 0) $probeStep = 60;

    $staleThreshold = max(180, $probeStep * 6);
    $lagSec = max(0, $now - $latestTs);
    setSetting($db, 'perf_last_rrd_lag_sec', (string)$lagSec);

    if ($lagSec < $staleThreshold) {
        return ['checked' => true, 'stale' => false, 'lag_sec' => $lagSec, 'threshold_sec' => $staleThreshold];
    }

    $lastRestart = (int)getSetting($db, 'perf_last_stale_rrd_restart', '0');
    $restartCooldown = 900;
    if (($now - $lastRestart) < $restartCooldown) {
        return ['checked' => true, 'stale' => true, 'restarted' => false, 'lag_sec' => $lagSec, 'threshold_sec' => $staleThreshold, 'reason' => 'cooldown'];
    }

    $restartRes = doRestart();
    setSetting($db, 'perf_last_stale_rrd_restart', (string)$now);
    setSetting($db, 'perf_last_stale_rrd_result', (string)($restartRes['msg'] ?? ''));
    logActivity($db, 'smokeping_auto_recover', 'Stale RRD gedetecteerd (lag=' . $lagSec . 's, threshold=' . $staleThreshold . 's). Auto-restart: ' . (($restartRes['success'] ?? false) ? 'ok' : 'failed'));

    return [
        'checked' => true,
        'stale' => true,
        'restarted' => true,
        'success' => (bool)($restartRes['success'] ?? false),
        'lag_sec' => $lagSec,
        'threshold_sec' => $staleThreshold,
        'message' => (string)($restartRes['msg'] ?? ''),
    ];
}

function writeAllConfig($db): array {
    // Keep previous files so we can rollback if syntax check fails.
    $oldProbes = @file_get_contents(SMOKEPING_PROBES_FILE);
    $oldTargets = @file_get_contents(SMOKEPING_TARGETS_FILE);

    // Probes
    $pc = generateProbesConfig($db);
    if (@file_put_contents(SMOKEPING_PROBES_FILE, $pc) === false)
        return ['success'=>false,'msg'=>'Kan Probes niet schrijven. Check bestandspermissies in ' . SMOKEPING_CONF_DIR];
    
    // Targets
    $tc = generateTargetsConfig($db);
    if (@file_put_contents(SMOKEPING_TARGETS_FILE, $tc) === false)
        return ['success'=>false,'msg'=>'Kan Targets niet schrijven. Check bestandspermissies in ' . SMOKEPING_CONF_DIR];

    // Ensure directories exist
    ensureRunDir();
    sleep(1);
    
    // Test SmokePing config syntax
    $testOut = @shell_exec('/usr/bin/sudo -n /usr/bin/smokeping --check 2>&1');
    if ($testOut && (strpos($testOut, 'ERROR') !== false || strpos(strtolower($testOut), 'error') !== false)) {
        // Ignore "does not exist" directory errors - we'll try to fix those
        if (strpos($testOut, 'does not exist') === false) {
            if ($oldProbes !== false) @file_put_contents(SMOKEPING_PROBES_FILE, $oldProbes);
            if ($oldTargets !== false) @file_put_contents(SMOKEPING_TARGETS_FILE, $oldTargets);
            return ['success'=>false,'msg'=>'SmokePing config syntax fout: ' . htmlspecialchars(substr($testOut, 0, 300))];
        }
    }
    
    // Prefer reload so multiple batched changes do not force a restart when not needed.
    $beforePid = getSmokePingMainPid();
    $reloadOut = @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl reload smokeping 2>&1');
    sleep(2);
    $status = getSmokePingActiveStatus();
    $afterPid = getSmokePingMainPid();
    if ($status === 'active') {
        return ['success'=>true,'msg'=>'✅ Config opgeslagen & SmokePing reload uitgevoerd (PID '.$afterPid.').'];
    }

    $restartOut = @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl restart smokeping 2>&1');
    sleep(3);
    $status = getSmokePingActiveStatus();
    $afterPid = getSmokePingMainPid();
    if ($status === 'active') {
        return ['success'=>true,'msg'=>'✅ Config opgeslagen & SmokePing herstart uitgevoerd (PID '.$afterPid.').'];
    }

    // Fallback: force stop/start via systemd
    $fallbackOut = @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl stop smokeping 2>&1; /usr/bin/sudo -n /usr/bin/systemctl start smokeping 2>&1');
    sleep(3);
    $status2 = getSmokePingActiveStatus();
    $afterPid2 = getSmokePingMainPid();
    if ($status2 === 'active') {
        return ['success'=>true,'msg'=>'✅ Config opgeslagen & SmokePing is actief (fallback, PID '.$afterPid2.').'];
    }

    // Auto-heal: align probe step with existing RRD history when mismatch is detected.
    $errCombined = trim((string)$reloadOut . "\n" . (string)$restartOut . "\n" . (string)$fallbackOut);
    if (preg_match('/Wrong value of step:\s+.+\s+has\s+(\d+),\s+create string has\s+(\d+)/i', $errCombined, $mm)) {
        $rrdStep = (int)$mm[1];
        if ($rrdStep > 0) {
            $upd = $db->prepare('UPDATE probes SET step=:st WHERE name IN ("FPing","FPing6")');
            $upd->bindValue(':st', $rrdStep, SQLITE3_INTEGER);
            $upd->execute();
            $pc2 = generateProbesConfig($db);
            @file_put_contents(SMOKEPING_PROBES_FILE, $pc2);
            ensureRunDir();
            @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl restart smokeping 2>&1');
            sleep(3);
            $status3 = getSmokePingActiveStatus();
            $afterPid3 = getSmokePingMainPid();
            if ($status3 === 'active') {
                return ['success'=>true,'msg'=>'✅ Config opgeslagen. RRD step mismatch auto-gehersteld (step='.$rrdStep.'). SmokePing is actief (PID '.$afterPid3.').'];
            }
        }
    }

    // Config saved but runtime is down: report failure so UI does not show false success.
    $err = trim((string)$reloadOut);
    if ($err === '') $err = trim((string)$restartOut);
    if ($err === '') $err = trim((string)$fallbackOut);
    if ($err === '') $err = 'Service is mogelijk inactief.';
    return ['success'=>false,'msg'=>'❌ Config opgeslagen maar SmokePing is niet actief (status: '.($status ?: $status2 ?: 'onbekend').'). Detail: '.substr($err,0,260)];
}

function doRestart(): array {
    ensureRunDir();
    sleep(1);
    
    $beforePid = getSmokePingMainPid();
    $restartOut = @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl restart smokeping 2>&1');
    sleep(3);
    $status = getSmokePingActiveStatus();
    $afterPid = getSmokePingMainPid();
    if ($status === 'active' && $afterPid > 0 && ($beforePid === 0 || $afterPid !== $beforePid)) {
        return ['success'=>true,'msg'=>'✅ SmokePing succesvol herstart (PID '.$afterPid.').'];
    }

    $fallbackOut = @shell_exec('/usr/bin/sudo -n /usr/bin/systemctl stop smokeping 2>&1; /usr/bin/sudo -n /usr/bin/systemctl start smokeping 2>&1');
    sleep(3);
    $status2 = getSmokePingActiveStatus();
    $afterPid2 = getSmokePingMainPid();
    if ($status2 === 'active' && $afterPid2 > 0 && ($beforePid === 0 || $afterPid2 !== $beforePid)) {
        return ['success'=>true,'msg'=>'✅ SmokePing herstart via fallback (PID '.$afterPid2.').'];
    }

    $err = trim((string)$restartOut);
    if ($err === '') $err = trim((string)$fallbackOut);
    if ($err === '') $err = 'Service blijft inactief.';
    return ['success'=>false,'msg'=>'❌ SmokePing restart mislukt: '.substr($err,0,220).' | status='.$status.', pid_before='.$beforePid.', pid_after='.$afterPid.', pid_after_fallback='.$afterPid2];
}

// DNS/Reachability Validation Helpers (lightweight)
function targetsBackupDir(): string {
    return rtrim(BACKUP_DIR, '/').'/targets_files';
}

function targetsBackupVersionMarker(): string {
    return targetsBackupDir() . '/.targets_backups_version';
}

function touchTargetsBackupVersionMarker(): void {
    $marker = targetsBackupVersionMarker();
    $dir = dirname($marker);
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) return;
    @file_put_contents($marker, (string)time(), LOCK_EX);
}

function isConfigBackupFileName(string $name): bool {
    return (bool)preg_match('/\.(?:wipe_backup_\d+|uploaded_backup_\d+|backup(?:_\d+)?|bak(?:\.\d+)?|orig|old)$/i', $name);
}

function getConfigBaseNameFromBackup(string $backupName): string {
    $base = preg_replace('/\.(?:wipe_backup_\d+|uploaded_backup_\d+|backup(?:_\d+)?|bak(?:\.\d+)?|orig|old)$/i', '', $backupName);
    return $base !== '' ? $base : $backupName;
}

function getConfigBackupTypeLabel(string $backupName): string {
    if (preg_match('/\.wipe_backup_\d+$/i', $backupName)) return 'Wipe backup';
    if (preg_match('/\.uploaded_backup_\d+$/i', $backupName)) return 'Upload backup';
    if (preg_match('/\.backup(?:_\d+)?$/i', $backupName)) return 'Backup';
    if (preg_match('/\.bak(?:\.\d+)?$/i', $backupName)) return 'BAK';
    if (preg_match('/\.orig$/i', $backupName)) return 'Orig';
    if (preg_match('/\.old$/i', $backupName)) return 'Oud';
    return 'Overig';
}

function getTargetsBackupTypeLabel(string $backupName): string {
    if (strpos($backupName, '_manual.') !== false) return 'Handmatig';
    if (strpos($backupName, '_uploaded_restore') !== false) return 'Upload + herstel';
    if (strpos($backupName, '_uploaded') !== false) return 'Upload';
    if (strpos($backupName, '_autosave') !== false) return 'Autosave';
    if (strpos($backupName, '_restore') !== false) return 'Herstel';
    if (strpos($backupName, '_before_') !== false) return 'Voor herstel';
    return 'Backup';
}

function listEditableConfigFiles(): array {
    $key = 'fs:listEditableConfigFiles:' . smPathVersion(SMOKEPING_CONF_DIR);
    return smCacheRemember($key, 600, static function (): array {
        $all = glob(SMOKEPING_CONF_DIR.'/*') ?: [];
        $files = [];
        foreach ($all as $path) {
            if (!is_file($path)) continue;
            $bn = basename($path);
            if (isConfigBackupFileName($bn)) continue;
            $files[] = $bn;
        }
        sort($files, SORT_STRING);
        return $files;
    }, static fn($value): bool => is_array($value));
}

function listConfigBackupFiles(): array {
    $key = 'fs:listConfigBackupFiles:' . smPathVersion(SMOKEPING_CONF_DIR);
    return smCacheRemember($key, 600, static function (): array {
        $all = glob(SMOKEPING_CONF_DIR.'/*') ?: [];
        $files = [];
        foreach ($all as $path) {
            if (!is_file($path)) continue;
            $bn = basename($path);
            if (!isConfigBackupFileName($bn)) continue;
            $files[] = $bn;
        }
        rsort($files, SORT_STRING);
        return $files;
    }, static fn($value): bool => is_array($value));
}

function removeDirectoryRecursive(string $path): bool {
    if (!is_dir($path)) return @unlink($path);
    $items = scandir($path);
    if ($items === false) return false;
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $full = $path . '/' . $item;
        if (is_dir($full)) {
            if (!removeDirectoryRecursive($full)) return false;
        } else {
            if (!@unlink($full)) return false;
        }
    }
    return @rmdir($path);
}

function createFullBackup(string $reason = 'manual'): array {
    $safeReason = preg_replace('/[^a-z0-9_]+/i', '_', strtolower(trim($reason)));
    $suffix = $safeReason !== '' ? '_' . trim($safeReason, '_') : '';
    $name = 'backup_' . date('Ymd_His') . $suffix;
    $dir = BACKUP_DIR . '/' . $name;
    if (!@mkdir($dir, 0750, true) && !is_dir($dir)) {
        return ['success' => false, 'msg' => 'Kon backup directory niet aanmaken.'];
    }
    foreach (glob(SMOKEPING_CONF_DIR . '/*') ?: [] as $file) {
        if (is_file($file)) @copy($file, $dir . '/' . basename($file));
    }
    if (file_exists(DB_PATH)) @copy(DB_PATH, $dir . '/smokeping_manager.db');
    @exec('tar czf ' . escapeshellarg($dir . '/rrd_data.tar.gz') . ' -C ' . escapeshellarg(SMOKEPING_DATA_DIR) . ' . 2>/dev/null');
    return ['success' => true, 'msg' => 'Backup gemaakt: ' . $name, 'name' => $name, 'dir' => $dir];
}

function getAutoBackupSettings($db): array {
    return [
        'enabled' => getSetting($db, 'auto_backup_enabled', '0') === '1',
        'frequency' => getSetting($db, 'auto_backup_frequency', 'daily'),
        'keep_latest' => max(1, (int)getSetting($db, 'auto_backup_keep_latest', '10')),
        'retain_daily' => max(0, (int)getSetting($db, 'auto_backup_retain_daily', '14')),
        'retain_weekly' => max(0, (int)getSetting($db, 'auto_backup_retain_weekly', '8')),
        'retain_monthly' => max(0, (int)getSetting($db, 'auto_backup_retain_monthly', '6')),
        'last_period_key' => getSetting($db, 'auto_backup_last_period_key', ''),
        'last_run_at' => getSetting($db, 'auto_backup_last_run_at', ''),
        'last_result' => getSetting($db, 'auto_backup_last_result', ''),
    ];
}

function autoBackupPeriodKey(string $frequency, ?int $ts = null): string {
    $ts = $ts ?? time();
    if ($frequency === 'weekly') return date('o-\\WW', $ts);
    if ($frequency === 'monthly') return date('Y-m', $ts);
    return date('Y-m-d', $ts);
}

function listAutoFullBackupDirs(): array {
    $key = 'fs:listAutoFullBackupDirs:' . smPathVersion(BACKUP_DIR);
    return smCacheRemember($key, 300, static function (): array {
        $dirs = [];
        foreach (glob(BACKUP_DIR . '/backup_*_auto_*') ?: [] as $dir) {
            if (!is_dir($dir)) continue;
            $dirs[] = ['path' => $dir, 'name' => basename($dir), 'mtime' => (int)@filemtime($dir)];
        }
        usort($dirs, static function ($a, $b) {
            return ($b['mtime'] <=> $a['mtime']);
        });
        return $dirs;
    }, static fn($value): bool => is_array($value));
}

function pruneAutoFullBackups(array $cfg): array {
    $dirs = listAutoFullBackupDirs();
    if (empty($dirs)) return ['removed' => 0, 'kept' => 0];

    $keep = [];
    $weeklyBuckets = [];
    $monthlyBuckets = [];
    $now = time();
    $latestCount = max(1, (int)$cfg['keep_latest']);
    $dailyWindow = max(0, (int)$cfg['retain_daily']);
    $weeklyWindow = max(0, (int)$cfg['retain_weekly']);
    $monthlyWindow = max(0, (int)$cfg['retain_monthly']);

    foreach ($dirs as $index => $dir) {
        $name = $dir['name'];
        $mtime = (int)$dir['mtime'];
        $ageDays = (int)floor(max(0, $now - $mtime) / 86400);
        if ($index < $latestCount) {
            $keep[$name] = true;
            continue;
        }
        if ($dailyWindow > 0 && $ageDays <= $dailyWindow) {
            $keep[$name] = true;
            continue;
        }
        if ($weeklyWindow > 0 && $ageDays <= ($weeklyWindow * 7)) {
            $bucket = date('o-W', $mtime);
            if (!isset($weeklyBuckets[$bucket])) {
                $weeklyBuckets[$bucket] = $name;
                $keep[$name] = true;
            }
            continue;
        }
        if ($monthlyWindow > 0 && $ageDays <= ($monthlyWindow * 31)) {
            $bucket = date('Y-m', $mtime);
            if (!isset($monthlyBuckets[$bucket])) {
                $monthlyBuckets[$bucket] = $name;
                $keep[$name] = true;
            }
        }
    }

    $removed = 0;
    foreach ($dirs as $dir) {
        if (isset($keep[$dir['name']])) continue;
        if (removeDirectoryRecursive($dir['path'])) $removed++;
    }
    return ['removed' => $removed, 'kept' => count($keep)];
}

function runAutoBackupIfDue($db, bool $logActivity = false): array {
    $cfg = getAutoBackupSettings($db);
    if (!$cfg['enabled']) return ['success' => false, 'msg' => 'Automatische backups zijn uitgeschakeld.', 'skipped' => true];
    $frequency = in_array($cfg['frequency'], ['daily', 'weekly', 'monthly'], true) ? $cfg['frequency'] : 'daily';
    $periodKey = autoBackupPeriodKey($frequency);
    if ($cfg['last_period_key'] === $periodKey) {
        return ['success' => true, 'msg' => 'Automatische backup voor deze periode bestaat al.', 'skipped' => true];
    }

    $backup = createFullBackup('auto_' . $frequency);
    if (!$backup['success']) {
        setSetting($db, 'auto_backup_last_result', $backup['msg']);
        return $backup;
    }

    setSetting($db, 'auto_backup_last_period_key', $periodKey);
    setSetting($db, 'auto_backup_last_run_at', date('Y-m-d H:i:s'));
    $prune = pruneAutoFullBackups($cfg);
    $msg = $backup['msg'] . ' Automatisch schema: ' . $frequency . '. Opruimen verwijderd ' . (int)$prune['removed'] . ' oude auto-backups.';
    setSetting($db, 'auto_backup_last_result', $msg);
    if ($logActivity && function_exists('logActivity')) {
        logActivity($db, 'auto_backup', $msg);
    }
    return ['success' => true, 'msg' => $msg, 'name' => $backup['name']];
}

function buildDatabaseConfigContent(int $step, int $pings): string {
    $step = max(10, min(3600, $step));
    $pings = max(1, min(100, $pings));
    return "*** Database ***\n"
        . "step     = {$step}\n"
        . "pings    = {$pings}\n"
        . "# consfn mrhb steps total\n"
        . "AVERAGE  0.5   1  28800\n"
        . "AVERAGE  0.5  12   9600\n"
        . "    MIN  0.5  12   9600\n"
        . "    MAX  0.5  12   9600\n"
        . "AVERAGE  0.5 144   2400\n"
        . "    MAX  0.5 144   2400\n"
        . "    MIN  0.5 144   2400\n";
}

function applyDatabaseConfig(int $step, int $pings, $db = null): array {
    $dbFile = SMOKEPING_CONF_DIR . '/Database';
    $content = buildDatabaseConfigContent($step, $pings);
    if (@file_put_contents($dbFile, $content) === false) {
        return ['success' => false, 'msg' => 'Kon Database config niet schrijven.'];
    }
    @chmod($dbFile, 0664);

    // Also sync step and pings in Probes so runtime behavior matches the wizard choice.
    $probesSynced = false;
    if ($db !== null) {
        $upd = $db->prepare('UPDATE probes SET step=:st, pings=:pg WHERE name IN ("FPing","FPing6")');
        if ($upd !== false) {
            $upd->bindValue(':st', $step, SQLITE3_INTEGER);
            $upd->bindValue(':pg', $pings, SQLITE3_INTEGER);
            $upd->execute();
            $pc = generateProbesConfig($db);
            if (@file_put_contents(SMOKEPING_PROBES_FILE, $pc) !== false) {
                @chmod(SMOKEPING_PROBES_FILE, 0664);
                $probesSynced = true;
            }
        }
    }

    // Fallback for older schemas/migrations: patch existing Probes file directly.
    if (!$probesSynced && is_file(SMOKEPING_PROBES_FILE)) {
        $existingProbes = (string)@file_get_contents(SMOKEPING_PROBES_FILE);
        if ($existingProbes !== '') {
            $updatedProbes = preg_replace_callback(
                '/(^\+\s+FPing6?\s*\R)(.*?)(?=^\+\s|\z)/ms',
                static function(array $m) use ($step, $pings): string {
                    $header = $m[1];
                    $body = (string)$m[2];
                    $body = preg_replace('/^\s*(step|pings)\s*=.*\R?/mi', '', $body);
                    $body = ltrim((string)$body, "\r\n");
                    return $header . "step = {$step}\n" . "pings = {$pings}\n" . $body;
                },
                $existingProbes,
                -1,
                $probeSectionsChanged
            );
            if ((int)$probeSectionsChanged > 0 && is_string($updatedProbes)) {
                @file_put_contents(SMOKEPING_PROBES_FILE, $updatedProbes);
                @chmod(SMOKEPING_PROBES_FILE, 0664);
            }
        }
    }

    return ['success' => true, 'msg' => 'Database config bijgewerkt (step=' . $step . ', pings=' . $pings . ').'];
}

function parsePresentationRanges(string $raw): array {
    $rows = preg_split('/\r\n|\r|\n/', trim($raw));
    $items = [];
    foreach ($rows as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        $parts = explode('|', $line, 2);
        if (count($parts) !== 2) continue;
        $label = trim($parts[0], " \t\"'");
        $range = strtolower(trim($parts[1]));
        if ($label === '') continue;
        if (!preg_match('/^[0-9]+[smhdwmy]$/', $range)) continue;
        $items[] = ['label' => $label, 'range' => $range];
    }
    return $items;
}

function applyPresentationRanges(string $rawRanges): array {
    $presFile = SMOKEPING_CONF_DIR . '/Presentation';
    if (!is_file($presFile)) return ['success' => false, 'msg' => 'Presentation bestand niet gevonden.'];

    $items = parsePresentationRanges($rawRanges);
    if (empty($items)) return ['success' => false, 'msg' => 'Geen geldige Presentation ranges opgegeven. Gebruik: Label|waarde (bijv. Last 1 Hour|1h).'];

    $lines = [];
    foreach ($items as $it) {
        $safeLabel = str_replace('"', '', $it['label']);
        $lines[] = '"' . $safeLabel . '"    ' . $it['range'];
    }
    $newBlock = implode("\n", $lines);

    $current = (string)@file_get_contents($presFile);
    if ($current === '') return ['success' => false, 'msg' => 'Kon Presentation bestand niet lezen.'];

    $pattern = '/(^\s*"[^"\n]+"\s+[0-9]+[smhdwmy]\s*\R)+/mi';
    if (preg_match($pattern, $current)) {
        $updated = preg_replace($pattern, $newBlock . "\n", $current, 1);
    } else {
        $updated = rtrim($current) . "\n\n# Custom chart ranges\n" . $newBlock . "\n";
    }

    if (@file_put_contents($presFile, $updated) === false) {
        return ['success' => false, 'msg' => 'Kon Presentation config niet schrijven.'];
    }
    @chmod($presFile, 0664);
    return ['success' => true, 'msg' => 'Presentation ranges bijgewerkt (' . count($items) . ' regels).'];
}

function clearAllRrdData(): array {
    $out = [];
    $rc = 0;
    @exec('sudo -n /usr/local/bin/smokeping-clear-rrd all 2>&1', $out, $rc);
    if ($rc !== 0) {
        $detail = trim(implode(' | ', $out));
        if ($detail === '') $detail = 'onbekende fout';
        return ['success' => false, 'msg' => 'Kon bestaande grafiekdata niet verwijderen: ' . substr($detail, 0, 220)];
    }
    return ['success' => true, 'msg' => 'Bestaande grafiekdata verwijderd zodat de nieuwe grafiekinstellingen direct gelden.'];
}

function getDashboardOverviewData(SQLite3 $db): array {
    $categoryCount = (int)$db->querySingle('SELECT COUNT(*) FROM categories');
    $targetCount = (int)$db->querySingle('SELECT COUNT(*) FROM targets');
    $activeTargetCount = (int)$db->querySingle('SELECT COUNT(*) FROM targets WHERE enabled=1');
    $inactiveTargetCount = max(0, $targetCount - $activeTargetCount);
    $probeCount = (int)$db->querySingle('SELECT COUNT(*) FROM probes WHERE enabled=1');
    $alertCount = (int)$db->querySingle('SELECT COUNT(*) FROM alerts WHERE enabled=1');
    $userCount = (int)$db->querySingle('SELECT COUNT(*) FROM users');
    $openOutageCount = (int)$db->querySingle('SELECT COUNT(*) FROM target_outages WHERE is_open=1');
    $mailLogCount = (int)$db->querySingle('SELECT COUNT(*) FROM mail_log');
    $configFileCount = count(listEditableConfigFiles());
    $configBackupCount = count(listConfigBackupFiles());
    $targetsBackupCount = count(listTargetsFileBackups());
    $fullBackupCount = 0;
    foreach (glob(BACKUP_DIR.'/backup_*') ?: [] as $dir) {
        if (is_dir($dir)) $fullBackupCount++;
    }
    $roleLabel = isAdmin($db) ? 'Admin' : (isReadOnly($db) ? 'Alleen-lezen gebruiker' : 'Manager');

    return [
        'stats' => [
            ['label' => 'Categorieen', 'value' => $categoryCount],
            ['label' => 'Targets', 'value' => $targetCount],
            ['label' => 'Actief', 'value' => $activeTargetCount],
            ['label' => 'Open uitval', 'value' => $openOutageCount],
            ['label' => 'Backups', 'value' => $fullBackupCount + $targetsBackupCount + $configBackupCount],
            ['label' => 'Gebruikers', 'value' => $userCount],
        ],
        'sections' => [
            [
                'title' => 'Targets en monitoring',
                'summary' => 'Beheer alle meetdoelen vanuit een centrale lijst met live tellingen en snelle acties.',
                'items' => [
                    $categoryCount.' categorieen en '.$targetCount.' targets zijn direct beschikbaar, waarvan '.$activeTargetCount.' actief en '.$inactiveTargetCount.' inactief.',
                    'Targets ondersteunt kolomsortering op Groep, Klantnummer, Target, Host, Probe en Status.',
                    'Beschikbare acties: toevoegen, bewerken, klonen, bulk verwijderen en grafiekdata wissen.',
                    'Targets kunnen handmatig of via een bestaand Targets bestand worden geimporteerd.',
                ],
                'links' => [
                    ['href' => '?p=targets&tab=targets', 'label' => 'Open Targets'],
                ],
            ],
            [
                'title' => 'Configuratie en backups',
                'summary' => 'Configuratiebestanden, targetbackups en volledige applicatiebackups zijn samengebracht op een plek.',
                'items' => [
                    $configFileCount.' configuratiebestanden zijn bewerkbaar zonder dat backupbestanden door de editorlijst lopen.',
                    $targetsBackupCount.' targets back-ups, '.$configBackupCount.' configuratie back-ups en '.$fullBackupCount.' volledige back-ups zijn beschikbaar vanuit Instellingen > Backups.',
                    'Uploaden, downloaden, herstellen en verwijderen van backups gebeurt vanuit dezelfde beheerpagina.',
                    'Rebuild & Restart en Restart SmokePing staan vast in de zijbalk voor snelle wijzigingen aan de live configuratie.',
                ],
                'links' => array_merge(
                    [['href' => '?p=settings&stab=configuratie', 'label' => 'Open Configuratie']],
                    isAdmin($db) ? [['href' => '?p=settings&stab=backups', 'label' => 'Open Backups']] : []
                ),
            ],
            [
                'title' => 'Meldingen en logging',
                'summary' => 'De tool houdt gebeurtenissen en notificaties centraal bij zodat storingen en wijzigingen traceerbaar blijven.',
                'items' => [
                    'De infobox links toont de laatste 100 systeemmeldingen met datum, tijd en type.',
                    $mailLogCount.' mail-logregels zijn beschikbaar in het e-mailgedeelte voor testmails en aflevercontrole.',
                    'Uitvaltracking en notificatieverwerking blijven actief, ook zonder aparte statuspagina.',
                    'RRD reset logs en notificatiestatus per target helpen bij diagnose en terugzoeken van wijzigingen.',
                ],
                'links' => [
                    ['href' => '?p=settings&stab=beheer', 'label' => 'Open Beheer'],
                ],
            ],
            [
                'title' => 'Platform en rechten',
                'summary' => 'Installatie, permissies en toegangsrechten zijn ingericht voor dagelijks beheer zonder handmatig shellwerk.',
                'items' => [
                    'Je bent nu ingelogd als '.$roleLabel.'. Rechten bepalen of je alleen kunt kijken of ook kunt wijzigen.',
                    $probeCount.' probes en '.$alertCount.' actieve alerts zijn momenteel geconfigureerd.',
                    'De installer controleert en herstelt automatisch SmokePing-mappen, logpaden en schrijfrechten tijdens install/update/deploy.',
                    isAdmin($db) ? 'Admins hebben daarnaast toegang tot Admin Debug en gebruikersbeheer.' : 'Adminfuncties zoals gebruikersbeheer en debug zijn alleen zichtbaar voor admins.',
                ],
                'links' => [
                    ['href' => '?p=settings&stab=instellingen', 'label' => 'Open Instellingen'],
                    ['href' => '?p=admin', 'label' => 'Open Admin Debug'],
                ],
            ],
        ],
    ];
}

function getDashboardOverviewDataCached(SQLite3 $db, int $ttlSec = 45): array {
    $role = isAdmin($db) ? 'admin' : (isReadOnly($db) ? 'readonly' : 'manager');
    $key = 'dash_overview:' . $role . ':' . smDbCacheVersion() . ':' . smPathVersion([SMOKEPING_CONF_DIR, BACKUP_DIR, targetsBackupDir()]);
    $cached = null;
    if (smCacheGet($key, $ttlSec, $cached) && is_array($cached)) {
        return $cached;
    }
    smCacheMiss();
    $data = getDashboardOverviewData($db);
    smCacheSet($key, $data, $ttlSec);
    return $data;
}

function listTargetsFileBackups(): array {
    $dir = targetsBackupDir();
    $key = 'fs:listTargetsFileBackups:' . smPathVersion(targetsBackupVersionMarker());
    return smCacheRemember($key, 600, static function () use ($dir): array {
        if (!is_dir($dir)) return [];
        $files = glob($dir.'/targets_*.conf') ?: [];
        rsort($files, SORT_STRING);
        return array_map('basename', $files);
    }, static fn($value): bool => is_array($value));
}

function backupTargetsFileSnapshot(string $reason = 'manual'): array {
    if (!file_exists(SMOKEPING_TARGETS_FILE)) {
        return ['success'=>false,'msg'=>'Targets bestand niet gevonden.'];
    }
    $dir = targetsBackupDir();
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return ['success'=>false,'msg'=>'Kan backup map voor targets niet aanmaken.'];
    }
    $safeReason = preg_replace('/[^a-zA-Z0-9_-]/', '_', $reason);
    $fileName = 'targets_'.date('Ymd_His').'_'.($safeReason ?: 'manual').'.conf';
    $dest = $dir.'/'.$fileName;
    if (!@copy(SMOKEPING_TARGETS_FILE, $dest)) {
        return ['success'=>false,'msg'=>'Kon Targets backup niet maken.'];
    }
    touchTargetsBackupVersionMarker();
    return ['success'=>true,'msg'=>'Targets backup gemaakt: '.$fileName, 'file'=>$fileName];
}

function storeTargetsBackupContent(string $content, string $reason = 'uploaded', string $originalName = ''): array {
    $dir = targetsBackupDir();
    if (!is_dir($dir) && !@mkdir($dir, 0750, true)) {
        return ['success'=>false,'msg'=>'Kan backup map voor targets niet aanmaken.'];
    }
    $safeReason = preg_replace('/[^a-zA-Z0-9_-]/', '_', $reason);
    $nameBase = pathinfo($originalName, PATHINFO_FILENAME);
    $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', (string)$nameBase);
    $suffix = $safeName !== '' ? '_'.$safeName : '';
    $fileName = 'targets_'.date('Ymd_His').'_'.($safeReason ?: 'uploaded').$suffix.'.conf';
    $dest = $dir.'/'.$fileName;
    if (@file_put_contents($dest, $content) === false) {
        return ['success'=>false,'msg'=>'Kon geuploade Targets backup niet opslaan.'];
    }
    touchTargetsBackupVersionMarker();
    return ['success'=>true,'msg'=>'Targets backup opgeslagen: '.$fileName, 'file'=>$fileName, 'path'=>$dest];
}

function isLegacyMultiHostCategory(string $name): bool {
    return strtolower(trim($name)) === 'multihost_ipv4_ipv6';
}

function sanitizeTargetsContent(string $content): array {
    $lines = preg_split('/\r\n|\n|\r/', $content) ?: [];
    $out = [];
    $skipCategory = false;
    $removedCategories = 0;
    $removedHostRefs = 0;

    foreach ($lines as $rawLine) {
        $line = trim($rawLine);

        if (preg_match('/^\+\s+([a-zA-Z0-9_.-]+)$/', $line, $m)) {
            $catName = $m[1];
            if (isLegacyMultiHostCategory($catName)) {
                $skipCategory = true;
                $removedCategories++;
                continue;
            }
            $skipCategory = false;
        }

        if ($skipCategory) continue;

        if (preg_match('/^host\s*=\s*(.+)$/i', $line, $m)) {
            $hostValue = trim($m[1]);
            if (preg_match('/\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+/', $hostValue)) {
                $removedHostRefs++;
                continue;
            }
        }

        $out[] = $rawLine;
    }

    $clean = implode("\n", $out);
    if ($content !== '' && preg_match('/(\r\n|\n|\r)$/', $content)) {
        $clean .= "\n";
    }

    return [
        'content' => $clean,
        'removed_categories' => $removedCategories,
        'removed_host_refs' => $removedHostRefs,
        'changed' => ($removedCategories > 0 || $removedHostRefs > 0)
    ];
}

function parseTargetsConfigContent(string $content): array {
    $sanitized = sanitizeTargetsContent($content);
    $content = $sanitized['content'];
    $lines = preg_split('/\r\n|\n|\r/', $content) ?: [];
    $parsed = [];
    $currentCat = null;
    $currentTarget = null;

    $flushTarget = static function() use (&$parsed, &$currentCat, &$currentTarget): void {
        if ($currentCat === null || empty($currentTarget['name'])) return;
        if (!isset($parsed[$currentCat])) {
            $parsed[$currentCat] = ['display_name'=>$currentCat, 'probe'=>'', 'targets'=>[]];
        }
        $parsed[$currentCat]['targets'][] = $currentTarget;
    };

    foreach ($lines as $rawLine) {
        $line = trim($rawLine);
        if ($line === '' || $line[0] === '#') continue;

        if (preg_match('/^\+\s+([a-zA-Z0-9_.-]+)$/', $line, $m)) {
            $flushTarget();
            $currentTarget = null;
            $currentCat = $m[1];
            if (!isset($parsed[$currentCat])) {
                $parsed[$currentCat] = ['display_name'=>$currentCat, 'probe'=>'', 'targets'=>[]];
            }
            continue;
        }

        if (preg_match('/^\+\+\s+([a-zA-Z0-9_.-]+)$/', $line, $m)) {
            $flushTarget();
            $currentTarget = ['name'=>$m[1], 'display_name'=>$m[1], 'host'=>'', 'menu_name'=>'', 'probe'=>'', 'remark'=>''];
            continue;
        }

        if (preg_match('/^(menu|title|host|probe|remark)\s*=\s*(.*)$/i', $line, $m) && $currentTarget !== null) {
            $key = strtolower($m[1]);
            $value = trim($m[2]);
            if ($key === 'menu') $currentTarget['menu_name'] = $value;
            elseif ($key === 'title') $currentTarget['display_name'] = $value !== '' ? $value : $currentTarget['display_name'];
            elseif ($key === 'host') $currentTarget['host'] = $value;
            elseif ($key === 'probe') $currentTarget['probe'] = $value;
            elseif ($key === 'remark') $currentTarget['remark'] = $value;
        }
    }
    $flushTarget();

    return $parsed;
}

function isGeneratedCompanionCategoryName(string $categoryName): bool {
    $name = strtolower(trim($categoryName));
    if ($name === 'multihost_ipv4_ipv6') return true;
    return (bool)preg_match('/_ipv6$/', $name);
}

function isGeneratedCompanionTarget(array $target): bool {
    $name = strtolower(trim((string)($target['name'] ?? '')));
    if ($name === '') return false;
    if (preg_match('/(_v4_v6)$/', $name)) return true;

    $host = trim((string)($target['host'] ?? ''));
    $hostIpv6 = trim((string)($target['host_ipv6'] ?? ''));
    $menu = strtolower(trim((string)($target['menu_name'] ?? '')));
    $display = strtolower(trim((string)($target['display_name'] ?? '')));
    $hostLooksIpv6 = ($host !== '' && strpos($host, ':') !== false);

    // Companion targets produced by config generation are IPv6-only entries with suffixes.
    if ($hostIpv6 === '' && $hostLooksIpv6 && preg_match('/(_v6|_ipv6)$/', $name)) return true;
    if ($hostIpv6 === '' && $hostLooksIpv6 && (preg_match('/\sipv6$/', $display) || preg_match('/\(ipv6\)$/', $menu))) return true;
    return false;
}

function isManagerVisibleTargetRow(array $row): bool {
    $catName = (string)($row['cat_name'] ?? $row['category_name'] ?? '');
    if ($catName !== '' && isGeneratedCompanionCategoryName($catName)) return false;
    return !isGeneratedCompanionTarget($row);
}

function importTargetsConfigContent($db, string $content, string $reason = 'manual_import', string $originalName = '', bool $applyConfig = true): array {
    $sanitized = sanitizeTargetsContent($content);
    $cleanContent = $sanitized['content'];
    $parsed = parseTargetsConfigContent($cleanContent);
    if (empty($parsed)) {
        return ['success'=>false,'msg'=>'Het aangeleverde Targets bestand bevat geen geldige categorieen/targets.', 'imported'=>0];
    }

    if (file_exists(SMOKEPING_TARGETS_FILE)) {
        backupTargetsFileSnapshot('before_'.$reason);
    }

    $storedBackup = storeTargetsBackupContent($content, $reason, $originalName);
    if (@file_put_contents(SMOKEPING_TARGETS_FILE, $cleanContent) === false) {
        return ['success'=>false,'msg'=>'Kon Targets bestand niet wegschrijven.', 'imported'=>0];
    }

    $syncRes = syncTargetsFromFile($db, true);
    if (!$syncRes['success']) {
        return ['success'=>false,'msg'=>'Targets bestand opgeslagen, maar inladen mislukte: '.$syncRes['msg'], 'imported'=>0];
    }

    $msgParts = ['Targets bestand geimporteerd.'];
    if (!empty($sanitized['changed'])) {
        $msgParts[] = 'Sanity-cleanup toegepast (oude Multihost blokken/path-host regels verwijderd).';
    }
    if ($storedBackup['success'] ?? false) {
        $msgParts[] = $storedBackup['msg'];
    }
    $msgParts[] = $syncRes['msg'];

    if (!$applyConfig) {
        return ['success'=>true,'msg'=>implode(' ', $msgParts), 'imported'=>(int)($syncRes['imported'] ?? 0)];
    }

    $r = writeAllConfig($db);
    $msgParts[] = $r['msg'];
    return ['success'=>$r['success'], 'msg'=>implode(' ', $msgParts), 'imported'=>(int)($syncRes['imported'] ?? 0)];
}

// Target File Sync - Parse SmokePing Targets file and import to database.
// If $replaceAll=true, the file becomes source of truth (full replace of categories + targets).
function syncTargetsFromFile($db, bool $replaceAll = false): array {
    if (!file_exists(SMOKEPING_TARGETS_FILE)) {
        return ['success' => false, 'msg' => 'Targets bestand niet gevonden', 'imported' => 0, 'replaced' => false];
    }

    $content = @file_get_contents(SMOKEPING_TARGETS_FILE);
    if ($content === false) {
        return ['success' => false, 'msg' => 'Kan targets bestand niet lezen', 'imported' => 0, 'replaced' => false];
    }

    $parsed = parseTargetsConfigContent($content);
    if (empty($parsed)) {
        return ['success' => false, 'msg' => 'Targets bestand bevat geen geldige categorieen/targets', 'imported' => 0, 'replaced' => false];
    }

    if ($replaceAll) {
        $db->exec('BEGIN IMMEDIATE TRANSACTION');
        try {
            $db->exec('DELETE FROM targets');
            $db->exec('DELETE FROM categories');

            $catSort = 0;
            $imported = 0;
            foreach ($parsed as $catName => $catData) {
                if (isGeneratedCompanionCategoryName((string)$catName)) continue;
                $insCat = $db->prepare('INSERT INTO categories(name,display_name,probe,sort_order) VALUES(:n,:d,:p,:s)');
                $insCat->bindValue(':n', $catName);
                $insCat->bindValue(':d', $catData['display_name'] ?? $catName);
                $insCat->bindValue(':p', $catData['probe'] ?? '');
                $insCat->bindValue(':s', $catSort++, SQLITE3_INTEGER);
                $insCat->execute();

                $catId = (int)$db->lastInsertRowID();
                $tSort = 0;
                foreach ($catData['targets'] as $target) {
                    if (isGeneratedCompanionTarget($target)) continue;
                    if (empty($target['name']) || empty($target['host'])) continue;
                    $ins = $db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,enabled,sort_order) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:e,:s)');
                    $ins->bindValue(':c', $catId, SQLITE3_INTEGER);
                    $ins->bindValue(':n', $target['name']);
                    $ins->bindValue(':d', $target['display_name'] ?? $target['name']);
                    $ins->bindValue(':h', $target['host']);
                    $ins->bindValue(':h6', '');
                    $ins->bindValue(':p', $target['probe'] ?? '');
                    $ins->bindValue(':m', $target['menu_name'] ?? '');
                    $ins->bindValue(':r', normalizeTargetRemark($target['remark'] ?? null));
                    $ins->bindValue(':e', 1, SQLITE3_INTEGER);
                    $ins->bindValue(':s', $tSort++, SQLITE3_INTEGER);
                    $ins->execute();
                    $imported++;
                }
            }

            $db->exec('COMMIT');
            return ['success'=>true,'msg'=>"✅ Targets volledig opnieuw ingeladen ({$imported} targets)",'imported'=>$imported,'replaced'=>true];
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            return ['success'=>false,'msg'=>'Fout bij volledig inladen van Targets bestand: '.substr($e->getMessage(),0,220),'imported'=>0,'replaced'=>false];
        }
    }

    $imported = 0;
    foreach ($parsed as $catName => $catData) {
        if (isGeneratedCompanionCategoryName((string)$catName)) continue;
        $chk = $db->prepare('SELECT id FROM categories WHERE name=:n');
        $chk->bindValue(':n', $catName);
        $catRow = $chk->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$catRow) {
            $ins = $db->prepare('INSERT INTO categories(name,display_name,probe) VALUES(:n,:d,:p)');
            $ins->bindValue(':n', $catName);
            $ins->bindValue(':d', $catData['display_name'] ?? $catName);
            $ins->bindValue(':p', $catData['probe'] ?? '');
            $ins->execute();
        }
        foreach ($catData['targets'] as $target) {
            $imported += importTargetToDb($db, $catName, $target);
        }
    }

    if ($imported > 0) {
        return ['success' => true, 'msg' => "✅ {$imported} target(s) geïmporteerd uit bestand", 'imported' => $imported, 'replaced' => false];
    }
    return ['success' => true, 'msg' => 'Geen nieuwe targets gevonden in bestand', 'imported' => 0, 'replaced' => false];
}

function importTargetToDb($db, $catName, $target): int {
    if (isGeneratedCompanionCategoryName((string)$catName)) return 0;
    if (isGeneratedCompanionTarget((array)$target)) return 0;

    // Get category ID
    $catQ = $db->prepare('SELECT id FROM categories WHERE name=:n');
    $catQ->bindValue(':n', $catName);
    $catRow = $catQ->execute()->fetchArray(SQLITE3_ASSOC);
    if (!$catRow) return 0;
    
    $catId = (int)$catRow['id'];
    $targetName = $target['name'] ?? '';
    if (empty($targetName)) return 0;
    
    // Check if target already exists
    $chk = $db->prepare('SELECT id FROM targets WHERE category_id=:c AND name=:n');
    $chk->bindValue(':c', $catId, SQLITE3_INTEGER);
    $chk->bindValue(':n', $targetName);
    if ($chk->execute()->fetchArray()) {
        return 0; // Already exists, skip
    }
    
    // Insert new target
    $ins = $db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,enabled) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:e)');
    $ins->bindValue(':c', $catId, SQLITE3_INTEGER);
    $ins->bindValue(':n', $targetName);
    $ins->bindValue(':d', $target['display_name'] ?? $targetName);
    $ins->bindValue(':h', $target['host'] ?? '');
    $ins->bindValue(':h6', '');
    $ins->bindValue(':p', $target['probe'] ?? '');
    $ins->bindValue(':m', $target['menu_name'] ?? '');
    $ins->bindValue(':r', normalizeTargetRemark($target['remark'] ?? null));
    $ins->bindValue(':e', 1, SQLITE3_INTEGER);
    $ins->execute();
    
    return 1;
}

// ============================================================
// ROUTING
// ============================================================
$sessionTimeoutSeconds = ((int)$uiSessionTimeoutHours) * 3600;
if (isLoggedIn()) {
    $now = time();
    $lastActivity = (int)($_SESSION['last_activity'] ?? 0);
    if ($lastActivity > 0 && $sessionTimeoutSeconds > 0 && ($now - $lastActivity) > $sessionTimeoutSeconds) {
        clearCurrentSession(true);
        redirectToLogin('Je sessie is verlopen. Log opnieuw in.');
    }
    $_SESSION['last_activity'] = $now;
}

$page = $_GET['p'] ?? (isLoggedIn() ? 'dash' : 'login');
$setupComplete = getSetting($db, 'setup_complete', '0') === '1';

if ($page === 'google_auth') {
    startGoogleAuth($db);
}
if ($page === 'google_callback') {
    finishGoogleAuth($db);
}

if (!isLoggedIn() && !in_array($page, ['login','public_target_add','set_password'], true)) {
    redirectToLogin('Je sessie is verlopen. Log opnieuw in.');
}

if (isLoggedIn()) {
    if ($page === 'status') {
        $page = 'dash';
    } elseif ($page === 'probes') {
        $page = 'settings';
        $_GET['stab'] = 'configuratie';
    } elseif ($page === 'config') {
        $page = 'settings';
        $_GET['stab'] = 'configuratie';
    } elseif ($page === 'backup') {
        $page = 'settings';
        $_GET['stab'] = 'backups';
    }
}
// After login, if setup not complete, force to setup wizard
if (isLoggedIn() && !$setupComplete && $page !== 'setup') {
    $page = 'setup';
}

// Enforce page visibility for non-admin users
if (isLoggedIn() && !isAdmin($db)) {
    $userRole = getUserRole($db);
    $uid = (int)($_SESSION['uid'] ?? 0);
    $hasCustomPerms = $uid > 0 ? ((int)$db->querySingle('SELECT COUNT(*) FROM user_permissions WHERE user_id=' . $uid . ' AND page_key IN ("targets","dashboard","database","settings","logging")') > 0) : false;
    $shouldEnforce = ($userRole === 'user' || $userRole === 'readonly') || ($userRole === 'manager' && $hasCustomPerms);

    if ($shouldEnforce) {
        $pageMap = ['targets'=>'targets', 'dashboard'=>'dashboard', 'database'=>'database', 'settings'=>'settings', 'logging'=>'logging', 'cat'=>'targets', 'probes'=>'settings', 'config'=>'settings', 'backup'=>'settings'];
        $pageKey = $pageMap[$page] ?? $page;
        $perms = getPageVisibility($db, $uid);
        $deny = false;

        // User/readonly never get database/logging access for safety.
        if (($userRole === 'user' || $userRole === 'readonly') && in_array($pageKey, ['database','logging'], true)) {
            $deny = true;
        } elseif (in_array($pageKey, ['targets','dashboard','database','settings','logging'], true) && empty($perms[$pageKey])) {
            $deny = true;
        }

        if ($deny) {
            $_SESSION['_flash_msg'] = 'Je hebt geen toegang tot deze pagina.';
            $_SESSION['_flash_type'] = 'error';
            $page = !empty($perms['dashboard']) ? 'dashboard' : (!empty($perms['targets']) ? 'targets' : 'login');
            if ($page === 'login') {
                unset($_SESSION['uid'], $_SESSION['user']);
                $_SESSION['_flash_msg'] = 'Je hebt geen toegang tot enige pagina.';
                $_SESSION['_flash_type'] = 'error';
            }
        }
    }
}

$updateNotice = null;
if (isLoggedIn() && isAdmin($db)) {
    $remoteInstallerUrl = null;
    $remoteVersionInfo = smFetchRemoteInstallerVersion($remoteInstallerUrl);
    if (!empty($remoteVersionInfo['available']) && !empty($remoteVersionInfo['latest'])) {
        $updateNotice = $remoteVersionInfo;
        $updateNotice['url'] = $remoteInstallerUrl;
    }
}

// AJAX API: batch fetch target statuses for lazy-load optimization
if (isset($_POST['action']) && $_POST['action'] === 'get_target_statuses' && isLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    smPerfStart('target_status_api_ms');
    $result = [];
    $cfgStale = max(20, (int)getSetting($db, 'outage_stale_seconds', '20'));
    $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes WHERE enabled=1');
    if ($probeStepSec <= 0) $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes');
    if ($probeStepSec <= 0) $probeStepSec = 300;
    $staleThresholdSec = max($cfgStale, 120, $probeStepSec * 2);
    $targets = json_decode((string)($_POST['targets'] ?? '[]'), true) ?? [];
    foreach ($targets as $tgt) {
        $cat = (string)($tgt['cat'] ?? '');
        $name = (string)($tgt['name'] ?? '');
        $enabled = (int)($tgt['enabled'] ?? 0);
        if ($cat !== '' && $name !== '') {
            $st = getTargetStatus($cat, $name);
            $label = 'Uit';
            $class = 'inactive';
            if ($enabled === 1) {
                if (!$st['exists'] || (int)($st['sample_ts'] ?? 0) <= 0 || $st['loss'] === null) {
                    $label = '⏳ Wacht op 1e meting'; $class = 'warn';
                } elseif ((((int)($st['sample_ts'] ?? 0) > 0) && (time() - (int)$st['sample_ts'] > $staleThresholdSec)) || ($st['loss'] !== null && $st['loss'] >= 1.0)) {
                    $label = '❌ Uit'; $class = 'err';
                } elseif ($st['loss'] !== null && $st['loss'] >= 0.5) {
                    $label = '⚠️ Slecht'; $class = 'warn';
                } else {
                    $label = '✅ OK'; $class = 'ok';
                }
            }
            $result[] = [
                'key' => $cat . '|' . $name,
                'label' => $label,
                'class' => $class,
                'loss' => $st['loss'] !== null ? number_format((float)$st['loss'] * 100, 1) . '%' : '—',
                'median' => $st['median'] !== null ? ((int)$st['median']) . 'ms' : '—'
            ];
        }
    }
    smPerfStop('target_status_api_ms');
    finalizePerformanceMetric($db, 'api_target_statuses');
    echo json_encode($result);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'run_web_maintenance' && isLoggedIn()) {
    header('Content-Type: application/json; charset=utf-8');
    $lockValue = null;
    if (smCacheGet('maintenance:web:throttle', 10, $lockValue)) {
        smPerfSet('maintenance_ms', 0.0);
        finalizePerformanceMetric($db, 'maintenance');
        echo json_encode(['ok' => true, 'skipped' => true, 'reason' => 'throttled']);
        exit;
    }
    smCacheMiss();
    smCacheSet('maintenance:web:throttle', ['ts' => time()], 10);
    $res = runDeferredWebMaintenance($db);
    finalizePerformanceMetric($db, 'maintenance');
    echo json_encode(['ok' => true, 'skipped' => false, 'ran' => $res['ran'], 'ms' => $res['ms']]);
    exit;
}

$contentLen = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
$postMaxRaw = (string)ini_get('post_max_size');
$postMaxBytes = iniSizeToBytes($postMaxRaw);
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $contentLen > 0 && $postMaxBytes > 0 && $contentLen > $postMaxBytes && empty($_POST) && empty($_FILES)) {
    $uploadMaxRaw = (string)ini_get('upload_max_filesize');
    $returnPage = $_GET['p'] ?? (isLoggedIn() ? 'dash' : 'login');
    $returnQuery = [];
    if (isset($_GET['stab']) && $_GET['stab'] !== '') $returnQuery['stab'] = (string)$_GET['stab'];
    if (isset($_GET['tab']) && $_GET['tab'] !== '') $returnQuery['tab'] = (string)$_GET['tab'];
    flash('Upload mislukt: bestand of request is groter dan de serverlimiet (post_max_size='.$postMaxRaw.', upload_max_filesize='.$uploadMaxRaw.').', 'error');
    redir((string)$returnPage, $returnQuery);
}

$act = $_POST['action'] ?? '';
if ($_SERVER['REQUEST_METHOD']==='POST' && $act) {
    if ($act==='login') {
        $s=$db->prepare('SELECT * FROM users WHERE username=:u'); $s->bindValue(':u',trim($_POST['username']??''));
        $row=$s->execute()->fetchArray(SQLITE3_ASSOC);
        if ($row && password_verify($_POST['password']??'',$row['password'])) {
            if (strtolower((string)($row['approval_status'] ?? 'active')) !== 'active') {
                flash('Je account wacht nog op goedkeuring door beheer.','error');
                redir('login');
            }
            session_regenerate_id(true);
            $_SESSION['uid']=$row['id']; $_SESSION['uname']=$row['username']; $_SESSION['last_activity']=time();
            $up = $db->prepare('UPDATE users SET last_login_at=CURRENT_TIMESTAMP, auth_provider=COALESCE(NULLIF(auth_provider, ""), "local") WHERE id=:id');
            $up->bindValue(':id', (int)$row['id'], SQLITE3_INTEGER);
            $up->execute();
            logActivity($db, 'login', 'Ingelogd als '.($row['username']));
            flash('Welkom!'); redir('dash');
        }
        flash('Ongeldige login.','error'); redir('login');
    }
    if ($act==='set_initial_password') {
        $token = trim((string)($_POST['invite_token'] ?? ''));
        $newPassword = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');
        if ($token === '') { flash('Uitnodigingslink ontbreekt.','error'); redir('login'); }
        if (strlen($newPassword) < 6) { flash('Wachtwoord min. 6 tekens.','error'); redir('set_password', ['t' => $token]); }
        if ($newPassword !== $confirmPassword) { flash('Wachtwoorden komen niet overeen.','error'); redir('set_password', ['t' => $token]); }
        $invite = findValidUserInviteByToken($db, $token);
        if (!$invite) {
            flash('Deze link is ongeldig of verlopen. Vraag een nieuwe uitnodiging aan de beheerder.','error');
            redir('login');
        }
        $u = $db->prepare('UPDATE users SET password=:p, approval_status="active", approved_at=COALESCE(approved_at, CURRENT_TIMESTAMP), auth_provider=COALESCE(NULLIF(auth_provider, ""), "local") WHERE id=:id');
        $u->bindValue(':p', password_hash($newPassword, PASSWORD_BCRYPT), SQLITE3_TEXT);
        $u->bindValue(':id', (int)$invite['user_id'], SQLITE3_INTEGER);
        $u->execute();
        markUserInviteUsed($db, (int)$invite['invite_id']);
        logActivity($db, 'wachtwoord_init', 'Eerste wachtwoord ingesteld voor gebruiker ' . (string)($invite['username'] ?? ('ID ' . (int)$invite['user_id'])));
        flash('Je wachtwoord is ingesteld. Je kunt nu inloggen.','success');
        redir('login');
    }
    if ($act==='public_submit_target') {
        $token = trim((string)($_POST['public_token'] ?? ''));
        if (!isPublicTargetTokenValid($db, $token)) {
            flash('Ongeldige of verlopen openbare link.', 'error');
            redir('public_target_add');
        }

        // Basic honeypot against simple bot posts.
        if (trim((string)($_POST['website'] ?? '')) !== '') {
            flash('Inzending ontvangen.', 'success');
            redir('public_target_add', ['k' => $token]);
        }

        $enabledCats = [];
        foreach (getCats($db) as $cat) {
            if ((int)($cat['enabled'] ?? 1) === 1) $enabledCats[(int)$cat['id']] = $cat;
        }
        if (empty($enabledCats)) {
            flash('Er zijn momenteel geen categorieen beschikbaar.', 'error');
            redir('public_target_add', ['k' => $token]);
        }

        $cid = (int)($_POST['category_id'] ?? 0);
        if (!isset($enabledCats[$cid])) $cid = (int)array_key_first($enabledCats);

        $displayName = trim((string)($_POST['display_name'] ?? ''));
        $host = normalizeTargetHostValue($_POST['host'] ?? '');
        $host_ipv6 = normalizeTargetHostValue($_POST['host_ipv6'] ?? '');
        $remark = normalizeTargetRemark($_POST['remark'] ?? '');

        if ($displayName === '' || strlen($displayName) > 120) {
            flash('Vul een geldige targetnaam in (max 120 tekens).', 'error');
            redir('public_target_add', ['k' => $token]);
        }
        if ($host === '' && $host_ipv6 === '') {
            flash('Vul minimaal een IPv4/hostname of IPv6 adres in.', 'error');
            redir('public_target_add', ['k' => $token]);
        }

        $internalName = generateUniqueTargetName($db, $cid, $displayName);
        $alertName = getDefaultTargetAlertName($db);
        $insRes = insertPublicSubmittedTarget($db, [
            'category_id' => $cid,
            'name' => $internalName,
            'display_name' => $displayName,
            'host' => $host,
            'host_ipv6' => $host_ipv6,
            'probe' => '',
            'menu_name' => '',
            'remark' => $remark,
            'alert' => $alertName,
            'session_duration' => 'unlimited',
            'session_notify_enabled' => 0,
            'session_notify_email' => '',
            'session_start_notified' => 0,
            'session_end_notified' => 0,
            'sort_order' => 0,
            'enabled' => 0,
            'user_id' => 0,
            'submission_source' => 'public_queue',
        ]);
        if (empty($insRes['success'])) {
            $errMsg = (string)($insRes['message'] ?? 'Onbekende databasefout');
            logActivity($db, 'publieke_target_inzending_mislukt', 'Publieke inzending mislukt: '.$displayName.' | '.$errMsg);
            flash('Opslaan van de aanvraag is mislukt. Probeer opnieuw of neem contact op met beheer. Details: '.$errMsg, 'error');
            redir('public_target_add', ['k' => $token]);
        }

        logActivity($db, 'publieke_target_inzending', 'Publieke inzending toegevoegd: '.$displayName.' (inactief, id='.(int)($insRes['id'] ?? 0).')');
        flash('Bedankt. Target toegevoegd en wacht op activatie door beheer. Beheer kan dit direct terugvinden via Targets > Wachtrij.', 'success');
        redir('public_target_add', ['k' => $token]);
    }
    if ($act==='logout') {
        logActivity($db, 'logout', 'Uitgelogd');
        clearCurrentSession(true);
        redirectToLogin('Je bent uitgelogd.');
    }
    if (!isLoggedIn()) redirectToLogin('Je sessie is verlopen. Log opnieuw in.');
    if (!verifyCsrf()) { flash('CSRF fout.','error'); redir('targets',['tab'=>'targets']); }

    // Setup Wizard
    if ($act==='setup_wizard_theme') {
        $th=$_POST['theme']??'auto';
        if(!in_array($th,['auto','light','dark'],true)) $th='auto';
        setSetting($db,'theme',$th);
        redir('setup',['step'=>'2']);
    }
    if ($act==='setup_wizard_credentials') {
        $newuser=trim($_POST['newuser']??''); $newpass=trim($_POST['newpass']??'');
        if(empty($newpass)) { flash('Wachtwoord is verplicht.','error'); redir('setup',['step'=>'2']); }
        $s=$db->prepare('UPDATE users SET username=:u, password=:p WHERE id=1');
        $s->bindValue(':u',$newuser ?: 'admin'); $s->bindValue(':p',password_hash($newpass,PASSWORD_BCRYPT));
        $s->execute(); $_SESSION['uname']=$newuser ?: 'admin';
        redir('setup',['step'=>'3']);
    }
    if ($act==='setup_wizard_email') {
        $provider=$_POST['email_provider']??'gmail';
        $email=trim($_POST['email_address']??'');
        $password=trim($_POST['email_password']??'');
        $googleAuthEnabled = isset($_POST['google_auth_enabled']) ? '1' : '0';
        $googleClientId = trim((string)($_POST['google_client_id'] ?? ''));
        $googleClientSecret = trim((string)($_POST['google_client_secret'] ?? ''));
        $googleRedirectUri = trim((string)($_POST['google_redirect_uri'] ?? ''));
        
        if(!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            flash('Ongeldig mailadres.','error'); redir('setup',['step'=>'3']);
        }
        if(empty($password)) {
            flash('Wachtwoord is verplicht.','error'); redir('setup',['step'=>'3']);
        }
        if ($googleAuthEnabled === '1') {
            if ($googleClientId === '') {
                flash('Vul een Google Client ID in als Google Auth is ingeschakeld.','error'); redir('setup',['step'=>'3']);
            }
            if ($googleClientSecret === '') {
                flash('Vul een Google Client Secret in als Google Auth is ingeschakeld.','error'); redir('setup',['step'=>'3']);
            }
            if ($googleRedirectUri === '') {
                $googleRedirectUri = buildGoogleRedirectUri($db);
            }
        }
        
        // Email provider settings
        $providers = [
            'gmail' => ['host'=>'smtp.gmail.com', 'port'=>587, 'encryption'=>'tls', 'name'=>'Gmail'],
            'outlook' => ['host'=>'smtp-mail.outlook.com', 'port'=>587, 'encryption'=>'tls', 'name'=>'Outlook'],
            'yahoo' => ['host'=>'smtp.mail.yahoo.com', 'port'=>465, 'encryption'=>'ssl', 'name'=>'Yahoo'],
            'custom' => ['host'=>trim($_POST['custom_smtp_host']??''), 'port'=>(int)($_POST['custom_smtp_port']??587), 'encryption'=>trim($_POST['custom_smtp_encryption']??'tls'), 'name'=>'Custom']
        ];
        
        if(!isset($providers[$provider])) $provider='gmail';
        $prov=$providers[$provider];
        
        $s=$db->prepare('UPDATE email_settings SET smtp_enabled=1, smtp_host=:host, smtp_port=:port, smtp_encryption=:enc, smtp_username=:user, smtp_password=:pass, smtp_from_email=:from, alert_recipients=:ar, updated_at=CURRENT_TIMESTAMP WHERE id=1');
        $s->bindValue(':host', $prov['host']);
        $s->bindValue(':port', $prov['port'], SQLITE3_INTEGER);
        $s->bindValue(':enc', $prov['encryption']);
        $s->bindValue(':user', $email);
        $s->bindValue(':pass', smEncryptPassword($password));
        $s->bindValue(':from', $email);
        $s->bindValue(':ar', $email);
        $s->execute();

        setSetting($db, 'google_auth_enabled', $googleAuthEnabled);
        setSetting($db, 'google_client_id', $googleClientId);
        setSetting($db, 'google_client_secret', smEncryptPassword($googleClientSecret));
        setSetting($db, 'google_redirect_uri', $googleRedirectUri !== '' ? $googleRedirectUri : buildGoogleRedirectUri($db));
        
        redir('setup',['step'=>'4']);
    }
    if ($act==='setup_wizard_smokeping_tuning') {
        $messages = [];
        $hasChanges = false;
        $didPresentationTuning = false;

        if (isset($_POST['apply_database_tuning'])) {
            $profile = (string)($_POST['db_profile'] ?? 'fast_10_5');
            $dbStep = 10;
            $dbPings = 5;
            if ($profile === 'fast_10_5') {
                $dbStep = 10;
                $dbPings = 5;
            } elseif ($profile === 'custom') {
                $dbStep = (int)($_POST['db_step'] ?? 300);
                $dbPings = (int)($_POST['db_pings'] ?? 20);
            }
            $dbStep = max(10, min(3600, $dbStep));
            $dbPings = max(1, min(100, $dbPings));

            $dbRes = applyDatabaseConfig($dbStep, $dbPings, $db);
            if (!$dbRes['success']) {
                flash($dbRes['msg'], 'error');
                redir('setup', ['step' => '4']);
            }
            $interval = round($dbStep / $dbPings, 2);
            $messages[] = $dbRes['msg'] . ' (ongeveer 1 ping per ' . $interval . ' seconden).';
            $hasChanges = true;
        }

        if (isset($_POST['apply_presentation_tuning'])) {
            $rangesRaw = (string)($_POST['presentation_ranges'] ?? '');
            $presRes = applyPresentationRanges($rangesRaw);
            if (!$presRes['success']) {
                flash($presRes['msg'], 'error');
                redir('setup', ['step' => '4']);
            }
            $messages[] = $presRes['msg'];
            $hasChanges = true;
            $didPresentationTuning = true;
        }

        if ($didPresentationTuning) {
            $clearRes = clearAllRrdData();
            if (!$clearRes['success']) {
                flash($clearRes['msg'], 'error');
                redir('setup', ['step' => '4']);
            }
            $messages[] = $clearRes['msg'];
        }

        if ($hasChanges) {
            $restartRes = doRestart();
            if (!$restartRes['success']) {
                flash('Wijzigingen zijn opgeslagen, maar herstarten van SmokePing is mislukt. ' . $restartRes['msg'], 'error');
                redir('setup', ['step' => '4']);
            }
            $messages[] = 'SmokePing is herstart om de nieuwe instellingen toe te passen.';
        }

        if (!empty($messages)) {
            flash(implode(' ', $messages), 'success');
        } else {
            flash('Geen wijzigingen geselecteerd.', 'error');
        }

        redir('setup', ['step' => '5']);
    }
    if ($act==='setup_wizard_targets_import') {
        $messages=[];
        $uploadErr = $_FILES['targets_import_file']['error'] ?? UPLOAD_ERR_NO_FILE;
        $hasUpload = $uploadErr !== UPLOAD_ERR_NO_FILE;
        if ($hasUpload) {
            if ($uploadErr !== UPLOAD_ERR_OK) {
                flash('Targets upload mislukt tijdens de wizard.','error'); redir('setup',['step'=>'5']);
            }
            $content = @file_get_contents($_FILES['targets_import_file']['tmp_name']);
            if ($content === false || trim($content) === '') {
                flash('Kon het geuploade Targets bestand niet lezen.','error'); redir('setup',['step'=>'5']);
            }
            $importRes = importTargetsConfigContent($db, $content, 'wizard_import', (string)($_FILES['targets_import_file']['name'] ?? ''), true);
            if (!$importRes['success']) {
                flash($importRes['msg'],'error'); redir('setup',['step'=>'5']);
            }
            $messages[] = $importRes['msg'];
        }
        if (!empty($messages)) {
            flash(implode(' ', $messages), 'success');
        }
        redir('setup',['step'=>'6']);
    }
    if ($act==='setup_wizard_backup_schedule') {
        $enabled = isset($_POST['auto_backup_enabled']) ? '1' : '0';
        $frequency = (string)($_POST['auto_backup_frequency'] ?? 'daily');
        if (!in_array($frequency, ['daily','weekly','monthly'], true)) $frequency = 'daily';
        $keepLatest = max(1, min(100, (int)($_POST['auto_backup_keep_latest'] ?? 10)));
        $retainDaily = max(0, min(365, (int)($_POST['auto_backup_retain_daily'] ?? 14)));
        $retainWeekly = max(0, min(104, (int)($_POST['auto_backup_retain_weekly'] ?? 8)));
        $retainMonthly = max(0, min(36, (int)($_POST['auto_backup_retain_monthly'] ?? 6)));
        setSetting($db, 'auto_backup_enabled', $enabled);
        setSetting($db, 'auto_backup_frequency', $frequency);
        setSetting($db, 'auto_backup_keep_latest', (string)$keepLatest);
        setSetting($db, 'auto_backup_retain_daily', (string)$retainDaily);
        setSetting($db, 'auto_backup_retain_weekly', (string)$retainWeekly);
        setSetting($db, 'auto_backup_retain_monthly', (string)$retainMonthly);
        flash('Automatische backup instellingen opgeslagen.', 'success');
        redir('setup',['step'=>'complete']);
    }
    if ($act==='setup_wizard_complete') {
        setSetting($db,'setup_complete','1');
        flash('Stappenplan voltooid! Welkom bij SmokePing Manager.','success');
        redir('dash');
    }
    if ($act==='reset_setup') {
        setSetting($db,'setup_complete','0');
        // Delete all categories and targets (except keep users)
        $db->exec('DELETE FROM targets'); $db->exec('DELETE FROM categories');
        flash('Setup gereset. Volg het stappenplan opnieuw.','success');
        redir('setup');
    }

    // Categories
    if ($act==='add_cat') {
        if (!hasActionPermission($db, 'act_categories_manage')) { flash('Je hebt geen rechten om categorieën toe te voegen.','error'); redir('targets',['tab'=>'targets']); }
        $s=$db->prepare('INSERT INTO categories(name,display_name,probe,remark,sort_order) VALUES(:n,:d,:p,:r,:s)');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':p',''); $s->bindValue(':r', normalizeTargetRemark($_POST['remark'] ?? null));
        $s->bindValue(':s',(int)($_POST['sort_order']??0));
        $s->execute(); $r=writeAllConfig($db);
        logActivity($db, 'categorie_toevoegen', 'Categorie toegevoegd: '.trim($_POST['display_name']??''));
        flash('Categorie toegevoegd. '.$r['msg']); redir('targets',['tab'=>'targets']);
    }
    if ($act==='edit_cat') {
        if (!hasActionPermission($db, 'act_categories_manage')) { flash('Je hebt geen rechten om categorieën te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $s=$db->prepare('UPDATE categories SET name=:n,display_name=:d,probe=:p,remark=:r,sort_order=:s,enabled=:e WHERE id=:id');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':p',''); $s->bindValue(':r', normalizeTargetRemark($_POST['remark'] ?? null));
        $s->bindValue(':s',(int)($_POST['sort_order']??0)); $s->bindValue(':e',isset($_POST['enabled'])?1:0);
        $s->bindValue(':id',(int)$_POST['id']); $s->execute(); $r=writeAllConfig($db);
        logActivity($db, 'categorie_bewerken', 'Categorie bewerkt: '.trim($_POST['display_name']??'').' (ID '.(int)$_POST['id'].')');
        flash('Bijgewerkt. '.$r['msg']); redir('targets',['tab'=>'targets']);
    }
    if ($act==='del_cat') {
        if (!hasActionPermission($db, 'act_categories_manage')) { flash('Je hebt geen rechten om categorieën te verwijderen.','error'); redir('targets',['tab'=>'targets']); }
        $db->exec('DELETE FROM targets WHERE category_id='.(int)$_POST['id']);
        $s=$db->prepare('DELETE FROM categories WHERE id=:id'); $s->bindValue(':id',(int)$_POST['id']); $s->execute();
        $r=writeAllConfig($db);
        logActivity($db, 'categorie_verwijderen', 'Categorie verwijderd (ID '.(int)$_POST['id'].')');
        flash('Verwijderd. '.$r['msg']); redir('targets',['tab'=>'targets']);
    }
    // Targets
    if ($act==='add_tgt') {
        if (!canCrudTargets($db)) { flash('Je hebt geen rechten om targets toe te voegen.','error'); redir('targets',['tab'=>'targets']); }
        $cid=(int)$_POST['category_id'];
        $displayName = trim((string)($_POST['display_name'] ?? ''));
        if ($displayName === '') { flash('Vul een naam in.','error'); redir('targets',['tab'=>'targets']); }
        $host = normalizeTargetHostValue($_POST['host'] ?? ''); $host_ipv6 = normalizeTargetHostValue($_POST['host_ipv6'] ?? '');
        if ($host === '' && $host_ipv6 === '') { flash('Vul minimaal een IPv4/hostname of IPv6 adres in.','error'); redir('targets',['tab'=>'targets']); }
        $probe = ''; // Always inherit probe from category
        $internalName = generateUniqueTargetName($db, $cid, $displayName);
        $alertName = trim((string)($_POST['alert'] ?? ''));
        if ($alertName === '') $alertName = getDefaultTargetAlertName($db);
        $sessionDuration = normalizeSessionDuration(trim((string)($_POST['session_duration'] ?? 'unlimited')));
        $sessionNotifyEnabled = isset($_POST['session_notify_enabled']) ? 1 : 0;
        $sessionNotifyEmail = trim((string)($_POST['session_notify_email'] ?? ''));
        if ($sessionNotifyEnabled) {
            if ($sessionNotifyEmail === '') $sessionNotifyEmail = getDefaultNotifyRecipientList($db);
            $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
            if ($sessionNotifyEmail === '') {
                flash('Vul een geldig e-mailadres in voor sessie notificaties (meerdere met komma).','error');
                redir('targets',['tab'=>'targets']);
            }
        }
        $sessionStartedAt = date('Y-m-d H:i:s');
        $allowedTgtIntervals = [5,10,15,30,240,480,1440,2880,10080];
        $outageIntervalRaw = (isset($_POST['outage_mail_interval']) && $_POST['outage_mail_interval'] !== '') ? (int)$_POST['outage_mail_interval'] : null;
        if ($outageIntervalRaw !== null && !in_array($outageIntervalRaw, $allowedTgtIntervals, true)) $outageIntervalRaw = null;
        $userId = (int)($_SESSION['uid'] ?? 0);
        $s=$db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,alert,session_duration,session_notify_enabled,session_notify_email,session_started_at,session_start_notified,session_end_notified,sort_order,outage_mail_interval,user_id) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:a,:sd,:sne,:snem,:ssa,:ssn,:sen,:s,:omi,:uid)');
        $s->bindValue(':c',$cid); $s->bindValue(':n',$internalName); $s->bindValue(':d',$displayName);
        $s->bindValue(':h',$host); $s->bindValue(':h6',$host_ipv6);
        $s->bindValue(':p',$probe); $s->bindValue(':m','');
        $s->bindValue(':r', normalizeTargetRemark($_POST['remark'] ?? null)); $s->bindValue(':a',$alertName);
        $s->bindValue(':sd',$sessionDuration);
        $s->bindValue(':sne',$sessionNotifyEnabled,SQLITE3_INTEGER);
        $s->bindValue(':snem',$sessionNotifyEmail,SQLITE3_TEXT);
        $s->bindValue(':ssa',$sessionStartedAt,SQLITE3_TEXT);
        $s->bindValue(':ssn',0,SQLITE3_INTEGER);
        $s->bindValue(':sen',0,SQLITE3_INTEGER);
        $s->bindValue(':s',0,SQLITE3_INTEGER);
        $s->bindValue(':omi',$outageIntervalRaw,$outageIntervalRaw===null?SQLITE3_NULL:SQLITE3_INTEGER);
        $s->bindValue(':uid',$userId,SQLITE3_INTEGER);
        $s->execute();
        $newTargetId = (int)$db->lastInsertRowID();
        try { maybeSendSessionStartMail($db, $newTargetId); } catch (\Throwable $e) {}
        $r=writeAllConfig($db);
        logActivity($db, 'target_toevoegen', 'Target toegevoegd: '.trim($_POST['display_name']??'').' ('.trim($_POST['host']??'').')');
        $addParams = ['tab'=>'targets'];
        if (($_POST['after_add'] ?? '') === 'stay') $addParams['tgt_continue'] = '1';
        flash('Target toegevoegd. '.$r['msg']); redir('targets', $addParams);
    }
    if ($act==='add_tgt_queue') {
        if (!hasActionPermission($db, 'act_targets_queue')) { flash('Je hebt geen rechten om wachtrij-targets toe te voegen.','error'); redir('targets',['tab'=>'targets']); }
        $res = upsertTargetDraftQueueItem($db, $_POST);
        if (empty($res['success'])) {
            flash($res['msg'] ?? 'Concepttarget kon niet worden toegevoegd.', 'error');
            redir('targets',['tab'=>'targets','tgt_continue'=>'1']);
        }
        $params = ['tab'=>'targets'];
        if (($_POST['after_add'] ?? '') === 'stay') $params['tgt_continue'] = '1';
        flash(($res['updated'] ? 'Concepttarget bijgewerkt.' : 'Concepttarget toegevoegd aan wachtrij.').' Wachtrij: '.(int)($res['count'] ?? 0).' item(s).');
        redir('targets', $params);
    }
    if ($act==='add_tgt_queue_bulk') {
        if (!hasActionPermission($db, 'act_targets_add')) { flash('Je hebt geen rechten om targets toe te voegen.','error'); redir('targets',['tab'=>'targets']); }
        $res = parseBulkTargetDrafts($db, $_POST);
        if (empty($res['success'])) {
            flash($res['msg'] ?? 'Bulkregels konden niet worden verwerkt.', 'error');
            redir('targets',['tab'=>'targets']);
        }
        $parseErrors = $res['errors'] ?? [];
        $queue = getTargetDraftQueue();
        $preparedInfo = prepareQueuedTargetDraftsForApply($db, $queue);
        $prepared = $preparedInfo['prepared'];
        $applyErrors = array_merge($parseErrors, $preparedInfo['errors'] ?? []);
        if (empty($prepared)) {
            clearTargetDraftQueue();
            flash('Geen geldige targets verwerkt. '.implode(' | ', array_slice($applyErrors, 0, 3)), 'error');
            redir('targets',['tab'=>'targets']);
        }
        $insertedIds = [];
        $userId = (int)($_SESSION['uid'] ?? 0);
        $db->exec('BEGIN IMMEDIATE TRANSACTION');
        try {
            $stmt = $db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,alert,session_duration,session_notify_enabled,session_notify_email,session_started_at,session_start_notified,session_end_notified,sort_order,outage_mail_interval,user_id) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:a,:sd,:sne,:snem,:ssa,:ssn,:sen,:s,:omi,:uid)');
            foreach ($prepared as $draft) {
                $sessionStartedAt = date('Y-m-d H:i:s');
                $stmt->bindValue(':c', $draft['category_id'], SQLITE3_INTEGER);
                $stmt->bindValue(':n', $draft['internal_name'], SQLITE3_TEXT);
                $stmt->bindValue(':d', $draft['display_name'], SQLITE3_TEXT);
                $stmt->bindValue(':h', $draft['host'], SQLITE3_TEXT);
                $stmt->bindValue(':h6', $draft['host_ipv6'], SQLITE3_TEXT);
                $stmt->bindValue(':p', '', SQLITE3_TEXT);
                $stmt->bindValue(':m', '', SQLITE3_TEXT);
                $stmt->bindValue(':r', $draft['remark'], SQLITE3_TEXT);
                $stmt->bindValue(':a', $draft['alert'], SQLITE3_TEXT);
                $stmt->bindValue(':sd', $draft['session_duration'], SQLITE3_TEXT);
                $stmt->bindValue(':sne', $draft['session_notify_enabled'], SQLITE3_INTEGER);
                $stmt->bindValue(':snem', $draft['session_notify_email'], SQLITE3_TEXT);
                $stmt->bindValue(':ssa', $sessionStartedAt, SQLITE3_TEXT);
                $stmt->bindValue(':ssn', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':sen', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':s', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':omi', $draft['outage_mail_interval'], $draft['outage_mail_interval'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
                $stmt->bindValue(':uid', $userId, SQLITE3_INTEGER);
                $stmt->execute();
                $insertedIds[] = (int)$db->lastInsertRowID();
            }
            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            clearTargetDraftQueue();
            flash('Targets toevoegen mislukt: '.substr($e->getMessage(), 0, 220), 'error');
            redir('targets',['tab'=>'targets']);
        }
        foreach ($insertedIds as $newTargetId) {
            try { maybeSendSessionStartMail($db, $newTargetId); } catch (\Throwable $e) {}
        }
        clearTargetDraftQueue();
        $r = writeAllConfig($db);
        logActivity($db, 'target_bulk_toevoegen', count($insertedIds).' target(s) toegevoegd via batch');
        $msg = count($insertedIds).' target(s) toegevoegd. '.$r['msg'];
        if (!empty($applyErrors)) $msg .= ' Overgeslagen: '.implode(' | ', array_slice($applyErrors, 0, 3));
        flash($msg, ($r['success'] && empty($applyErrors)) ? 'success' : ($r['success'] ? 'success' : 'error'));
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='remove_tgt_queue') {
        if (!hasActionPermission($db, 'act_targets_queue')) { flash('Je hebt geen rechten om de wachtrij te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $remaining = removeTargetDraftQueueItem((string)($_POST['queue_id'] ?? ''));
        flash('Concepttarget verwijderd. Wachtrij: '.$remaining.' item(s).');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='clear_tgt_queue') {
        if (!hasActionPermission($db, 'act_targets_queue')) { flash('Je hebt geen rechten om de wachtrij te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        clearTargetDraftQueue();
        flash('Conceptwachtrij leeggemaakt.');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='apply_tgt_queue') {
        if (!hasActionPermission($db, 'act_targets_queue')) { flash('Je hebt geen rechten om de wachtrij toe te passen.','error'); redir('targets',['tab'=>'targets']); }
        $queue = getTargetDraftQueue();
        if (empty($queue)) {
            flash('De conceptwachtrij is leeg.', 'error');
            redir('targets',['tab'=>'targets']);
        }
        $applyMode = (($_POST['apply_mode'] ?? '') === 'partial') ? 'partial' : 'strict';
        $preparedInfo = prepareQueuedTargetDraftsForApply($db, $queue);
        $prepared = $preparedInfo['prepared'];
        $errors = $preparedInfo['errors'];
        if ($applyMode === 'strict' && !empty($errors)) {
            flash('Toepassen afgebroken: '.implode(' | ', array_slice($errors, 0, 3)), 'error');
            redir('targets',['tab'=>'targets']);
        }
        if (empty($prepared)) {
            flash('Geen geldige concepttargets om toe te passen. '.implode(' | ', array_slice($errors, 0, 3)), 'error');
            redir('targets',['tab'=>'targets']);
        }

        $insertedIds = [];
        $insertedQueueIds = [];
        $db->exec('BEGIN IMMEDIATE TRANSACTION');
        try {
            $userId = (int)($_SESSION['uid'] ?? 0);
            $stmt = $db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,alert,session_duration,session_notify_enabled,session_notify_email,session_started_at,session_start_notified,session_end_notified,sort_order,outage_mail_interval,user_id) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:a,:sd,:sne,:snem,:ssa,:ssn,:sen,:s,:omi,:uid)');
            foreach ($prepared as $draft) {
                $sessionStartedAt = date('Y-m-d H:i:s');
                $stmt->bindValue(':c', $draft['category_id'], SQLITE3_INTEGER);
                $stmt->bindValue(':n', $draft['internal_name'], SQLITE3_TEXT);
                $stmt->bindValue(':d', $draft['display_name'], SQLITE3_TEXT);
                $stmt->bindValue(':h', $draft['host'], SQLITE3_TEXT);
                $stmt->bindValue(':h6', $draft['host_ipv6'], SQLITE3_TEXT);
                $stmt->bindValue(':p', '', SQLITE3_TEXT);
                $stmt->bindValue(':m', '', SQLITE3_TEXT);
                $stmt->bindValue(':r', $draft['remark'], SQLITE3_TEXT);
                $stmt->bindValue(':a', $draft['alert'], SQLITE3_TEXT);
                $stmt->bindValue(':sd', $draft['session_duration'], SQLITE3_TEXT);
                $stmt->bindValue(':sne', $draft['session_notify_enabled'], SQLITE3_INTEGER);
                $stmt->bindValue(':snem', $draft['session_notify_email'], SQLITE3_TEXT);
                $stmt->bindValue(':ssa', $sessionStartedAt, SQLITE3_TEXT);
                $stmt->bindValue(':ssn', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':sen', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':s', 0, SQLITE3_INTEGER);
                $stmt->bindValue(':omi', $draft['outage_mail_interval'], $draft['outage_mail_interval'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
                $stmt->bindValue(':uid', $userId, SQLITE3_INTEGER);
                $stmt->execute();
                $insertedIds[] = (int)$db->lastInsertRowID();
                $insertedQueueIds[(string)($draft['queue_id'] ?? '')] = true;
            }
            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            flash('Concepttargets toepassen mislukt: '.substr($e->getMessage(), 0, 220), 'error');
            redir('targets',['tab'=>'targets']);
        }

        foreach ($insertedIds as $newTargetId) {
            try { maybeSendSessionStartMail($db, $newTargetId); } catch (\Throwable $e) {}
        }

        $remainingQueue = [];
        foreach ($queue as $draft) {
            if (!isset($insertedQueueIds[(string)($draft['queue_id'] ?? '')])) $remainingQueue[] = $draft;
        }
        saveTargetDraftQueue($remainingQueue);

        $r = writeAllConfig($db);
        logActivity($db, 'target_wachtrij_toepassen', count($insertedIds).' concepttarget(s) toegepast');
        $msg = count($insertedIds).' target(s) opgeslagen. '.$r['msg'];
        if (!empty($errors)) $msg .= ' Niet toegepast: '.implode(' | ', array_slice($errors, 0, 3));
        flash($msg, ($r['success'] && empty($errors)) ? 'success' : ($r['success'] ? 'success' : 'error'));
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='save_custom_graph') {
        if (!hasActionPermission($db, 'act_graphs_manage')) { flash('Je hebt geen rechten om samengestelde grafieken te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $graphId = (int)($_POST['graph_id'] ?? 0);
        $title = trim((string)($_POST['graph_title'] ?? ''));
        $groupName = trim((string)($_POST['graph_group_name'] ?? ''));
        $targetIdsRaw = $_POST['graph_target_ids'] ?? [];
        $modeMap = $_POST['graph_mode'] ?? [];
        if ($title === '') { flash('Vul een grafiektitel in.','error'); redir('targets',['tab'=>'targets']); }
        if ($groupName === '') $groupName = 'Samengestelde grafieken';
        if (!is_array($targetIdsRaw) || empty($targetIdsRaw)) { flash('Selecteer minimaal 1 target voor de samengestelde grafiek.','error'); redir('targets',['tab'=>'targets']); }

        $targetIds = [];
        $members = [];
        foreach ($targetIdsRaw as $targetIdRaw) {
            $targetId = (int)$targetIdRaw;
            if ($targetId <= 0 || isset($targetIds[$targetId])) continue;
            $targetIds[$targetId] = true;
            $mode = (string)($modeMap[$targetId] ?? 'ipv4');
            if (!in_array($mode, ['ipv4','ipv6','both'], true)) $mode = 'ipv4';
            $members[] = ['target_id' => $targetId, 'mode' => $mode];
        }
        if (empty($members)) { flash('Selecteer minimaal 1 geldig target.','error'); redir('targets',['tab'=>'targets']); }

        $db->exec('BEGIN IMMEDIATE TRANSACTION');
        try {
            if ($graphId > 0) {
                $stmt = $db->prepare('UPDATE custom_graphs SET title=:t, group_name=:g, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
                $stmt->bindValue(':id', $graphId, SQLITE3_INTEGER);
            } else {
                $stmt = $db->prepare('INSERT INTO custom_graphs(title, group_name) VALUES(:t,:g)');
            }
            $stmt->bindValue(':t', $title, SQLITE3_TEXT);
            $stmt->bindValue(':g', $groupName, SQLITE3_TEXT);
            $stmt->execute();
            if ($graphId <= 0) $graphId = (int)$db->lastInsertRowID();

            $del = $db->prepare('DELETE FROM custom_graph_members WHERE graph_id=:id');
            $del->bindValue(':id', $graphId, SQLITE3_INTEGER);
            $del->execute();

            $ins = $db->prepare('INSERT INTO custom_graph_members(graph_id, target_id, mode, sort_order) VALUES(:g,:t,:m,:s)');
            foreach ($members as $index => $member) {
                $ins->bindValue(':g', $graphId, SQLITE3_INTEGER);
                $ins->bindValue(':t', $member['target_id'], SQLITE3_INTEGER);
                $ins->bindValue(':m', $member['mode'], SQLITE3_TEXT);
                $ins->bindValue(':s', $index * 10, SQLITE3_INTEGER);
                $ins->execute();
            }
            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            flash('Samengestelde grafiek opslaan mislukt: '.substr($e->getMessage(), 0, 220), 'error');
            redir('targets',['tab'=>'targets']);
        }

        $r = writeAllConfig($db);
        logActivity($db, 'samengestelde_grafiek_opslaan', 'Grafiek opgeslagen: '.$title.' ('.count($members).' targets)');
        flash('Samengestelde grafiek opgeslagen. '.$r['msg'], $r['success'] ? 'success' : 'error');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='delete_custom_graph') {
        if (!hasActionPermission($db, 'act_graphs_manage')) { flash('Je hebt geen rechten om samengestelde grafieken te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $graphId = (int)($_POST['graph_id'] ?? 0);
        if ($graphId <= 0) { flash('Ongeldige grafiek geselecteerd.','error'); redir('targets',['tab'=>'targets']); }
        $stmt = $db->prepare('DELETE FROM custom_graphs WHERE id=:id');
        $stmt->bindValue(':id', $graphId, SQLITE3_INTEGER);
        $stmt->execute();
        $r = writeAllConfig($db);
        logActivity($db, 'samengestelde_grafiek_verwijderen', 'Grafiek verwijderd (ID '.$graphId.')');
        flash('Samengestelde grafiek verwijderd. '.$r['msg'], $r['success'] ? 'success' : 'error');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='edit_tgt') {
        if (!hasActionPermission($db, 'act_targets_edit')) { flash('Je hebt geen rechten om targets te bewerken.','error'); redir('targets',['tab'=>'targets']); }
        $targetId = (int)$_POST['id'];
        if (!canEditTarget($db, $targetId)) { flash('Je hebt geen rechten om deze target te bewerken.','error'); redir('targets',['tab'=>'targets']); }
        $cid=(int)$_POST['category_id'];
        $tid=(int)$_POST['id'];
        $displayName = trim((string)($_POST['display_name'] ?? ''));
        if ($displayName === '') { flash('Vul een naam in.','error'); redir('targets',['tab'=>'targets']); }
        $host = normalizeTargetHostValue($_POST['host'] ?? ''); $host_ipv6 = normalizeTargetHostValue($_POST['host_ipv6'] ?? '');
        if ($host === '' && $host_ipv6 === '') { flash('Vul minimaal een IPv4/hostname of IPv6 adres in.','error'); redir('targets',['tab'=>'targets']); }
        $probe = ''; // Always inherit probe from category
        $internalName = generateUniqueTargetName($db, $cid, $displayName, $tid);
        $sessionDuration = normalizeSessionDuration(trim((string)($_POST['session_duration'] ?? 'unlimited')));
        $sessionNotifyEnabled = isset($_POST['session_notify_enabled']) ? 1 : 0;
        $sessionNotifyEmail = trim((string)($_POST['session_notify_email'] ?? ''));
        if ($sessionNotifyEnabled) {
            if ($sessionNotifyEmail === '') $sessionNotifyEmail = getDefaultNotifyRecipientList($db);
            $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
            if ($sessionNotifyEmail === '') {
                flash('Vul een geldig e-mailadres in voor sessie notificaties (meerdere met komma).','error');
                redir('targets',['tab'=>'targets']);
            }
        }

        $oldQ=$db->prepare('SELECT session_duration, enabled, session_end_notified, menu_name, sort_order FROM targets WHERE id=:id');
        $oldQ->bindValue(':id',$tid,SQLITE3_INTEGER);
        $old=$oldQ->execute()->fetchArray(SQLITE3_ASSOC);
        $oldDur=normalizeSessionDuration((string)($old['session_duration'] ?? 'unlimited'));
        $wasDisabled=((int)($old['enabled'] ?? 1) === 0);
        $sessionWasEnded=((int)($old['session_end_notified'] ?? 0) === 1);
        $willBeEnabled=(isset($_POST['enabled']) ? 1 : 0) === 1;
        // Herstart sessie als: duur veranderd OF als target opnieuw geactiveerd wordt na beëindigd sessie
        $restartSession=($sessionDuration!=='unlimited' && ($sessionDuration!==$oldDur || ($wasDisabled && $sessionWasEnded && $willBeEnabled)));
        $sessionStartedAt=$restartSession ? date('Y-m-d H:i:s') : null;
        $sessionFallbackStart=date('Y-m-d H:i:s');
        $existingSortOrder = (int)($old['sort_order'] ?? 0);
    $allowedTgtIntervals = [5,10,15,30,240,480,1440,2880,10080];
    $outageIntervalRaw = (isset($_POST['outage_mail_interval']) && $_POST['outage_mail_interval'] !== '') ? (int)$_POST['outage_mail_interval'] : null;
    if ($outageIntervalRaw !== null && !in_array($outageIntervalRaw, $allowedTgtIntervals, true)) $outageIntervalRaw = null;
    $s=$db->prepare('UPDATE targets SET category_id=:c,name=:n,display_name=:d,host=:h,host_ipv6=:h6,probe=:p,menu_name=:m,remark=:r,alert=:a,session_duration=:sd,session_notify_enabled=:sne,session_notify_email=:snem,session_started_at=CASE WHEN :restart=1 THEN :ssa WHEN session_started_at IS NULL OR TRIM(session_started_at)="" THEN :sfallback ELSE session_started_at END,session_start_notified=CASE WHEN :restart=1 THEN 0 ELSE session_start_notified END,session_end_notified=CASE WHEN :restart=1 THEN 0 ELSE session_end_notified END,outage_mail_interval=:omi,sort_order=:s,enabled=:e,updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $s->bindValue(':c',$cid); $s->bindValue(':n',$internalName); $s->bindValue(':d',$displayName);
        $s->bindValue(':h',$host); $s->bindValue(':h6',$host_ipv6);
        $existingMenuName = (string)($old['menu_name'] ?? '');
        $s->bindValue(':p',$probe); $s->bindValue(':m',$existingMenuName);
        $s->bindValue(':r', normalizeTargetRemark($_POST['remark'] ?? null)); $s->bindValue(':a',trim($_POST['alert']??''));
        $s->bindValue(':sd',$sessionDuration);
        $s->bindValue(':sne',$sessionNotifyEnabled,SQLITE3_INTEGER);
        $s->bindValue(':snem',$sessionNotifyEmail,SQLITE3_TEXT);
        $s->bindValue(':restart',$restartSession?1:0,SQLITE3_INTEGER);
        $s->bindValue(':ssa',$sessionStartedAt,SQLITE3_TEXT);
        $s->bindValue(':sfallback',$sessionFallbackStart,SQLITE3_TEXT);
    $s->bindValue(':omi',$outageIntervalRaw,$outageIntervalRaw===null?SQLITE3_NULL:SQLITE3_INTEGER);
        $s->bindValue(':s',$existingSortOrder,SQLITE3_INTEGER); $s->bindValue(':e',isset($_POST['enabled'])?1:0);
        $s->bindValue(':id',$tid,SQLITE3_INTEGER);
        $s->execute();
        try { maybeSendSessionStartMail($db, $tid); } catch (\Throwable $e) {}
        $r=writeAllConfig($db);
        logActivity($db, 'target_bewerken', 'Target bewerkt: '.trim($_POST['display_name']??'').' (ID '.$tid.')');
        flash('Bijgewerkt. '.$r['msg']); redir('targets',['tab'=>'targets']);
    }
    if ($act==='clone_tgt') {
        if (!hasActionPermission($db, 'act_targets_add')) { flash('Je hebt geen rechten om targets te klonen.','error'); redir('targets',['tab'=>'targets']); }
        $sourceId = (int)($_POST['source_id'] ?? 0);
        if($sourceId <= 0) { flash('Ongeldig source target ID.','error'); redir('targets'); }
        if (!canEditTarget($db, $sourceId)) { flash('Je hebt geen rechten om dit target te klonen.','error'); redir('targets',['tab'=>'targets']); }
        $s = $db->prepare('SELECT * FROM targets WHERE id=:id');
        $s->bindValue(':id', $sourceId); 
        $source = $s->execute()->fetchArray(SQLITE3_ASSOC);
        if(!$source) { flash('Bron target niet gevonden.','error'); redir('targets'); }
        
        // Create clone with "_copy" suffix
        $newName = $source['name'] . '_copy';
        $counter = 1;
        $checkName = $db->prepare('SELECT COUNT(*) FROM targets WHERE category_id=:c AND name=:n');
        $checkName->bindValue(':c', $source['category_id']);
        $checkName->bindValue(':n', $newName);
        while($checkName->execute()->fetchArray()[0] > 0) {
            $counter++;
            $newName = $source['name'] . '_copy' . $counter;
            $checkName->reset();
            $checkName->bindValue(':c', $source['category_id']);
            $checkName->bindValue(':n', $newName);
        }
        
        $ins = $db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,alert,session_duration,session_notify_enabled,session_notify_email,session_started_at,session_start_notified,session_end_notified,sort_order,enabled,user_id) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:a,:sd,:sne,:snem,NULL,0,0,:s,:e,:uid)');
        $ins->bindValue(':c', $source['category_id']);
        $ins->bindValue(':n', $newName);
        $ins->bindValue(':d', $source['display_name'] . ' (copy)');
        $ins->bindValue(':h', $source['host']);
        $ins->bindValue(':h6', $source['host_ipv6']);
        $ins->bindValue(':p', $source['probe']);
        $ins->bindValue(':m', $source['menu_name']);
        $ins->bindValue(':r', normalizeTargetRemark($source['remark'] ?? null));
        $ins->bindValue(':a', $source['alert']);
        $ins->bindValue(':sd', $source['session_duration']);
        $ins->bindValue(':sne', $source['session_notify_enabled'], SQLITE3_INTEGER);
        $ins->bindValue(':snem', $source['session_notify_email']);
        $ins->bindValue(':s', $source['sort_order'] + 1);
        $ins->bindValue(':e', 0, SQLITE3_INTEGER); // Clone starts disabled
        $uid = isLoggedIn() ? (int)($_SESSION['uid'] ?? 0) : 0;
        $ins->bindValue(':uid', $uid, SQLITE3_INTEGER);
        $ins->execute();
        
        $r=writeAllConfig($db);
        logActivity($db, 'target_klonen', 'Target gekloond als "'.$newName.'"');
        flash('Target gekloond als "' . $newName . '". '.$r['msg']); 
        redir('targets',['tab'=>'overview']);
    }
    if ($act==='toggle_target_enabled') {
        if (!hasActionPermission($db, 'act_targets_toggle')) { flash('Je hebt geen rechten om targets in te schakelen.','error'); redir('targets',['tab'=>'targets']); }
        $targetId = (int)($_POST['target_id'] ?? 0);
        if ($targetId <= 0) { flash('Ongeldig target ID.','error'); redir('targets',['tab'=>'targets']); }
        $s = $db->prepare('SELECT enabled, submission_source FROM targets WHERE id=:id');
        $s->bindValue(':id', $targetId, SQLITE3_INTEGER);
        $row = $s->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$row) { flash('Target niet gevonden.','error'); redir('targets',['tab'=>'targets']); }
        $submissionSource = strtolower(trim((string)($row['submission_source'] ?? '')));
        $returnTab = 'targets';
        $canApprovePublicQueueAsUser = (getUserRole($db) === 'user' && (int)($row['enabled'] ?? 0) === 0 && $submissionSource === 'public_queue');
        if (!canEditTarget($db, $targetId) && !$canApprovePublicQueueAsUser) {
            flash('Je hebt geen rechten om dit target in te schakelen.','error');
            redir('targets',['tab'=>$returnTab]);
        }
        $newEnabled = ((int)($row['enabled'] ?? 0) === 1) ? 0 : 1;
        $u = $db->prepare('UPDATE targets SET enabled=:e, submission_source=CASE WHEN :e=1 THEN "" ELSE submission_source END, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $u->bindValue(':e', $newEnabled, SQLITE3_INTEGER);
        $u->bindValue(':id', $targetId, SQLITE3_INTEGER);
        $u->execute();
        $r = writeAllConfig($db);
        $actionLabel = $newEnabled === 1 ? 'geactiveerd' : 'gedeactiveerd';
        logActivity($db, 'target_toggle', 'Target ' . $actionLabel . ' (ID ' . $targetId . ')');
        flash('Target ' . $actionLabel . '. ' . $r['msg']);
        redir('targets',['tab'=>$returnTab]);
    }
    if ($act==='del_tgt') {
        if (!hasActionPermission($db, 'act_targets_delete')) { flash('Je hebt geen rechten om targets te verwijderen.','error'); redir('targets',['tab'=>'targets']); }
        $targetId = (int)$_POST['id'];
        if (!canEditTarget($db, $targetId)) { flash('Je hebt geen rechten om deze target te verwijderen.','error'); redir('targets',['tab'=>'targets']); }
        $cid=(int)$_POST['category_id']; $s=$db->prepare('DELETE FROM targets WHERE id=:id');
        $s->bindValue(':id',(int)$_POST['id']); $s->execute(); $r=writeAllConfig($db);
        logActivity($db, 'target_verwijderen', 'Target verwijderd (ID '.(int)$_POST['id'].')');
        flash('Verwijderd. '.$r['msg']); redir('targets',['tab'=>'targets']);
    }
    if ($act==='bulk_del_tgt') {
        if (!hasActionPermission($db, 'act_targets_delete')) { flash('Je hebt geen rechten om targets te verwijderen.','error'); redir('targets',['tab'=>'targets']); }
        $ids = $_POST['ids'] ?? [];
        if ((!is_array($ids) || empty($ids)) && !empty($_POST['bulk_ids'])) {
            $ids = array_filter(array_map('trim', explode(',', (string)$_POST['bulk_ids'])), static function($v) { return $v !== ''; });
        }
        if (!is_array($ids) || empty($ids)) {
            flash('Geen targets geselecteerd.','error');
            redir('targets',['tab'=>'targets']);
        }
        $cleanIds = [];
        foreach ($ids as $id) {
            $iid = (int)$id;
            if ($iid > 0 && canEditTarget($db, $iid)) $cleanIds[$iid] = $iid;
        }
        if (empty($cleanIds)) {
            flash('Geen targets geselecteerd die je mag verwijderen.','error');
            redir('targets',['tab'=>'targets']);
        }
        $placeholders = implode(',', array_fill(0, count($cleanIds), '?'));
        $stmt = $db->prepare('DELETE FROM targets WHERE id IN ('.$placeholders.')');
        $idx = 1;
        foreach ($cleanIds as $iid) {
            $stmt->bindValue($idx++, $iid, SQLITE3_INTEGER);
        }
        $stmt->execute();
        $r = writeAllConfig($db);
        logActivity($db, 'bulk_target_verwijderen', count($cleanIds).' targets verwijderd');
        flash(count($cleanIds).' target(s) verwijderd. '.$r['msg'], $r['success'] ? 'success' : 'error');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='bulk_edit_tgt') {
        if (!hasActionPermission($db, 'act_targets_edit')) { flash('Je hebt geen rechten om targets te bewerken.','error'); redir('targets',['tab'=>'targets']); }

        $idsRaw = $_POST['target_ids'] ?? [];
        if (!is_array($idsRaw) || empty($idsRaw)) {
            flash('Geen targets geselecteerd voor bulk-bewerking.','error');
            redir('targets',['tab'=>'targets']);
        }

        $ids = [];
        foreach ($idsRaw as $idRaw) {
            $iid = (int)$idRaw;
            if ($iid > 0) $ids[$iid] = $iid;
        }
        if (empty($ids)) {
            flash('Geen geldige targets gevonden voor bulk-bewerking.','error');
            redir('targets',['tab'=>'targets']);
        }

        $catMap = $_POST['be_category_id'] ?? [];
        $displayMap = $_POST['be_display_name'] ?? [];
        $hostMap = $_POST['be_host'] ?? [];
        $host6Map = $_POST['be_host_ipv6'] ?? [];
        $remarkMap = $_POST['be_remark'] ?? [];
        $alertMap = $_POST['be_alert'] ?? [];
        $durationMap = $_POST['be_session_duration'] ?? [];
        $notifyEnabledMap = $_POST['be_session_notify_enabled'] ?? [];
        $notifyMailMap = $_POST['be_session_notify_email'] ?? [];
        $sortMap = $_POST['be_sort_order'] ?? [];
        $enabledMap = $_POST['be_enabled'] ?? [];
        $outageIntervalMap = $_POST['be_outage_mail_interval'] ?? [];
        $allowedTgtIntervals = [5,10,15,30,240,480,1440,2880,10080];

        $rows = [];
        $errors = [];

        foreach ($ids as $id) {
            if (!canEditTarget($db, $id)) {
                $errors[] = 'Target ID '.$id.': je hebt geen rechten om dit target te bewerken.';
                continue;
            }
            $q = $db->prepare('SELECT id, category_id, display_name, host, host_ipv6, remark, alert, session_duration, session_notify_enabled, session_notify_email, session_end_notified, enabled, sort_order FROM targets WHERE id=:id');
            $q->bindValue(':id', $id, SQLITE3_INTEGER);
            $old = $q->execute()->fetchArray(SQLITE3_ASSOC);
            if (!$old) {
                $errors[] = 'Target ID '.$id.' bestaat niet meer.';
                continue;
            }

            $cid = isset($catMap[$id]) ? (int)$catMap[$id] : (int)$old['category_id'];
            $display = trim((string)($displayMap[$id] ?? $old['display_name']));
            $host = normalizeTargetHostValue($hostMap[$id] ?? $old['host']);
            $host6 = normalizeTargetHostValue($host6Map[$id] ?? $old['host_ipv6']);
            $remark = normalizeTargetRemark($remarkMap[$id] ?? $old['remark']);
            $alert = trim((string)($alertMap[$id] ?? $old['alert']));
            $sessionDuration = normalizeSessionDuration(trim((string)($durationMap[$id] ?? $old['session_duration'] ?? 'unlimited')));
            $sessionNotifyEnabled = isset($notifyEnabledMap[$id]) ? 1 : 0;
            $sessionNotifyEmail = trim((string)($notifyMailMap[$id] ?? $old['session_notify_email'] ?? ''));
            $sortOrder = isset($sortMap[$id]) ? (int)$sortMap[$id] : (int)$old['sort_order'];
            $enabled = isset($enabledMap[$id]) ? 1 : 0;
            $outageInterval = (isset($outageIntervalMap[$id]) && $outageIntervalMap[$id] !== '') ? (int)$outageIntervalMap[$id] : null;
            if ($outageInterval !== null && !in_array($outageInterval, $allowedTgtIntervals, true)) $outageInterval = null;

            if ($display === '') $display = (string)$old['display_name'];
            if ($host === '' && $host6 === '') {
                $errors[] = 'Target ID '.$id.' moet minimaal een IPv4/hostname of IPv6 host hebben.';
                continue;
            }

            if ($sessionNotifyEnabled) {
                if ($sessionNotifyEmail === '') $sessionNotifyEmail = getDefaultNotifyRecipientList($db);
                $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
                if ($sessionNotifyEmail === '') {
                    $errors[] = 'Target ID '.$id.' heeft notificatie aan, maar geen geldig e-mailadres.';
                    continue;
                }
            } else {
                $sessionNotifyEmail = normalizeEmailListString($sessionNotifyEmail);
            }

            $oldDur = normalizeSessionDuration((string)($old['session_duration'] ?? 'unlimited'));
            $wasDisabled = ((int)($old['enabled'] ?? 1) === 0);
            $sessionWasEnded = ((int)($old['session_end_notified'] ?? 0) === 1);
            $restartSession = ($sessionDuration !== 'unlimited' && ($sessionDuration !== $oldDur || ($wasDisabled && $sessionWasEnded && $enabled === 1)));

            $rows[] = [
                'id' => $id,
                'category_id' => $cid,
                'display_name' => $display,
                'host' => $host,
                'host_ipv6' => $host6,
                'remark' => $remark,
                'alert' => $alert,
                'session_duration' => $sessionDuration,
                'session_notify_enabled' => $sessionNotifyEnabled,
                'session_notify_email' => $sessionNotifyEmail,
                'sort_order' => $sortOrder,
                'enabled' => $enabled,
                'outage_mail_interval' => $outageInterval,
                'restart_session' => $restartSession ? 1 : 0,
                'session_started_at' => date('Y-m-d H:i:s'),
                'session_fallback_start' => date('Y-m-d H:i:s')
            ];
        }

        if (!empty($errors)) {
            flash('Bulk-bewerking afgebroken: '.implode(' | ', array_slice($errors, 0, 3)), 'error');
            redir('targets',['tab'=>'targets']);
        }

        $db->exec('BEGIN IMMEDIATE TRANSACTION');
        try {
            $upd = $db->prepare('UPDATE targets SET category_id=:c, display_name=:d, host=:h, host_ipv6=:h6, remark=:r, alert=:a, session_duration=:sd, session_notify_enabled=:sne, session_notify_email=:snem, session_started_at=CASE WHEN :restart=1 THEN :ssa WHEN session_started_at IS NULL OR TRIM(session_started_at)="" THEN :sfallback ELSE session_started_at END, session_start_notified=CASE WHEN :restart=1 THEN 0 ELSE session_start_notified END, session_end_notified=CASE WHEN :restart=1 THEN 0 ELSE session_end_notified END, sort_order=:s, enabled=:e, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
            $upd = $db->prepare('UPDATE targets SET category_id=:c, display_name=:d, host=:h, host_ipv6=:h6, remark=:r, alert=:a, session_duration=:sd, session_notify_enabled=:sne, session_notify_email=:snem, session_started_at=CASE WHEN :restart=1 THEN :ssa WHEN session_started_at IS NULL OR TRIM(session_started_at)="" THEN :sfallback ELSE session_started_at END, session_start_notified=CASE WHEN :restart=1 THEN 0 ELSE session_start_notified END, session_end_notified=CASE WHEN :restart=1 THEN 0 ELSE session_end_notified END, outage_mail_interval=:omi, sort_order=:s, enabled=:e, updated_at=CURRENT_TIMESTAMP WHERE id=:id');

            foreach ($rows as $row) {
                $upd->bindValue(':c', $row['category_id'], SQLITE3_INTEGER);
                $upd->bindValue(':d', $row['display_name'], SQLITE3_TEXT);
                $upd->bindValue(':h', $row['host'], SQLITE3_TEXT);
                $upd->bindValue(':h6', $row['host_ipv6'], SQLITE3_TEXT);
                $upd->bindValue(':r', $row['remark'], SQLITE3_TEXT);
                $upd->bindValue(':a', $row['alert'], SQLITE3_TEXT);
                $upd->bindValue(':sd', $row['session_duration'], SQLITE3_TEXT);
                $upd->bindValue(':sne', $row['session_notify_enabled'], SQLITE3_INTEGER);
                $upd->bindValue(':snem', $row['session_notify_email'], SQLITE3_TEXT);
                $upd->bindValue(':restart', $row['restart_session'], SQLITE3_INTEGER);
                $upd->bindValue(':ssa', $row['session_started_at'], SQLITE3_TEXT);
                $upd->bindValue(':sfallback', $row['session_fallback_start'], SQLITE3_TEXT);
                $upd->bindValue(':omi', $row['outage_mail_interval'], $row['outage_mail_interval'] === null ? SQLITE3_NULL : SQLITE3_INTEGER);
                $upd->bindValue(':s', $row['sort_order'], SQLITE3_INTEGER);
                $upd->bindValue(':e', $row['enabled'], SQLITE3_INTEGER);
                $upd->bindValue(':id', $row['id'], SQLITE3_INTEGER);
                $upd->execute();
            }

            $db->exec('COMMIT');
        } catch (Throwable $e) {
            $db->exec('ROLLBACK');
            flash('Bulk-bewerking mislukt: '.substr($e->getMessage(), 0, 220), 'error');
            redir('targets',['tab'=>'targets']);
        }

        $r = writeAllConfig($db);
        logActivity($db, 'bulk_target_bewerken', count($rows).' targets in een keer bijgewerkt');
        flash(count($rows).' target(s) in een keer opgeslagen. '.$r['msg'], $r['success'] ? 'success' : 'error');
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='reorder_targets') {
        if (!hasActionPermission($db, 'act_targets_move')) { flash('Je hebt geen rechten om volgorde te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $order = json_decode($_POST['order'] ?? '[]', true);
        if (!is_array($order) || empty($order)) {
            flash('Ongeldige sorteervolgorde.','error');
            redir('targets',['tab'=>'targets']);
            exit;
        }
        $upCat = $db->prepare('UPDATE categories SET sort_order=:s WHERE id=:id');
        $upTgt = $db->prepare('UPDATE targets SET category_id=:c, sort_order=:s WHERE id=:id');
        foreach ($order as $i => $catItem) {
            $cid = (int)($catItem['id'] ?? 0);
            if ($cid <= 0) continue;
            $upCat->bindValue(':s', $i * 10, SQLITE3_INTEGER);
            $upCat->bindValue(':id', $cid, SQLITE3_INTEGER);
            $upCat->execute();
            if (!empty($catItem['targets']) && is_array($catItem['targets'])) {
                foreach ($catItem['targets'] as $j => $tgtItem) {
                    $tid = (int)($tgtItem['id'] ?? 0);
                    if ($tid <= 0) continue;
                    $upTgt->bindValue(':c', $cid, SQLITE3_INTEGER);
                    $upTgt->bindValue(':s', $j * 10, SQLITE3_INTEGER);
                    $upTgt->bindValue(':id', $tid, SQLITE3_INTEGER);
                    $upTgt->execute();
                }
            }
        }
        $r=writeAllConfig($db);
        flash('Targets-volgorde opgeslagen. '.$r['msg'],$r['success']?'success':'error');
        redir('targets',['tab'=>'targets']);
    }
    // Reorder categories only
    if ($act==='reorder_categories') {
        if (!hasActionPermission($db, 'act_targets_move')) { flash('Je hebt geen rechten om volgorde te wijzigen.','error'); redir('targets',['tab'=>'targets']); }
        $order = json_decode($_POST['order'] ?? '[]', true);
        if (!is_array($order) || empty($order)) {
            flash('Ongeldige sorteervolgorde.','error');
            redir('targets',['tab'=>'categories']);
            exit;
        }
        $upCat = $db->prepare('UPDATE categories SET sort_order=:s WHERE id=:id');
        foreach ($order as $i => $catItem) {
            $cid = (int)($catItem['id'] ?? 0);
            if ($cid <= 0) continue;
            $upCat->bindValue(':s', $i * 10, SQLITE3_INTEGER);
            $upCat->bindValue(':id', $cid, SQLITE3_INTEGER);
            $upCat->execute();
        }
        $r=writeAllConfig($db);
        flash('Categorieën-volgorde opgeslagen. '.$r['msg'],$r['success']?'success':'error');
        redir('targets',['tab'=>'categories']);
    }
    // Move category up/down
    if ($act==='move_category') {
        if (!hasActionPermission($db, 'act_targets_move')) { flash('Je hebt geen rechten om categorieën te verplaatsen.','error'); redir('targets',['tab'=>'targets']); }
        $cid=(int)$_POST['category_id']; $dir=$_POST['direction']??'';
        if(!in_array($dir,['up','down'])) { flash('Ongeldige richting.','error'); redir('targets',['tab'=>'categories']); }
        $s=$db->prepare('SELECT sort_order FROM categories WHERE id=:id'); $s->bindValue(':id',$cid);
        $cur=$s->execute()->fetchArray(SQLITE3_ASSOC);
        if(!$cur) { flash('Categorie niet gevonden.','error'); redir('targets',['tab'=>'categories']); }
        $curSort=(int)$cur['sort_order'];
        if($dir==='up') {
            $s=$db->prepare('SELECT id,sort_order FROM categories WHERE sort_order<:s ORDER BY sort_order DESC LIMIT 1');
            $s->bindValue(':s',$curSort);
            $other=$s->execute()->fetchArray(SQLITE3_ASSOC);
            if($other) {
                $upd=$db->prepare('UPDATE categories SET sort_order=:s WHERE id=:id');
                $upd->bindValue(':s',(int)$other['sort_order']); $upd->bindValue(':id',$cid); $upd->execute();
                $upd->bindValue(':s',$curSort); $upd->bindValue(':id',(int)$other['id']); $upd->execute();
                $r=writeAllConfig($db); flash('Categorie verplaatst. '.$r['msg'],$r['success']?'success':'error');
            } else flash('Kan niet verder omhoog.','warning');
        } else {
            $s=$db->prepare('SELECT id,sort_order FROM categories WHERE sort_order>:s ORDER BY sort_order ASC LIMIT 1');
            $s->bindValue(':s',$curSort);
            $other=$s->execute()->fetchArray(SQLITE3_ASSOC);
            if($other) {
                $upd=$db->prepare('UPDATE categories SET sort_order=:s WHERE id=:id');
                $upd->bindValue(':s',(int)$other['sort_order']); $upd->bindValue(':id',$cid); $upd->execute();
                $upd->bindValue(':s',$curSort); $upd->bindValue(':id',(int)$other['id']); $upd->execute();
                $r=writeAllConfig($db); flash('Categorie verplaatst. '.$r['msg'],$r['success']?'success':'error');
            } else flash('Kan niet verder omlaag.','warning');
        }
        redir('targets',['tab'=>'categories']);
    }
    // Reset target RRD
    if ($act==='reset_target_rrd') {
        if (!hasActionPermission($db, 'act_rrd_manage')) { flash('Je hebt geen rechten om RRD data te resetten.','error'); redir('targets',['tab'=>'targets']); }
        $tid = (int)($_POST['target_id'] ?? 0);
        if ($tid <= 0) { flash('Ongeldig target ID.', 'error'); redir('targets', ['tab' => 'targets']); }
        
        $username = $_SESSION['uname'] ?? 'unknown';
        $result = resetTargetRRD($db, $tid, $username);
        
        if ($result['success']) {
            $backupMsg = !empty($result['backup']) ? (' Backup: ' . basename((string)$result['backup'])) : '';
            flash('Target RRD geslaagd gereset.' . $backupMsg, 'success');
        } else {
            flash('Fout bij reset: ' . $result['message'], 'error');
        }
        redir('targets', ['tab' => 'targets']);
    }
    if ($act==='reset_target_rrd_json') {
        if (!hasActionPermission($db, 'act_rrd_manage')) { header('Content-Type: application/json'); echo json_encode(['success'=>false,'message'=>'Geen rechten']); exit; }
        header('Content-Type: application/json');
        $tid = (int)($_POST['target_id'] ?? $_GET['target_id'] ?? 0);
        if ($tid <= 0) {
            echo json_encode(['status' => 'error', 'message' => 'Ongeldig target ID']);
            exit;
        }
        
        $username = $_SESSION['uname'] ?? 'unknown';
        $result = resetTargetRRD($db, $tid, $username);
        
        if ($result['success']) {
            echo json_encode([
                'status' => 'success',
                'message' => $result['message'],
                'backup' => !empty($result['backup']) ? basename((string)$result['backup']) : null
            ]);
        } else {
            echo json_encode(['status' => 'error', 'message' => $result['message']]);
        }
        exit;
    }
    // Sync targets from file
    if ($act==='sync_targets_from_file') {
        if (!hasActionPermission($db, 'act_config_manage')) { flash('Je hebt geen rechten om te syncen.','error'); redir('targets'); }
        $result = syncTargetsFromFile($db, true);
        if ($result['imported'] > 0) {
            $r = writeAllConfig($db);
            flash($result['msg'] . ' ' . $r['msg'], $result['success'] ? 'success' : 'error');
        } else {
            flash($result['msg'], $result['success'] ? 'success' : 'error');
        }
        redir('targets',['tab'=>'overview']);
    }
    if ($act==='backup_targets_file') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om een backup te maken.','error'); redir('settings',['stab'=>'instellingen']); }
        $bk = backupTargetsFileSnapshot('manual');
        flash($bk['msg'], $bk['success'] ? 'success' : 'error');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='restore_targets_file') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om te herstellen.','error'); redir('settings',['stab'=>'instellingen']); }
        $backupFile = basename((string)($_POST['backup_file'] ?? ''));
        $restorePath = targetsBackupDir().'/'.$backupFile;
        if ($backupFile === '' || !is_file($restorePath)) {
            flash('Targets backup niet gevonden.','error');
            redir('settings',['stab'=>'backups']);
        }
        $content = @file_get_contents($restorePath);
        if ($content === false || trim($content) === '') {
            flash('Kon Targets backup niet lezen.','error');
            redir('settings',['stab'=>'backups']);
        }
        $restoreRes = importTargetsConfigContent($db, $content, 'restore', $backupFile, true);
        flash('Targets backup teruggezet: '.$backupFile.'. '.$restoreRes['msg'], $restoreRes['success'] ? 'success' : 'error');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='download_targets_file_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om targets backups te downloaden.','error'); redir('settings',['stab'=>'instellingen']); }
        $backupFile = basename((string)($_POST['backup_file'] ?? ''));
        $downloadPath = targetsBackupDir().'/'.$backupFile;
        if ($backupFile === '' || !is_file($downloadPath)) {
            flash('Targets backup niet gevonden.','error');
            redir('settings',['stab'=>'backups']);
        }
        header('Content-Type: text/plain; charset=UTF-8');
        header('Content-Disposition: attachment; filename="'.$backupFile.'"');
        header('Content-Length: '.filesize($downloadPath));
        readfile($downloadPath);
        exit;
    }
    if ($act==='delete_targets_file_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups te verwijderen.','error'); redir('settings',['stab'=>'instellingen']); }
        $backupFile = basename((string)($_POST['backup_file'] ?? ''));
        $deletePath = targetsBackupDir().'/'.$backupFile;
        if ($backupFile === '' || !is_file($deletePath)) {
            flash('Targets backup niet gevonden.','error');
            redir('settings',['stab'=>'backups']);
        }
        if (!@unlink($deletePath)) {
            flash('Kon Targets backup niet verwijderen.','error');
            redir('settings',['stab'=>'backups']);
        }
            touchTargetsBackupVersionMarker();
        flash('Targets backup verwijderd: '.$backupFile, 'success');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='upload_targets_file_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om een Targets backup te uploaden.','error'); redir('settings',['stab'=>'instellingen']); }
        $uploadErr = $_FILES['targets_backup_upload']['error'] ?? UPLOAD_ERR_NO_FILE;
        if ($uploadErr === UPLOAD_ERR_NO_FILE) {
            flash('Selecteer eerst een Targets backup bestand.','error');
            redir('settings',['stab'=>'backups']);
        }
        if ($uploadErr !== UPLOAD_ERR_OK) {
            flash('Upload van Targets backup mislukt.','error');
            redir('settings',['stab'=>'backups']);
        }
        $content = @file_get_contents($_FILES['targets_backup_upload']['tmp_name']);
        if ($content === false || trim($content) === '') {
            flash('Kon het geuploade Targets backup bestand niet lezen.','error');
            redir('settings',['stab'=>'backups']);
        }
        $restoreAfterUpload = ($_POST['restore_after_upload'] ?? '0') === '1';
        if ($restoreAfterUpload) {
            $importRes = importTargetsConfigContent($db, $content, 'uploaded_restore', (string)($_FILES['targets_backup_upload']['name'] ?? ''), true);
            flash($importRes['msg'], $importRes['success'] ? 'success' : 'error');
            redir('settings',['stab'=>'backups']);
        }
        $storeRes = storeTargetsBackupContent($content, 'uploaded', (string)($_FILES['targets_backup_upload']['name'] ?? ''));
        flash(($storeRes['success'] ? $storeRes['msg'].' Gebruik Terugzetten om deze backup actief te maken.' : $storeRes['msg']), $storeRes['success'] ? 'success' : 'error');
        redir('settings',['stab'=>'backups']);
    }

    if ($act==='save_auto_backup_settings') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om automatische backups te wijzigen.','error'); redir('settings',['stab'=>'instellingen']); }
        $enabled = isset($_POST['auto_backup_enabled']) ? '1' : '0';
        $frequency = (string)($_POST['auto_backup_frequency'] ?? 'daily');
        if (!in_array($frequency, ['daily','weekly','monthly'], true)) $frequency = 'daily';
        $keepLatest = max(1, min(100, (int)($_POST['auto_backup_keep_latest'] ?? 10)));
        $retainDaily = max(0, min(365, (int)($_POST['auto_backup_retain_daily'] ?? 14)));
        $retainWeekly = max(0, min(104, (int)($_POST['auto_backup_retain_weekly'] ?? 8)));
        $retainMonthly = max(0, min(36, (int)($_POST['auto_backup_retain_monthly'] ?? 6)));
        setSetting($db, 'auto_backup_enabled', $enabled);
        setSetting($db, 'auto_backup_frequency', $frequency);
        setSetting($db, 'auto_backup_keep_latest', (string)$keepLatest);
        setSetting($db, 'auto_backup_retain_daily', (string)$retainDaily);
        setSetting($db, 'auto_backup_retain_weekly', (string)$retainWeekly);
        setSetting($db, 'auto_backup_retain_monthly', (string)$retainMonthly);
        flash('Automatische backup instellingen opgeslagen.', 'success');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='run_auto_backup_now') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om automatische backups uit te voeren.','error'); redir('settings',['stab'=>'instellingen']); }
        $res = createFullBackup('auto_manual');
        if (!empty($res['success'])) {
            $cfg = getAutoBackupSettings($db);
            $prune = pruneAutoFullBackups($cfg);
            $msg = ($res['msg'] ?? 'Automatische backup gestart.') . ' Opruimen verwijderd ' . (int)($prune['removed'] ?? 0) . ' oude auto-backups.';
            setSetting($db, 'auto_backup_last_run_at', date('Y-m-d H:i:s'));
            setSetting($db, 'auto_backup_last_result', $msg);
            logActivity($db, 'auto_backup', 'Handmatige auto-backup: ' . $msg);
            flash($msg, 'success');
        } else {
            $msg = (string)($res['msg'] ?? 'Automatische backup mislukt.');
            setSetting($db, 'auto_backup_last_result', $msg);
            flash($msg, 'error');
        }
        redir('settings',['stab'=>'backups']);
    }

    // Backup hardening helpers
    $isValidBackupName = static function(string $name): bool {
        return $name !== '' && (bool)preg_match('/^backup_[A-Za-z0-9._-]+$/', $name);
    };
    $tarEntriesAreSafe = static function(string $tarPath, array &$entries = null, string &$err = null): bool {
        $out = []; $rc = 1;
        @exec('/usr/bin/tar tzf '.escapeshellarg($tarPath).' 2>&1', $out, $rc);
        if ($rc !== 0) { $err = trim(implode("\n", $out)); return false; }
        $entries = [];
        foreach ($out as $line) {
            $entry = trim((string)$line);
            if ($entry === '' || $entry === '.' || $entry === './') continue;
            if ($entry[0] === '/' || strpos($entry, '..') !== false || strpos($entry, "\0") !== false) {
                $err = 'Onveilig pad gedetecteerd in archief: '.$entry;
                return false;
            }
            $entries[] = $entry;
        }
        if (empty($entries)) { $err = 'Archief bevat geen bestanden.'; return false; }
        return true;
    };
    $extractTarSafe = static function(string $tarPath, string $destDir, string &$err = null) use ($tarEntriesAreSafe): bool {
        $entries = [];
        if (!$tarEntriesAreSafe($tarPath, $entries, $err)) return false;
        $out = []; $rc = 1;
        @exec('/usr/bin/tar --no-same-owner --no-same-permissions -xzf '.escapeshellarg($tarPath).' -C '.escapeshellarg($destDir).' 2>&1', $out, $rc);
        if ($rc !== 0) { $err = trim(implode("\n", $out)); return false; }
        return true;
    };

    // Backup web
    if ($act==='backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups te maken.','error'); redir('settings',['stab'=>'instellingen']); }
        $res = createFullBackup('manual');
        if ($res['success']) {
            logActivity($db, 'backup_maken', $res['msg']);
            flash($res['msg'], 'success');
        } else {
            flash($res['msg'], 'error');
        }
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='restore') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups terug te zetten.','error'); redir('settings',['stab'=>'instellingen']); }
        $bname=$_POST['backup_name']??''; $bdir=BACKUP_DIR.'/'.$bname;
        if (!$isValidBackupName($bname)) {
            flash('Ongeldige backupnaam.','error');
            redir('settings',['stab'=>'backups']);
        }
        if(is_dir($bdir)) {
            $allowedConfig = array_fill_keys(array_merge(listEditableConfigFiles(), ['config']), true);
            foreach(glob($bdir.'/*') as $f) {
                $bn=basename($f);
                if($bn==='smokeping_manager.db') copy($f,DB_PATH);
                elseif($bn==='rrd_data.tar.gz') {
                    $extractErr = '';
                    if (!$extractTarSafe($f, SMOKEPING_DATA_DIR, $extractErr)) {
                        flash('RRD data niet teruggezet: ongeldig/onveilig archief. '.substr((string)$extractErr, 0, 180), 'error');
                    }
                }
                elseif(isset($allowedConfig[$bn])) copy($f,SMOKEPING_CONF_DIR.'/'.$bn);
            }
            @exec("chown -R smokeping:smokeping ".SMOKEPING_DATA_DIR);
            ensureRunDir();
            $syncMsg = '';
            if (is_file(SMOKEPING_TARGETS_FILE)) {
                $syncRes = syncTargetsFromFile($db, true);
                $syncMsg = ' '.$syncRes['msg'];
            }
            $r = writeAllConfig($db);
            logActivity($db, 'backup_herstellen', "Backup hersteld: $bname");
            flash("Backup $bname hersteld.".$syncMsg.' '.$r['msg'], $r['success'] ? 'success' : 'error');
        } else flash('Backup niet gevonden.','error');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='del_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups te verwijderen.','error'); redir('settings',['stab'=>'instellingen']); }
        $bname=$_POST['backup_name']??''; $bdir=BACKUP_DIR.'/'.$bname;
        if (!$isValidBackupName($bname)) {
            flash('Ongeldige backupnaam.','error');
            redir('settings',['stab'=>'backups']);
        }
        if(is_dir($bdir)) {
            if (function_exists('removeDirectoryRecursive')) removeDirectoryRecursive($bdir);
            else @exec("rm -rf ".escapeshellarg($bdir));
            logActivity($db, 'backup_verwijderen', "Backup verwijderd: $bname");
            flash("Backup $bname verwijderd."); }
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='download_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups te downloaden.','error'); redir('settings',['stab'=>'instellingen']); }
        $bname=$_POST['backup_name']??''; $bdir=BACKUP_DIR.'/'.$bname;
        if (!$isValidBackupName($bname)) {
            flash('Ongeldige backupnaam.','error');
            redir('settings',['stab'=>'backups']);
        }
        if(is_dir($bdir)) {
            $tarFile=tempnam(sys_get_temp_dir(),'backup_').'.tar.gz';
            @exec('tar czf '.escapeshellarg($tarFile).' -C '.escapeshellarg($bdir).' . 2>/dev/null', $out, $rc);
            if($rc===0 && file_exists($tarFile) && filesize($tarFile)>0) {
                header('Content-Type: application/gzip');
                header('Content-Disposition: attachment; filename="'.$bname.'.tar.gz"');
                header('Content-Length: '.filesize($tarFile));
                readfile($tarFile);
                @unlink($tarFile);
                exit;
            }
            @unlink($tarFile);
        }
        flash('Backup kan niet als tar.gz worden gedownload.','error');
        redir('settings',['stab'=>'backups']);
    }
    if ($act==='upload_backup') {
        if (!hasActionPermission($db, 'act_backups_manage')) { flash('Je hebt geen rechten om backups te uploaden.','error'); redir('settings',['stab'=>'instellingen']); }
        if(isset($_FILES['backup_tar']) && $_FILES['backup_tar']['error']===0) {
            $bname='backup_'.date('Ymd_His').'_uploaded';
            $bdir=BACKUP_DIR.'/'.$bname;
            mkdir($bdir,0750,true);
            $extractErr = '';
            $ok = $extractTarSafe((string)$_FILES['backup_tar']['tmp_name'], $bdir, $extractErr);
            if($ok) flash("Backup geüpload: $bname");
            else {
                if (function_exists('removeDirectoryRecursive')) removeDirectoryRecursive($bdir);
                else @exec('rm -rf '.escapeshellarg($bdir));
                flash('Ongeldig/onveilig tar.gz bestand. '.substr((string)$extractErr, 0, 160),'error');
            }
        } else {
            $err = isset($_FILES['backup_tar']['error']) ? (int)$_FILES['backup_tar']['error'] : UPLOAD_ERR_NO_FILE;
            $uploadMaxRaw = (string)ini_get('upload_max_filesize');
            $postMaxRaw = (string)ini_get('post_max_size');
            $msg = 'Upload mislukt.';
            if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
                $msg = 'Upload mislukt: bestand is te groot (upload_max_filesize='.$uploadMaxRaw.', post_max_size='.$postMaxRaw.').';
            } elseif ($err === UPLOAD_ERR_PARTIAL) {
                $msg = 'Upload mislukt: bestand is maar gedeeltelijk geüpload.';
            } elseif ($err === UPLOAD_ERR_NO_FILE) {
                $msg = 'Upload mislukt: geen bestand geselecteerd.';
            } elseif ($err === UPLOAD_ERR_NO_TMP_DIR) {
                $msg = 'Upload mislukt: tijdelijke uploadmap ontbreekt op de server.';
            } elseif ($err === UPLOAD_ERR_CANT_WRITE) {
                $msg = 'Upload mislukt: server kan niet naar schijf schrijven.';
            } elseif ($err === UPLOAD_ERR_EXTENSION) {
                $msg = 'Upload mislukt: upload geblokkeerd door een PHP-extensie.';
            }
            flash($msg,'error');
        }
        redir('settings',['stab'=>'backups']);
    }
    // Config bestanden bewerken
    if ($act==='save_config_file') {
        if (!hasActionPermission($db, 'act_config_manage')) { flash('Je hebt geen rechten om configuratiebestanden op te slaan.','error'); redir('settings',['stab'=>'configuratie']); }
        $file=$_POST['config_file']??'';
        $allowed=listEditableConfigFiles();
        if(in_array(basename($file),$allowed)) {
            $bn = basename($file);
            $path=SMOKEPING_CONF_DIR.'/'.$bn;
            $contentToWrite = (string)($_POST['content'] ?? '');
            $sanitizedTargets = null;
            if ($bn === 'Targets') {
                backupTargetsFileSnapshot('autosave');
                $sanitizedTargets = sanitizeTargetsContent($contentToWrite);
                $contentToWrite = $sanitizedTargets['content'];
            }
            $ok = @file_put_contents($path,$contentToWrite);
            if ($ok === false) {
                flash('Kon bestand niet opslaan. Controleer schrijfrechten.','error');
                redir('settings',['stab'=>'config','file'=>$bn]);
            }

            if ($bn === 'Targets') {
                $syncRes = syncTargetsFromFile($db, true);
                if (!$syncRes['success']) {
                    flash('Targets opgeslagen, maar auto-inladen mislukte: '.$syncRes['msg'],'error');
                    redir('settings',['stab'=>'config','file'=>$bn]);
                }
                $r = writeAllConfig($db);
                $cleanupMsg = (!empty($sanitizedTargets['changed']))
                    ? ' Sanity-cleanup toegepast (oude Multihost blokken/path-host regels verwijderd).'
                    : '';
                flash('Targets bestand opgeslagen.'.$cleanupMsg.' '.$syncRes['msg'].' '.$r['msg'], $r['success'] ? 'success' : 'error');
            } else {
                $r = doRestart();
                flash('Bestand opgeslagen. '.$r['msg'], $r['success'] ? 'success' : 'error');
            }
        } else flash('Ongeldig bestand.','error');
        redir('settings',['stab'=>'config','file'=>basename($file)]);
    }
    if ($act==='clear_rrd_web') {
        if (!hasActionPermission($db, 'act_rrd_manage')) { flash('Je hebt geen rechten om RRD data te wissen.','error'); redir('targets',['tab'=>'targets']); }
        $scope=$_POST['scope']??''; $catId=(int)($_POST['category_id']??0); $tgtId=(int)($_POST['target_id']??0);
        $cmd=''; $msg='';
        $logUser = $_SESSION['un'] ?? ($_SESSION['username'] ?? 'unknown');
        $logCat = 'unknown';
        $logTarget = 'unknown';
        $logRrd = SMOKEPING_DATA_DIR;
        if($scope==='all') {
            $cmd="sudo -n /usr/local/bin/smokeping-clear-rrd all";
            $msg='Alle RRD bestanden gewist.';
            $logCat = 'ALL';
            $logTarget = 'ALL';
            $logRrd = SMOKEPING_DATA_DIR . '/*/*.rrd';
        } elseif($scope==='category'&&$catId>0) {
            $s=$db->prepare('SELECT name FROM categories WHERE id=:id'); $s->bindValue(':id',$catId);
            $cat=$s->execute()->fetchArray(SQLITE3_ASSOC);
            if($cat) {
                $catName=safeName($cat['name']);
                $cmdParts=[];
                $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd category ".escapeshellarg($catName);

                // Also clear generated companion IPv6 category for this category.
                $ipv6CatName=safeName((string)$cat['name'].'_IPv6');
                $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd category ".escapeshellarg($ipv6CatName);

                // Also clear matching multihost targets (new and legacy naming variants).
                $ts=$db->prepare('SELECT name, host_ipv6 FROM targets WHERE category_id=:cid');
                $ts->bindValue(':cid',$catId,SQLITE3_INTEGER);
                $trs=$ts->execute();
                while($tr=$trs->fetchArray(SQLITE3_ASSOC)) {
                    $tn=safeName((string)($tr['name'] ?? ''));
                    if ($tn==='') continue;
                    $hasV6=trim((string)($tr['host_ipv6'] ?? ''))!=='';
                    if(!$hasV6) continue;

                    $base=safeName($catName.'_'.$tn);
                    $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg('Multihost_IPv4_IPv6') . " " . escapeshellarg($tn.'_v4_v6');
                    $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg('Multihost_IPv4_IPv6') . " " . escapeshellarg($base.'_ipv6');
                    $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg('Multihost_IPv4_IPv6') . " " . escapeshellarg($base.'_ipv4');

                    // Legacy location: IPv6 child target in source category.
                    $cmdParts[]="sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($catName) . " " . escapeshellarg($tn.'_v6');
                }

                $cmd=implode(' ; ',array_values(array_unique($cmdParts)));
                $msg='RRD bestanden voor categorie + IPv6 + Multihost gewist.';
                $logCat = $catName;
                $logTarget = '*';
                $logRrd = SMOKEPING_DATA_DIR . '/' . $catName . '/*.rrd, ' . SMOKEPING_DATA_DIR . '/' . $ipv6CatName . '/*.rrd, ' . SMOKEPING_DATA_DIR . '/Multihost_IPv4_IPv6/*.rrd';
            }
        } elseif($scope==='target'&&$tgtId>0&&$catId>0) {
            $s=$db->prepare('SELECT c.name as cname, t.name as tname, t.host_ipv6 as host_ipv6 FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.id=:id');
            $s->bindValue(':id',$tgtId);
            $t=$s->execute()->fetchArray(SQLITE3_ASSOC);
            if($t) {
                $catPath=safeName($t['cname']);
                $tgtPath=safeName($t['tname']);
                $hasV6 = trim((string)($t['host_ipv6'] ?? '')) !== '';

                $cmdParts = [];
                $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($catPath) . " " . escapeshellarg($tgtPath);

                $clearedPaths = [SMOKEPING_DATA_DIR . '/' . $catPath . '/' . $tgtPath . '.rrd'];
                if ($hasV6) {
                    $ipv6CatPath = safeName((string)$t['cname'] . '_IPv6');
                    $v6TargetPath = $tgtPath . '_v6';
                    $multiCatPath = 'Multihost_IPv4_IPv6';
                    $multiTargetPath = $tgtPath . '_v4_v6';
                    $multiLegacyBase = safeName($catPath . '_' . $tgtPath);

                    // Dual-stack companion targets are generated in <Category>_IPv6 and Multihost_IPv4_IPv6.
                    $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($ipv6CatPath) . " " . escapeshellarg($v6TargetPath);
                    $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($multiCatPath) . " " . escapeshellarg($multiTargetPath);

                    // Legacy variants from older generator versions.
                    $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($catPath) . " " . escapeshellarg($v6TargetPath);
                    $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($multiCatPath) . " " . escapeshellarg($multiLegacyBase . '_ipv6');
                    $cmdParts[] = "sudo -n /usr/local/bin/smokeping-clear-rrd target " . escapeshellarg($multiCatPath) . " " . escapeshellarg($multiLegacyBase . '_ipv4');

                    $clearedPaths[] = SMOKEPING_DATA_DIR . '/' . $ipv6CatPath . '/' . $v6TargetPath . '.rrd';
                    $clearedPaths[] = SMOKEPING_DATA_DIR . '/' . $multiCatPath . '/' . $multiTargetPath . '.rrd';
                    $clearedPaths[] = SMOKEPING_DATA_DIR . '/' . $catPath . '/' . $v6TargetPath . '.rrd';
                    $clearedPaths[] = SMOKEPING_DATA_DIR . '/' . $multiCatPath . '/' . $multiLegacyBase . '_ipv6.rrd';
                    $clearedPaths[] = SMOKEPING_DATA_DIR . '/' . $multiCatPath . '/' . $multiLegacyBase . '_ipv4.rrd';
                }

                $cmd = implode(' ; ', array_values(array_unique($cmdParts)));
                $msg = $hasV6
                    ? 'RRD bestanden voor target + IPv6 + Multihost gewist.'
                    : 'RRD bestand voor target gewist.';
                $logCat = $catPath;
                $logTarget = $tgtPath;
                $logRrd = implode(', ', $clearedPaths);
            }
        }
        if(!empty($cmd)) {
            $out=[]; $rc=0;
            @exec($cmd.' 2>&1', $out, $rc);
            $details = 'cmd=' . $cmd . ' | rc=' . $rc;
            if (!empty($out)) $details .= ' | out=' . substr(implode(' | ', $out), 0, 220);
            logRRDReset($db, $logUser, $logCat, $logTarget, $logRrd, 'clear', $rc===0?'success':'failed', $details);
            if ($rc===0) {
                $r=writeAllConfig($db);
                flash($msg.' '.$r['msg'], $r['success']?'success':'error');
            } else {
                flash('RRD wissen mislukt. '.$details, 'error');
            }
        }
        redir('targets',['tab'=>'targets']);
    }
    if ($act==='reload') { if (!hasActionPermission($db, 'act_config_manage')) { flash('Je hebt geen rechten om te herladen.','error'); redir('targets',['tab'=>'targets']); } $r=writeAllConfig($db); logActivity($db,'systeem_herladen','Configuratie herladen'); flash($r['msg'],$r['success']?'success':'error'); redir('targets',['tab'=>'targets']); }
    if ($act==='restart') { if (!hasActionPermission($db, 'act_config_manage')) { flash('Je hebt geen rechten om te herstarten.','error'); redir('targets',['tab'=>'targets']); } $r=doRestart(); logActivity($db,'systeem_herstart','SmokePing herstart'); flash($r['msg'],$r['success']?'success':'error'); redir('targets',['tab'=>'targets']); }
    if ($act==='set_user_page_permissions' && isAdmin($db)) {
        $pageKeys = ['targets','dashboard','database','settings','logging'];
        $actionKeys = array_keys(getActionPermissionDefinitions());
        // Track which users were updated
        $updatedUsers = [];
        if (!empty($_POST['present_user_ids']) && is_array($_POST['present_user_ids'])) {
            foreach ($_POST['present_user_ids'] as $rawUid) {
                $uid = (int)$rawUid;
                if ($uid > 0) $updatedUsers[$uid] = true;
            }
        }
        // Process all user permission updates from POST
        foreach ($_POST as $key => $val) {
            if (strpos($key, 'user_') === 0) {
                $parts = explode('_', $key, 3);
                if (count($parts) === 3) {
                    $userId = (int)$parts[1];
                    $pageKey = $parts[2];
                    if ($userId > 0 && (in_array($pageKey, $pageKeys, true) || in_array($pageKey, $actionKeys, true))) {
                        $updatedUsers[$userId] = true;
                        setPageVisibility($db, $userId, $pageKey, 1);
                    }
                }
            }
        }
        // For each user that was in the form, unset permissions for unchecked page/action keys
        $allPermissionKeys = array_merge($pageKeys, $actionKeys);
        foreach ($updatedUsers as $userId => $dummy) {
            foreach ($allPermissionKeys as $pageKey) {
                $fieldName = "user_${userId}_${pageKey}";
                if (!isset($_POST[$fieldName])) {
                    setPageVisibility($db, (int)$userId, $pageKey, 0);
                }
            }
        }
        flash('Permissions opgeslagen','success');
        redir('settings',['stab'=>'beheer','btab'=>'permissions']);
    }
    if ($act==='save_email_settings') {
        if (!hasActionPermission($db, 'act_mail_settings')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $s = $db->prepare('UPDATE email_settings SET smtp_enabled=:se, smtp_host=:sh, smtp_port=:sp, smtp_encryption=:sen, smtp_username=:su, smtp_password=:spw, smtp_from_email=:sfe, smtp_from_name=:sfn, alert_enabled=:ae, alert_threshold=:at, alert_interval_minutes=:aim, mail_threshold=:mt, alert_recipients=:ar, batch_outage_notifications=:bon, outage_mail_interval=:omi, ping_loss_notifications=:pln, updated_at=CURRENT_TIMESTAMP WHERE id=1');
        $s->bindValue(':se', isset($_POST['smtp_enabled'])?1:0, SQLITE3_INTEGER);
        $s->bindValue(':sh', $_POST['smtp_host']??'', SQLITE3_TEXT);
        $s->bindValue(':sp', (int)($_POST['smtp_port']??587), SQLITE3_INTEGER);
        $s->bindValue(':sen', $_POST['smtp_encryption']??'tls', SQLITE3_TEXT);
        $s->bindValue(':su', $_POST['smtp_username']??'', SQLITE3_TEXT);
        // Only update password if provided; always store encrypted
        if (!empty($_POST['smtp_password'])) {
            $s->bindValue(':spw', smEncryptPassword($_POST['smtp_password']), SQLITE3_TEXT);
        } else {
            $old = $db->query('SELECT smtp_password FROM email_settings WHERE id=1')->fetchArray();
            $existing = $old['smtp_password'] ?? '';
            // Migrate plaintext to encrypted on next save
            if ($existing !== '' && strpos($existing, 'enc:') !== 0) {
                $existing = smEncryptPassword($existing);
            }
            $s->bindValue(':spw', $existing, SQLITE3_TEXT);
        }
        // Use username as from_email if from_email is empty
        $fromEmail = $_POST['smtp_from_email']??'';
        if(empty($fromEmail)) $fromEmail = $_POST['smtp_username']??'';
        $s->bindValue(':sfe', $fromEmail, SQLITE3_TEXT);
        $s->bindValue(':sfn', $_POST['smtp_from_name']??'SmokePing Manager', SQLITE3_TEXT);
        $s->bindValue(':ae', isset($_POST['alert_enabled'])?1:0, SQLITE3_INTEGER);
        $s->bindValue(':at', (int)($_POST['alert_threshold']??95), SQLITE3_INTEGER);
        $s->bindValue(':aim', max(1,(int)($_POST['alert_interval_minutes']??15)), SQLITE3_INTEGER);
        $s->bindValue(':mt', max(0,(float)($_POST['mail_threshold']??5.0)), SQLITE3_FLOAT);
        $s->bindValue(':ar', normalizeEmailListString($_POST['alert_recipients']??''), SQLITE3_TEXT);
        $s->bindValue(':bon', isset($_POST['batch_outage_notifications'])?1:0, SQLITE3_INTEGER);
        $allowedOutageIntervals = [5,10,15,30,240,480,1440,2880,10080];
        $selectedOutageInterval = (int)($_POST['outage_mail_interval'] ?? 5);
        if (!in_array($selectedOutageInterval, $allowedOutageIntervals, true)) $selectedOutageInterval = 5;
        $s->bindValue(':omi', $selectedOutageInterval, SQLITE3_INTEGER);
        $s->bindValue(':pln', isset($_POST['ping_loss_notifications'])?1:0, SQLITE3_INTEGER);
        $s->execute();
        logActivity($db, 'email_instellingen', 'E-mail instellingen opgeslagen');
        flash('E-mail instellingen opgeslagen.','success');
        redir('settings',['stab'=>'instellingen']);
    }
    if ($act==='test_email') {
        header('Content-Type: application/json');
        if (!hasActionPermission($db, 'act_mail_use')) { echo json_encode(['success'=>false,'message'=>'Geen rechten']); exit; }
        
        $email = trim((string)($_POST['test_email'] ?? ($_POST['email'] ?? '')));
        if(empty($email) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(['success'=>false,'message'=>'Ongeldig e-mailadres']);
            exit;
        }
        
        // Build test email
        $subject = 'SmokePing Manager Test Email';
        $body = '<html><body>';
        $body .= '<h2>✅ Test Email van SmokePing Manager</h2>';
        $body .= '<p>Gefeliciteerd! Je SMTP configuratie werkt correct.</p>';
        $body .= '<p><strong>Verzonden op:</strong> ' . date('d-m-Y H:i:s') . '</p>';
        $body .= '<p><strong>Naar:</strong> ' . htmlspecialchars($email) . '</p>';
        $body .= '<hr>';
        $body .= '<p style="color:#666;font-size:12px;">Dit is een test email van SmokePing Manager om je SMTP instellingen te verifiëren.</p>';
        $body .= '</body></html>';
        
        $result = logAndSendEmail($db, $email, $subject, $body, 'test', 'SMTP test', false);

        echo json_encode($result);
        exit;
    }
    
    // Mail Log Actions
    if ($act==='clear_mail_log') {
        if (!hasActionPermission($db, 'act_mail_use')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $db->exec('DELETE FROM mail_log');
        flash('Mail log gewist.','success'); redir('settings',['stab'=>'email']);
    }
    if ($act==='cancel_queued_mail') {
        if (!hasActionPermission($db, 'act_mail_use')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $mailLogId = (int)($_POST['mail_log_id'] ?? 0);
        if ($mailLogId <= 0) {
            flash('Ongeldige wachtrijregel.','error');
            redir('settings',['stab'=>'email']);
        }
        $s = $db->prepare('UPDATE mail_log SET status="cancelled", message="Verzending geannuleerd door beheerder" WHERE id=:id AND status="pending"');
        $s->bindValue(':id', $mailLogId, SQLITE3_INTEGER);
        $s->execute();
        if ((int)$db->changes() > 0) {
            logActivity($db, 'mail_queue_cancel', 'Mail wachtrij-item geannuleerd: id=' . $mailLogId);
            flash('Mail uit de wachtrij verwijderd.','success');
        } else {
            flash('Mail stond niet meer in de wachtrij.','error');
        }
        redir('settings',['stab'=>'email']);
    }
    if ($act==='reset_notify_flag') {
        if (!hasActionPermission($db, 'act_mail_use')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $tid = (int)($_POST['target_id']??0);
        if ($tid > 0) {
            $s = $db->prepare('UPDATE targets SET session_start_notified=0 WHERE id=:id');
            $s->bindValue(':id',$tid,SQLITE3_INTEGER); $s->execute();
            flash('Notificatie-status gereset. Bij volgende sessie-opstart wordt opnieuw een start-mail gestuurd.','success');
        }
        redir('settings',['stab'=>'email']);
    }
    if ($act==='session_summary_now') {
        if (!hasActionPermission($db, 'act_mail_use')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $tid = (int)($_POST['target_id'] ?? 0);
        $returnTo = (string)($_POST['return_to'] ?? 'email');
        $doReturn = static function(string $type) use ($returnTo): void {
            if ($returnTo === 'targets') {
                redir('targets',['tab'=>'targets']);
            }
            redir('settings',['stab'=>'email']);
        };
        if ($tid <= 0) { flash('Ongeldig target ID.','error'); $doReturn('error'); }

        $q = $db->prepare('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.id=:id');
        $q->bindValue(':id', $tid, SQLITE3_INTEGER);
        $t = $q->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$t) { flash('Target niet gevonden.','error'); $doReturn('error'); }
        if ((int)($t['enabled'] ?? 0) !== 1) { flash('Target is niet actief. Start eerst een sessie.','error'); $doReturn('error'); }

        $dur = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
        $startedAt = getTargetSessionStartTs($t);
        $snapshotTs = time();
        if ($snapshotTs < $startedAt) $snapshotTs = $startedAt;

        $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
        if (empty($recipients)) {
            flash('Geen geldige ontvangers voor dit target.','error');
            $doReturn('error');
        }

        $hours = ($dur === 'unlimited') ? 24 : sessionDurationHours($dur);
        $st = getTargetStatus((string)$t['cat_name'], (string)$t['name']);
        $ut = getTargetUptime((string)$t['cat_name'], (string)$t['name'], $hours);
        $outageSummary = collectTargetOutageSummary($db, $t);
        $pingSummary = collectSessionPingLossSummary($db, $tid, $startedAt, $snapshotTs);
        $body = buildSessionSnapshotMailBody($t, $dur, $startedAt, $snapshotTs, $st, $ut, $outageSummary, $pingSummary, 'Tussenstand');

        $res = logAndSendEmailList($db, $recipients, 'SmokePing - Sessie tussenstand: ' . $t['display_name'], $body, 'session_summary', (string)$t['display_name']);
        flash(!empty($res['success']) ? 'Tussenstand-mail verzonden.' : 'Tussenstand-mail mislukt: '.($res['message'] ?? 'onbekende fout'), !empty($res['success']) ? 'success' : 'error');
        $doReturn('ok');
    }
    if ($act==='manual_end_session') {
        if (!hasActionPermission($db, 'act_mail_use')) { flash('Geen rechten','error'); redir('settings',['stab'=>'email']); }
        $tid = (int)($_POST['target_id'] ?? 0);
        $returnTo = (string)($_POST['return_to'] ?? 'email');
        $doReturn = static function() use ($returnTo): void {
            if ($returnTo === 'targets') {
                redir('targets',['tab'=>'targets']);
            }
            redir('settings',['stab'=>'email']);
        };
        if ($tid <= 0) { flash('Ongeldig target ID.','error'); $doReturn(); }

        $q = $db->prepare('SELECT t.*, c.display_name AS cat_display, c.name AS cat_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.id=:id');
        $q->bindValue(':id', $tid, SQLITE3_INTEGER);
        $t = $q->execute()->fetchArray(SQLITE3_ASSOC);
        if (!$t) { flash('Target niet gevonden.','error'); $doReturn(); }

        $dur = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
        $startedAt = getTargetSessionStartTs($t);
        $endTs = time();
        if ($endTs < $startedAt) $endTs = $startedAt;

        $notifyEnabled = (int)($t['session_notify_enabled'] ?? 0) === 1;
        $mailSent = false;
        if ($notifyEnabled) {
            $recipients = resolveNotifyRecipients($db, (string)($t['session_notify_email'] ?? ''));
            if (!empty($recipients)) {
                $hours = $dur === 'unlimited' ? 24 : sessionDurationHours($dur);
                $st = getTargetStatus((string)$t['cat_name'], (string)$t['name']);
                $ut = getTargetUptime((string)$t['cat_name'], (string)$t['name'], $hours);
                $outageSummary = collectTargetOutageSummary($db, $t);
                $pingSummary = collectSessionPingLossSummary($db, $tid, $startedAt, $endTs);
                $lossPct = $st['loss'] !== null ? round(((float)$st['loss']) * 100, 1) . '%' : 'n.v.t.';
                $median = $st['median'] !== null ? $st['median'] . ' ms' : 'n.v.t.';
                $uptime = $ut['uptime'] !== null ? $ut['uptime'] . '%' : 'n.v.t.';

                $body  = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:20px 0;background:#f1f5f9;font-family:\'Segoe UI\',Arial,sans-serif">';
                $body .= '<div style="max-width:620px;margin:0 auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,.10)">';
                $body .= '<div style="background:linear-gradient(135deg,#2563eb 0%,#1e3a8a 100%);padding:28px 32px">';
                $body .= '<div style="color:#fff;font-size:22px;font-weight:700">Sessie handmatig beëindigd</div>';
                $body .= '<div style="color:rgba(255,255,255,.75);font-size:13px;margin-top:5px">SmokePing Manager &mdash; Handmatige sessie-einde melding</div></div>';
                $body .= '<div style="padding:24px 32px">';
                if ($dur === 'unlimited') {
                    $body .= '<p style="margin:0 0 12px;color:#1e3a8a;font-size:14px"><strong>Deze sessie was onbeperkt en is handmatig beëindigd.</strong></p>';
                }
                $body .= '<table style="width:100%;border-collapse:collapse;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden">';
                $rows = [
                    ['Categorie', htmlspecialchars((string)$t['cat_display'])],
                    ['Target', '<strong>'.htmlspecialchars((string)$t['display_name']).'</strong>'],
                    ['Host', '<code style="background:#f3f4f6;padding:2px 6px;border-radius:4px">'.htmlspecialchars((string)$t['host']).'</code>'],
                    ['Sessieduur', htmlspecialchars(sessionDurationLabel($dur))],
                    ['Gestart op', date('d-m-Y H:i:s', $startedAt)],
                    ['Beëindigd op', date('d-m-Y H:i:s', $endTs)],
                    ['Packet loss', htmlspecialchars($lossPct)],
                    ['Median RTT', htmlspecialchars($median)],
                    ['Uptime', htmlspecialchars($uptime)],
                ];
                foreach ($rows as $i => $rowInfo) {
                    $bg = ($i % 2 === 0) ? '#f9fafb' : '#fff';
                    $body .= '<tr style="background:'.$bg.'"><td style="padding:8px 12px;font-size:12px;color:#6b7280;width:150px">'.$rowInfo[0].'</td><td style="padding:8px 12px;font-size:14px;color:#111827">'.$rowInfo[1].'</td></tr>';
                }
                $body .= '</table>';

                $events = is_array($outageSummary['events'] ?? null) ? $outageSummary['events'] : [];
                if (!empty($events)) {
                    $body .= '<div style="margin-top:14px;background:#fff7ed;border:1px solid #fdba74;border-radius:8px;padding:12px 14px">';
                    $body .= '<div style="font-size:13px;font-weight:700;color:#9a3412;margin-bottom:8px">Uitval tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#7c2d12;font-size:12px">';
                    foreach (array_slice($events, 0, 8) as $ev) {
                        $sTs = (int)($ev['started_at_ts'] ?? 0);
                        $eTsRaw = (int)($ev['ended_at_ts'] ?? 0);
                        $eTs = $eTsRaw > 0 ? $eTsRaw : $endTs;
                        $durSec = max(0, $eTs - $sTs);
                        if ($durSec >= 60) {
                            $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $sTs).' t/m '.date('d-m-Y H:i:s', $eTs).' ('.formatDurationSeconds($durSec).')</li>';
                        } else {
                            $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $sTs).' ('.formatDurationSeconds($durSec).')</li>';
                        }
                    }
                    $body .= '</ul></div>';
                }

                $pingGroups = is_array($pingSummary['groups'] ?? null) ? $pingSummary['groups'] : [];
                if (!empty($pingGroups)) {
                    $body .= '<div style="margin-top:14px;background:#fffbeb;border:1px solid #fcd34d;border-radius:8px;padding:12px 14px">';
                    $body .= '<div style="font-size:13px;font-weight:700;color:#92400e;margin-bottom:8px">Pingverlies tijdens sessie</div><ul style="margin:0 0 0 16px;padding:0;color:#78350f;font-size:12px">';
                    foreach (array_slice($pingGroups, 0, 10) as $pg) {
                        $gStart=(int)($pg['start_ts'] ?? 0); $gEnd=(int)($pg['end_ts'] ?? 0); $gCount=(int)($pg['count'] ?? 0);
                        $gDur=max(0,$gEnd-$gStart); $gMaxPct=round(((float)($pg['max_loss'] ?? 0))*100,1);
                        if ($gCount <= 1) {
                            $body .= '<li style="margin:3px 0">'.date('d-m-Y H:i:s', $gStart).' - pingverlies ('.$gMaxPct.'%)</li>';
                        } else {
                            $body .= '<li style="margin:3px 0">Van '.date('d-m-Y H:i:s', $gStart).' t/m '.date('d-m-Y H:i:s', $gEnd).' ('.formatDurationSeconds($gDur).', '.$gCount.' metingen, max '.$gMaxPct.'%)</li>';
                        }
                    }
                    $body .= '</ul></div>';
                }

                $body .= '</div><div style="background:#f9fafb;border-top:1px solid #e5e7eb;padding:14px 32px;text-align:center;font-size:11px;color:#9ca3af">SmokePing Manager &mdash; Handmatige sessie samenvatting</div></div></body></html>';

                $res = logAndSendEmailList($db, $recipients, 'SmokePing - Sessie handmatig beëindigd: ' . $t['display_name'], $body, 'session_end_manual', (string)$t['display_name']);
                $mailSent = !empty($res['success']);
            }
        }

        $closeOutage = $db->prepare('UPDATE target_outages SET ended_at=datetime(:et, "unixepoch"), duration_seconds=CASE WHEN duration_seconds IS NULL OR duration_seconds<=0 THEN (:et - strftime("%s", started_at)) ELSE duration_seconds END, is_open=0, end_source_ts=:et, updated_at=CURRENT_TIMESTAMP WHERE target_id=:tid AND is_open=1');
        $closeOutage->bindValue(':et', $endTs, SQLITE3_INTEGER);
        $closeOutage->bindValue(':tid', $tid, SQLITE3_INTEGER);
        $closeOutage->execute();

        $u = $db->prepare('UPDATE targets SET session_end_notified=1, enabled=0, session_started_at=NULL, session_start_notified=0, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $u->bindValue(':id', $tid, SQLITE3_INTEGER);
        $u->execute();

        logActivity($db, 'sessie_handmatig_beeindigd', 'Sessie handmatig beëindigd voor target ID '.$tid);
        flash($mailSent ? 'Sessie handmatig beëindigd en samenvatting verstuurd.' : 'Sessie handmatig beëindigd.', 'success');
        $doReturn();
    }

    // Alert Management Actions
    if ($act==='add_alert') {
        if (!hasActionPermission($db, 'act_alerts_manage')) { flash('Geen rechten','error'); redir('settings',['stab'=>'alerts']); }
        $s = $db->prepare('INSERT INTO alerts (name, display_name, type, threshold_loss, threshold_duration, notification_method, recipients, enabled) VALUES (:n, :d, :t, :tl, :td, :nm, :r, :e)');
        $s->bindValue(':n', trim($_POST['name']), SQLITE3_TEXT);
        $s->bindValue(':d', trim($_POST['display_name']), SQLITE3_TEXT);
        $s->bindValue(':t', $_POST['type']??'email', SQLITE3_TEXT);
        $s->bindValue(':tl', ((float)$_POST['threshold_loss'])/100, SQLITE3_FLOAT); // Convert percentage to decimal
        $s->bindValue(':td', (int)$_POST['threshold_duration'], SQLITE3_INTEGER);
        $s->bindValue(':nm', $_POST['notification_method']??'email', SQLITE3_TEXT);
        $s->bindValue(':r', trim($_POST['recipients']??''), SQLITE3_TEXT);
        $s->bindValue(':e', isset($_POST['enabled'])?1:0, SQLITE3_INTEGER);
        $s->execute();
        logActivity($db, 'alert_toevoegen', 'Alert toegevoegd: '.trim($_POST['display_name']??''));
        flash('Alert configuratie toegevoegd.','success');
        redir('settings',['stab'=>'alerts']);
    }
    if ($act==='edit_alert') {
        if (!hasActionPermission($db, 'act_alerts_manage')) { flash('Geen rechten','error'); redir('settings',['stab'=>'alerts']); }
        $s = $db->prepare('UPDATE alerts SET name=:n, display_name=:d, type=:t, threshold_loss=:tl, threshold_duration=:td, notification_method=:nm, recipients=:r, enabled=:e, updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $s->bindValue(':n', trim($_POST['name']), SQLITE3_TEXT);
        $s->bindValue(':d', trim($_POST['display_name']), SQLITE3_TEXT);
        $s->bindValue(':t', $_POST['type']??'email', SQLITE3_TEXT);
        $s->bindValue(':tl', ((float)$_POST['threshold_loss'])/100, SQLITE3_FLOAT);
        $s->bindValue(':td', (int)$_POST['threshold_duration'], SQLITE3_INTEGER);
        $s->bindValue(':nm', $_POST['notification_method']??'email', SQLITE3_TEXT);
        $s->bindValue(':r', trim($_POST['recipients']??''), SQLITE3_TEXT);
        $s->bindValue(':e', isset($_POST['enabled'])?1:0, SQLITE3_INTEGER);
        $s->bindValue(':id', (int)$_POST['id'], SQLITE3_INTEGER);
        $s->execute();
        logActivity($db, 'alert_bewerken', 'Alert bewerkt: '.trim($_POST['display_name']??'').' (ID '.(int)$_POST['id'].')');
        flash('Alert configuratie bijgewerkt.','success');
        redir('settings',['stab'=>'alerts']);
    }
    if ($act==='del_alert') {
        if (!hasActionPermission($db, 'act_alerts_manage')) { flash('Geen rechten','error'); redir('settings',['stab'=>'alerts']); }
        $s = $db->prepare('DELETE FROM alerts WHERE id=:id');
        $s->bindValue(':id', (int)$_POST['id'], SQLITE3_INTEGER);
        $s->execute();
        logActivity($db, 'alert_verwijderen', 'Alert verwijderd (ID '.(int)$_POST['id'].')');
        flash('Alert configuratie verwijderd.','success');
        redir('settings',['stab'=>'alerts']);
    }
    
    if ($act==='set_theme') {
        $th=$_POST['theme']??'auto';
        if(!in_array($th,['auto','light','dark'],true)) $th='auto';
        setSetting($db,'theme',$th);
        $sessionTimeout=$_POST['ui_session_timeout_hours']??'24';
        if(!in_array($sessionTimeout,['24','168','720'],true)) $sessionTimeout='24';
        setSetting($db,'ui_session_timeout_hours',$sessionTimeout);
        $fs=$_POST['fontsize']??'14';
        if(!in_array($fs,['10','12','14','16','18','20','22','24'],true)) $fs='14';
        setSetting($db,'fontsize',$fs);
        flash('Thema, sessieduur en lettergrootte bijgewerkt.');
        redir('settings',['stab'=>'instellingen']);
    }
    if ($act==='set_fontsize') {
        $fs=$_POST['fontsize']??'14';
        if(!in_array($fs,['10','12','14','16','18','20','22','24'],true)) $fs='14';
        setSetting($db,'fontsize',$fs);
        flash('Lettergrootte bijgewerkt.');
        redir('settings',['stab'=>'instellingen']);
    }
    if ($act==='save_google_auth_settings') {
        if (!isAdmin($db)) { flash('Geen rechten','error'); redir('settings',['stab'=>'instellingen']); }
        $enabled = isset($_POST['google_auth_enabled']) ? '1' : '0';
        $clientId = trim((string)($_POST['google_client_id'] ?? ''));
        $clientSecret = trim((string)($_POST['google_client_secret'] ?? ''));
        $redirectUri = trim((string)($_POST['google_redirect_uri'] ?? ''));
        if ($clientSecret === '') {
            $clientSecret = smDecryptPassword((string)getSetting($db, 'google_client_secret', ''));
        }
        if ($redirectUri === '') {
            $redirectUri = buildGoogleRedirectUri($db);
        }
        setSetting($db, 'google_auth_enabled', $enabled);
        setSetting($db, 'google_client_id', $clientId);
        setSetting($db, 'google_client_secret', smEncryptPassword($clientSecret));
        setSetting($db, 'google_redirect_uri', $redirectUri);
        logActivity($db, 'google_auth_instellingen', 'Google OAuth instellingen opgeslagen');
        flash('Google OAuth instellingen opgeslagen.', 'success');
        redir('settings',['stab'=>'instellingen']);
    }
    if ($act==='chpw') {
        $s=$db->prepare('SELECT password FROM users WHERE id=:id'); $s->bindValue(':id',$_SESSION['uid']);
        $row=$s->execute()->fetchArray(SQLITE3_ASSOC);
        $cur=$_POST['cur']??'';$new=$_POST['new']??'';$con=$_POST['con']??'';$nu=$_POST['newuser']??'';
        if(!$row||!password_verify($cur,$row['password'])) flash('Huidig wachtwoord onjuist.','error');
        elseif(!empty($new)&&strlen($new)<6) flash('Min. 6 tekens.','error');
        elseif(!empty($new)&&$new!==$con) flash('Wachtwoorden komen niet overeen.','error');
        else {
            if(!empty($new)){$s=$db->prepare('UPDATE users SET password=:p WHERE id=:id');$s->bindValue(':p',password_hash($new,PASSWORD_BCRYPT));$s->bindValue(':id',$_SESSION['uid']);$s->execute();}
            if(!empty($nu)){$s=$db->prepare('UPDATE users SET username=:u WHERE id=:id');$s->bindValue(':u',$nu);$s->bindValue(':id',$_SESSION['uid']);$s->execute();$_SESSION['uname']=$nu;}
            logActivity($db, 'wachtwoord_wijzigen', 'Eigen wachtwoord/gebruikersnaam gewijzigd');
            flash('Gegevens bijgewerkt!');
        }
        redir('settings',['stab'=>'account']);
    }
    // User Management - Only for admins
    if ($act==='add_user' && isAdmin($db)) {
        $u=trim((string)($_POST['username']??''));
        $mail=strtolower(trim((string)($_POST['email']??'')));
        $r=trim((string)($_POST['role']??'manager'));
        if(empty($u)||strlen($u)<3) { flash('Gebruikersnaam min. 3 tekens.','error'); redir('settings',['stab'=>'users']); }
        if(!filter_var($mail, FILTER_VALIDATE_EMAIL)) { flash('Vul een geldig e-mailadres in.','error'); redir('settings',['stab'=>'users']); }
        if(!in_array($r,['admin','manager','user','readonly'],true)) $r='manager';
        $s=$db->prepare('SELECT id FROM users WHERE username=:u'); $s->bindValue(':u',$u,SQLITE3_TEXT);
        if($s->execute()->fetchArray()) { flash('Gebruiker bestaat al.','error'); redir('settings',['stab'=>'users']); }
        $e=$db->prepare('SELECT id FROM users WHERE LOWER(TRIM(COALESCE(email, "")))=LOWER(:mail) AND id>0 LIMIT 1');
        $e->bindValue(':mail',$mail,SQLITE3_TEXT);
        if($e->execute()->fetchArray()) { flash('E-mailadres is al in gebruik.','error'); redir('settings',['stab'=>'users']); }
        $tempPassword = password_hash(bin2hex(random_bytes(24)), PASSWORD_BCRYPT);
        $s=$db->prepare('INSERT INTO users(username,password,email,role,auth_provider,approval_status,requested_at,approved_at) VALUES(:u,:p,:mail,:r,:ap,:st,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)');
        $s->bindValue(':u',$u,SQLITE3_TEXT);
        $s->bindValue(':p',$tempPassword,SQLITE3_TEXT);
        $s->bindValue(':mail',$mail,SQLITE3_TEXT);
        $s->bindValue(':r',$r,SQLITE3_TEXT);
        $s->bindValue(':ap','local',SQLITE3_TEXT);
        $s->bindValue(':st','active',SQLITE3_TEXT);
        $s->execute();
        $newUserId = (int)$db->lastInsertRowID();
        $invite = createUserInvite($db, $newUserId, $mail, (int)($_SESSION['uid'] ?? 0), 24 * 7);
        $mailRes = sendUserInviteMail($db, $u, $mail, $r, (string)$invite['url'], (string)$invite['expires_at']);
        logActivity($db, 'gebruiker_toevoegen', "Gebruiker toegevoegd: $u (rol: $r, e-mail: $mail)");
        if (!empty($mailRes['success'])) {
            flash('Gebruiker toegevoegd. Uitnodigingsmail is verzonden.','success');
        } else {
            flash('Gebruiker toegevoegd, maar mail verzenden is mislukt. Deel deze link handmatig: '.(string)$invite['url'],'error');
        }
        redir('settings',['stab'=>'users']);
    }
    if ($act==='approve_user' && isAdmin($db)) {
        $uid=(int)($_POST['user_id']??0);
        $res = updateUserApprovalState($db, $uid, 'active');
        if (!empty($res['success'])) {
            $s = $db->prepare('UPDATE users SET approval_status="active", approved_at=CURRENT_TIMESTAMP, approved_by=:by WHERE id=:id');
            $s->bindValue(':by', (int)$_SESSION['uid'], SQLITE3_INTEGER);
            $s->bindValue(':id', $uid, SQLITE3_INTEGER);
            $s->execute();
            logActivity($db, 'user_approved', 'Gebruiker goedgekeurd: ' . (string)$res['message'] . ' (ID ' . $uid . ')');
            flash('Gebruiker goedgekeurd!','success');
        } else {
            flash((string)($res['message'] ?? 'Gebruiker kon niet worden goedgekeurd'),'error');
        }
        redir('settings',['stab'=>'users']);
    }
    if ($act==='reject_user' && isAdmin($db)) {
        $uid=(int)($_POST['user_id']??0);
        $res = updateUserApprovalState($db, $uid, 'rejected');
        if (!empty($res['success'])) {
            logActivity($db, 'user_rejected', 'Gebruiker afgewezen: ' . (string)$res['message'] . ' (ID ' . $uid . ')');
            flash('Gebruiker afgewezen.','success');
        } else {
            flash((string)($res['message'] ?? 'Gebruiker kon niet worden afgewezen'),'error');
        }
        redir('settings',['stab'=>'users']);
    }
    if ($act==='edit_user' && isAdmin($db)) {
        $uid=(int)($_POST['user_id']??0); $u=trim((string)($_POST['username']??'')); $mail=strtolower(trim((string)($_POST['email']??''))); $r=trim((string)($_POST['role']??'manager'));
        if($uid<=0||$uid===$_SESSION['uid']) { flash('Kan jezelf niet wijzigen hier.','error'); redir('settings',['stab'=>'users']); }
        if(empty($u)||strlen($u)<3) { flash('Gebruikersnaam min. 3 tekens.','error'); redir('settings',['stab'=>'users']); }
        if(!filter_var($mail, FILTER_VALIDATE_EMAIL)) { flash('Vul een geldig e-mailadres in.','error'); redir('settings',['stab'=>'users']); }
        if(!in_array($r,['admin','manager','user','readonly'],true)) $r='manager';
        $s=$db->prepare('SELECT id FROM users WHERE username=:u AND id!=:id'); $s->bindValue(':u',$u); $s->bindValue(':id',$uid,SQLITE3_INTEGER);
        if($s->execute()->fetchArray()) { flash('Gebruikersnaam al in gebruik.','error'); redir('settings',['stab'=>'users']); }
        $e=$db->prepare('SELECT id FROM users WHERE LOWER(TRIM(COALESCE(email, "")))=LOWER(:mail) AND id!=:id LIMIT 1');
        $e->bindValue(':mail',$mail,SQLITE3_TEXT); $e->bindValue(':id',$uid,SQLITE3_INTEGER);
        if($e->execute()->fetchArray()) { flash('E-mailadres al in gebruik.','error'); redir('settings',['stab'=>'users']); }
        $s=$db->prepare('UPDATE users SET username=:u, email=:mail, role=:r WHERE id=:id');
        $s->bindValue(':u',$u,SQLITE3_TEXT); $s->bindValue(':mail',$mail,SQLITE3_TEXT); $s->bindValue(':r',$r,SQLITE3_TEXT); $s->bindValue(':id',$uid,SQLITE3_INTEGER); $s->execute();
        logActivity($db, 'gebruiker_bewerken', "Gebruiker bewerkt: $u (ID $uid, e-mail: $mail, rol: $r)");
        flash('Gebruiker bijgewerkt!'); redir('settings',['stab'=>'users']);
    }
    if ($act==='del_user' && isAdmin($db)) {
        $uid=(int)($_POST['user_id']??0);
        if($uid<=0||$uid===$_SESSION['uid']) { flash('Kan jezelf niet verwijderen.','error'); redir('settings',['stab'=>'users']); }
        $s=$db->prepare('DELETE FROM users WHERE id=:id'); $s->bindValue(':id',$uid,SQLITE3_INTEGER); $s->execute();
        logActivity($db, 'gebruiker_verwijderen', "Gebruiker verwijderd (ID $uid)");
        flash('Gebruiker verwijderd!'); redir('settings',['stab'=>'users']);
    }
    if ($act==='user_change_password' && isAdmin($db)) {
        $uid=(int)($_POST['user_id']??0); $p=trim($_POST['new_password']??'');
        if($uid<=0) { flash('Ongeldige gebruiker.','error'); redir('settings',['stab'=>'users']); }
        if(empty($p)||strlen($p)<6) { flash('Wachtwoord min. 6 tekens.','error'); redir('settings',['stab'=>'users']); }
        $s=$db->prepare('UPDATE users SET password=:p WHERE id=:id');
        $s->bindValue(':p',password_hash($p,PASSWORD_BCRYPT)); $s->bindValue(':id',$uid,SQLITE3_INTEGER); $s->execute();
        logActivity($db, 'wachtwoord_reset', "Wachtwoord gereset voor gebruiker ID $uid");
        flash('Wachtwoord bijgewerkt!'); redir('settings',['stab'=>'users']);
    }
    // Activity Log Settings
    if ($act==='save_log_settings' && isAdmin($db)) {
        $retentionDays = (int)($_POST['log_retention_days'] ?? 90);
        if ($retentionDays < 1) $retentionDays = 90;
        if ($retentionDays > 3650) $retentionDays = 3650;
        setSetting($db, 'log_email_enabled',  isset($_POST['log_email_enabled'])  ? '1' : '0');
        setSetting($db, 'log_email_address',  trim($_POST['log_email_address']??''));
        setSetting($db, 'log_auto_100',       isset($_POST['log_auto_100'])       ? '1' : '0');
        setSetting($db, 'log_auto_daily',     isset($_POST['log_auto_daily'])     ? '1' : '0');
        setSetting($db, 'log_retention_days', (string)$retentionDays);
        logActivity($db, 'log_instellingen', 'Logging instellingen opgeslagen');
        flash('Logging instellingen opgeslagen.','success');
        redir('settings',['stab'=>'logging']);
    }
    if ($act==='save_performance_settings' && isAdmin($db)) {
        setSetting($db, 'perf_monitor_enabled', isset($_POST['perf_monitor_enabled']) ? '1' : '0');
        setSetting($db, 'perf_debug_headers', isset($_POST['perf_debug_headers']) ? '1' : '0');
        flash('Performance instellingen opgeslagen.', 'success');
        redir('settings', ['stab'=>'performance']);
    }
    if ($act==='reset_performance_metrics' && isAdmin($db)) {
        @unlink(getPerfMetricsFilePath());
        flash('Performance statistieken zijn gereset.', 'success');
        redir('settings', ['stab'=>'performance']);
    }
    if ($act==='export_performance_metrics' && isAdmin($db)) {
        $stats = summarizePerformanceMetrics(86400);
        header('Content-Type: text/csv; charset=UTF-8');
        header('Content-Disposition: attachment; filename="performance_24h.csv"');
        echo "page,count,avg_ms,p95_ms,p99_ms\n";
        foreach ($stats['by_page'] as $pageKey => $info) {
            echo '"'.str_replace('"','""',(string)$pageKey).'",'.(int)($info['count'] ?? 0).','.round((float)($info['avg_ms'] ?? 0),2).','.round((float)($info['p95_ms'] ?? 0),2).','.round((float)($info['p99_ms'] ?? 0),2)."\n";
        }
        exit;
    }
    if ($act==='cleanup_logs_by_days' && isAdmin($db)) {
        $scope = (string)($_POST['scope'] ?? 'all');
        $retentionDays = (int)($_POST['retention_days'] ?? getSetting($db, 'log_retention_days', '90'));
        if ($retentionDays < 1) $retentionDays = 90;
        if ($retentionDays > 3650) $retentionDays = 3650;

        $map = [
            'activity_log' => ['table' => 'activity_log', 'whereOld' => 'created_at < datetime("now", :cutoff)'],
            'mail_log' => ['table' => 'mail_log', 'whereOld' => 'created_at < datetime("now", :cutoff)'],
            'target_outages' => ['table' => 'target_outages', 'whereOld' => 'COALESCE(updated_at, ended_at, started_at) < datetime("now", :cutoff)'],
            'target_ping_loss_events' => ['table' => 'target_ping_loss_events', 'whereOld' => 'created_at < datetime("now", :cutoff)'],
            'rrd_reset_logs' => ['table' => 'rrd_reset_logs', 'whereOld' => 'created_at < datetime("now", :cutoff)'],
        ];
        $scopes = ($scope === 'all') ? array_keys($map) : [$scope];
        $cutoff = '-' . $retentionDays . ' days';
        $deletedTotal = 0;

        foreach ($scopes as $sc) {
            if (!isset($map[$sc])) continue;
            $before = (int)$db->querySingle('SELECT COUNT(*) FROM '.$map[$sc]['table']);
            $del = $db->prepare('DELETE FROM '.$map[$sc]['table'].' WHERE '.$map[$sc]['whereOld']);
            $del->bindValue(':cutoff', $cutoff, SQLITE3_TEXT);
            $del->execute();
            $after = (int)$db->querySingle('SELECT COUNT(*) FROM '.$map[$sc]['table']);
            $deletedTotal += max(0, $before - $after);
        }

        setSetting($db, 'log_retention_days', (string)$retentionDays);
        logActivity($db, 'log_opschonen', 'Logs opgeschoond op bewaartermijn: '.$retentionDays.' dagen (scope='.$scope.', verwijderd='.$deletedTotal.')');
        flash('Log opschonen voltooid: '.$deletedTotal.' record(s) verwijderd (ouder dan '.$retentionDays.' dagen).', 'success');
        redir('settings',['stab'=>'logging']);
    }
    if ($act==='clear_log_scope' && isAdmin($db)) {
        $scope = (string)($_POST['scope'] ?? '');
        $map = [
            'activity_log' => 'activity_log',
            'mail_log' => 'mail_log',
            'target_outages' => 'target_outages',
            'target_ping_loss_events' => 'target_ping_loss_events',
            'rrd_reset_logs' => 'rrd_reset_logs',
        ];
        if (!isset($map[$scope])) {
            flash('Ongeldige logscope.','error');
            redir('settings',['stab'=>'logging']);
        }
        $table = $map[$scope];
        $before = (int)$db->querySingle('SELECT COUNT(*) FROM '.$table);
        $db->exec('DELETE FROM '.$table);
        logActivity($db, 'log_leegmaken', 'Log volledig geleegd: '.$scope.' (verwijderd='.$before.')');
        flash('Log volledig geleegd: '.$scope.' ('.$before.' record(s)).', 'success');
        redir('settings',['stab'=>'logging']);
    }
    if ($act==='clear_activity_log' && isAdmin($db)) {
        $db->exec('DELETE FROM activity_log');
        logActivity($db, 'log_gewist', 'Activiteiten log gewist door admin');
        flash('Activiteiten log gewist.','success');
        redir('settings',['stab'=>'logging']);
    }
    if ($act==='send_log_email' && isAdmin($db)) {
        $res = sendActivityLogEmail($db, 'Handmatig verzonden via beheerpagina');
        logActivity($db, 'log_mailen', 'Log handmatig per e-mail verzonden');
        flash($res['success'] ? 'Log e-mail verzonden: '.$res['msg'] : 'Verzenden mislukt: '.$res['msg'], $res['success'] ? 'success' : 'error');
        redir('settings',['stab'=>'logging']);
    }
}
function runDeferredWebMaintenance($db): array {
    $startedAt = microtime(true);
    $ran = [];

    try {
        processSessionEndNotifications($db);
        $ran[] = 'session_end';
    } catch (\Throwable $e) {}

    $nowTs = time();
    $trackEvery = 5;
    $notifyEvery = 10;

    $lastTrack = (int)getSetting($db, 'perf_last_outage_tracking_run', '0');
    if (($nowTs - $lastTrack) >= $trackEvery) {
        try {
            updateOutageTracking($db);
            $ran[] = 'outage_tracking';
        } catch (\Throwable $e) {}
        setSetting($db, 'perf_last_outage_tracking_run', (string)$nowTs);
    }

    $lastNotify = (int)getSetting($db, 'perf_last_notify_run', '0');
    if (($nowTs - $lastNotify) >= $notifyEvery) {
        try {
            processOutageNotifications($db);
            $ran[] = 'outage_notifications';
        } catch (\Throwable $e) {}
        try {
            processPingLossNotifications($db);
            $ran[] = 'ping_loss_notifications';
        } catch (\Throwable $e) {}
        setSetting($db, 'perf_last_notify_run', (string)$nowTs);
    }

    $lastAutoBackupCheck = (int)getSetting($db, 'perf_last_auto_backup_check', '0');
    if (($nowTs - $lastAutoBackupCheck) >= 300) {
        try {
            runAutoBackupIfDue($db, true);
            $ran[] = 'auto_backup_check';
        } catch (\Throwable $e) {}
        setSetting($db, 'perf_last_auto_backup_check', (string)$nowTs);
    }

    if (getSetting($db,'log_auto_daily','0')==='1') {
        $lastDaily = getSetting($db,'log_last_daily_email','');
        if (empty($lastDaily) || (time()-strtotime($lastDaily)) >= 86400) {
            try {
                sendActivityLogEmail($db,'Dagelijks automatisch verzonden');
                $ran[] = 'daily_log_mail';
            } catch (\Throwable $e) {}
            setSetting($db,'log_last_daily_email',date('Y-m-d H:i:s'));
        }
    }

    try {
        $queueRes = processPendingMailQueue($db, 10);
        if ((int)($queueRes['processed'] ?? 0) > 0) {
            $ran[] = 'mail_queue';
        }
    } catch (\Throwable $e) {}

    try {
        $recover = autoRecoverSmokePingStaleData($db);
        if (!empty($recover['restarted'])) {
            $ran[] = 'smokeping_auto_recover';
        }
    } catch (\Throwable $e) {}

    $elapsedMs = round((microtime(true) - $startedAt) * 1000, 2);
    $GLOBALS['SM_NOTIF_MS'] = $elapsedMs;
    smPerfSet('maintenance_ms', $elapsedMs);
    return ['ran' => $ran, 'ms' => $elapsedMs];
}
$flash=getFlash();
$flashHistory=getFlashHistory();
?>
<!DOCTYPE html>
<html lang="nl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title><?=APP_TITLE?></title>
<style>
:root{--bg:#111111;--s1:#242424;--s2:#2b2b2b;--s3:#343434;--brd:#454545;--tx:#ececec;--txd:#a6a6a6;--ac:#4bc56b;--ach:#69d985;--ok:#57cb74;--okbg:#1d3422;--okfg:#b8f1c6;--err:#d66b6b;--errbg:#3a2020;--errfg:#f2b7b7;--warn:#d1a85b;--warnbg:#3a2f1c;--warnfg:#f4d79b;--v6:#8ea1ff;--ring:0 0 0 2px rgba(75,197,107,.18);--r:10px;--font-adjust:0px;--shadow:0 16px 40px rgba(0,0,0,.32);--shadow-soft:0 8px 18px rgba(0,0,0,.22);--body-grad:radial-gradient(900px 440px at 20% -12%,rgba(255,255,255,.04),transparent 65%),radial-gradient(780px 360px at 100% 0,rgba(75,197,107,.09),transparent 58%),linear-gradient(180deg,#121212 0%,#0d0d0d 100%);--control-bg:#1d1d1d;--control-bg2:#181818;--control-opt-bg:#202020;--control-opt-fg:#f1f1f1;--header-bg:rgba(20,20,20,.9);--nav-shell-bg:rgba(35,35,35,.82);--brand-bg1:#4d4d4d;--brand-bg2:#2f2f2f;--brand-brd:#585858;--table-head-bg:#2b2b2b;--mobile-menu-bg1:#2f2f2f;--mobile-menu-bg2:#252525;--sidebar-bg1:rgba(35,35,35,.98);--sidebar-bg2:rgba(28,28,28,.98)}
body[data-theme='dark']{--bg:#0b0b0b;--s1:#1d1d1d;--s2:#262626;--s3:#303030;--brd:#3d3d3d;--tx:#f1f1f1;--txd:#9d9d9d;--ac:#57cf78;--ach:#74e092;--ok:#62d883;--okbg:#173221;--okfg:#c4f6d0;--err:#e07d7d;--errbg:#382020;--errfg:#f5c3c3;--warn:#ddb36b;--warnbg:#3a2f18;--warnfg:#f9dfab;--v6:#9cabff;--body-grad:radial-gradient(900px 440px at 20% -12%,rgba(255,255,255,.04),transparent 65%),radial-gradient(780px 360px at 100% 0,rgba(75,197,107,.09),transparent 58%),linear-gradient(180deg,#121212 0%,#0d0d0d 100%);--control-bg:#1d1d1d;--control-bg2:#181818;--control-opt-bg:#202020;--control-opt-fg:#f1f1f1;--header-bg:rgba(20,20,20,.9);--nav-shell-bg:rgba(35,35,35,.82);--brand-bg1:#4d4d4d;--brand-bg2:#2f2f2f;--brand-brd:#585858;--table-head-bg:#2b2b2b;--mobile-menu-bg1:#2f2f2f;--mobile-menu-bg2:#252525;--sidebar-bg1:rgba(35,35,35,.98);--sidebar-bg2:rgba(28,28,28,.98);color-scheme:dark}
body[data-theme='light']{--bg:#f4f7fb;--s1:#ffffff;--s2:#f2f6fb;--s3:#e8eef7;--brd:#cfd8e6;--tx:#18212f;--txd:#4f6076;--ac:#1d9748;--ach:#16783a;--ok:#2f9f5d;--okbg:#e8f8ef;--okfg:#1f6a37;--err:#c44f4f;--errbg:#fdecec;--errfg:#8b3131;--warn:#b8871f;--warnbg:#fff7e8;--warnfg:#725515;--v6:#3a5fd7;--body-grad:radial-gradient(920px 470px at 18% -15%,rgba(67,118,194,.16),transparent 62%),radial-gradient(740px 320px at 100% 0,rgba(29,151,72,.12),transparent 58%),linear-gradient(180deg,#f8fbff 0%,#eef3fb 100%);--control-bg:#ffffff;--control-bg2:#f7faff;--control-opt-bg:#ffffff;--control-opt-fg:#1d2a3b;--header-bg:rgba(255,255,255,.92);--nav-shell-bg:rgba(246,249,255,.96);--brand-bg1:#f8fbff;--brand-bg2:#e7edf8;--brand-brd:#c6d2e5;--table-head-bg:#edf2f8;--mobile-menu-bg1:#ffffff;--mobile-menu-bg2:#f2f6fd;--sidebar-bg1:rgba(255,255,255,.98);--sidebar-bg2:rgba(246,249,255,.98);--shadow:0 14px 34px rgba(32,52,84,.14);--shadow-soft:0 6px 14px rgba(32,52,84,.1);color-scheme:light}
@media (prefers-color-scheme: dark){body:not([data-theme]){--bg:#0b0b0b;--s1:#1d1d1d;--s2:#262626;--s3:#303030;--brd:#3d3d3d;--tx:#f1f1f1;--txd:#9d9d9d;--ac:#57cf78;--ach:#74e092;--ok:#62d883;--okbg:#173221;--okfg:#c4f6d0;--err:#e07d7d;--errbg:#382020;--errfg:#f5c3c3;--warn:#ddb36b;--warnbg:#3a2f18;--warnfg:#f9dfab;--v6:#9cabff;--body-grad:radial-gradient(900px 440px at 20% -12%,rgba(255,255,255,.04),transparent 65%),radial-gradient(780px 360px at 100% 0,rgba(75,197,107,.09),transparent 58%),linear-gradient(180deg,#121212 0%,#0d0d0d 100%);--control-bg:#1d1d1d;--control-bg2:#181818;--control-opt-bg:#202020;--control-opt-fg:#f1f1f1;--header-bg:rgba(20,20,20,.9);--nav-shell-bg:rgba(35,35,35,.82);--brand-bg1:#4d4d4d;--brand-bg2:#2f2f2f;--brand-brd:#585858;--table-head-bg:#2b2b2b;--mobile-menu-bg1:#2f2f2f;--mobile-menu-bg2:#252525;--sidebar-bg1:rgba(35,35,35,.98);--sidebar-bg2:rgba(28,28,28,.98);color-scheme:dark}}
*{margin:0;padding:0;box-sizing:border-box}
html,body{width:100%;height:100%;overflow-x:hidden}
body{font-family:'Segoe UI','Calibri','Trebuchet MS',sans-serif;background:var(--body-grad);color:var(--tx);min-height:100vh;line-height:1.45;font-size:13px;-webkit-tap-highlight-color:transparent;-webkit-font-smoothing:antialiased}
body[data-fontsize='10']{--font-adjust:-4px}body[data-fontsize='12']{--font-adjust:-2px}body[data-fontsize='14']{--font-adjust:0px}body[data-fontsize='16']{--font-adjust:2px}body[data-fontsize='18']{--font-adjust:5px}body[data-fontsize='20']{--font-adjust:7px}body[data-fontsize='22']{--font-adjust:9px}body[data-fontsize='24']{--font-adjust:11px}
button,a,input,select,textarea{touch-action:manipulation}
a{color:var(--ac);text-decoration:none}a:hover{color:var(--ach)}
select{-webkit-appearance:none;-moz-appearance:none;appearance:none;background-image:linear-gradient(45deg,transparent 50%,var(--txd) 50%),linear-gradient(135deg,var(--txd) 50%,transparent 50%),linear-gradient(180deg,var(--control-bg),var(--control-bg2));background-position:calc(100% - 18px) calc(50% - 3px),calc(100% - 12px) calc(50% - 3px),0 0;background-size:6px 6px,6px 6px,100% 100%;background-repeat:no-repeat;padding-right:34px;color:var(--tx)}
select:hover{border-color:color-mix(in srgb,var(--ac) 38%,var(--brd))}
select option,select optgroup{background:var(--control-opt-bg);color:var(--control-opt-fg)}
select:disabled{opacity:.7;cursor:not-allowed}
.hd{backdrop-filter:blur(10px);background:var(--header-bg);border-bottom:1px solid var(--brd);padding:3px 10px;min-height:50px;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:18px;position:sticky;top:0;z-index:250;box-shadow:0 14px 36px rgba(0,0,0,.24)}
.hd h1{font-size:calc(16px + var(--font-adjust));color:var(--ac);display:flex;align-items:center;gap:10px;font-weight:700}.hd h1::before{content:none}
@keyframes versionGlow{0%,100%{box-shadow:0 0 8px rgba(66,165,245,.4),0 0 16px rgba(66,165,245,.2),inset 0 1px 0 rgba(255,255,255,.04);text-shadow:0 0 8px rgba(66,165,245,.3)}50%{box-shadow:0 0 12px rgba(66,165,245,.6),0 0 24px rgba(66,165,245,.35),inset 0 1px 0 rgba(255,255,255,.06);text-shadow:0 0 12px rgba(66,165,245,.5)}}
.hd .ver{font-size:calc(12px + var(--font-adjust));color:var(--tx);margin-left:6px;padding:4px 9px;border-radius:10px;border:1px solid #001d35;background:linear-gradient(180deg,rgba(66,165,245,.12),rgba(66,165,245,.08));box-shadow:0 0 8px rgba(66,165,245,.4),0 0 16px rgba(66,165,245,.2),inset 0 1px 0 rgba(255,255,255,.04);animation:versionGlow 3s ease-in-out infinite;font-weight:600}
.brand-mark{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:9px;background:linear-gradient(180deg,var(--brand-bg1),var(--brand-bg2));border:1px solid var(--brand-brd);color:var(--txd);font-size:15px;line-height:1;box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.brand-mark{position:relative;cursor:help}
.brand-mark::after{content:attr(data-tip);position:absolute;left:0;top:calc(100% + 8px);transform:translateY(-3px);width:max-content;min-width:240px;max-width:min(320px,calc(100vw - 28px));padding:8px 10px;border-radius:8px;border:1px solid color-mix(in srgb,var(--ac) 35%,var(--brd));background:linear-gradient(180deg,var(--s1),var(--s2));color:var(--tx);font-size:11px;font-weight:600;line-height:1.35;white-space:normal;pointer-events:none;opacity:0;visibility:hidden;transition:opacity .16s ease,transform .16s ease,visibility .16s ease;z-index:420;box-shadow:var(--shadow-soft)}
.brand-mark::before{content:'';position:absolute;left:12px;top:calc(100% + 3px);border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:6px solid color-mix(in srgb,var(--ac) 35%,var(--brd));opacity:0;visibility:hidden;transition:opacity .16s ease,visibility .16s ease;z-index:421}
.brand-mark:hover::after,.brand-mark:hover::before,.brand-mark:focus-visible::after,.brand-mark:focus-visible::before{opacity:1;visibility:visible}
.brand-mark:hover::after,.brand-mark:focus-visible::after{transform:translateY(0)}
.brand-mark.ok{color:var(--ok)}
.brand-mark.err{color:var(--err)}
@media(max-width:640px){
.brand-mark::after{left:-4px;min-width:200px;max-width:calc(100vw - 16px)}
.brand-mark::before{left:14px}
}
.hd-tip{position:relative}
.hd-tip::after{content:attr(data-tip);position:absolute;left:50%;top:calc(100% + 8px);transform:translateX(-50%) translateY(-3px);width:max-content;min-width:220px;max-width:min(340px,calc(100vw - 24px));padding:8px 10px;border-radius:8px;border:1px solid color-mix(in srgb,var(--ac) 35%,var(--brd));background:linear-gradient(180deg,var(--s1),var(--s2));color:var(--tx);font-size:11px;font-weight:600;line-height:1.35;white-space:normal;pointer-events:none;opacity:0;visibility:hidden;transition:opacity .16s ease,transform .16s ease,visibility .16s ease;z-index:420;box-shadow:var(--shadow-soft)}
.hd-tip::before{content:'';position:absolute;left:50%;top:calc(100% + 3px);transform:translateX(-50%);border-left:6px solid transparent;border-right:6px solid transparent;border-bottom:6px solid color-mix(in srgb,var(--ac) 35%,var(--brd));opacity:0;visibility:hidden;transition:opacity .16s ease,visibility .16s ease;z-index:421}
.hd-tip:hover::after,.hd-tip:hover::before,.hd-tip:focus-visible::after,.hd-tip:focus-visible::before{opacity:1;visibility:visible}
.hd-tip:hover::after,.hd-tip:focus-visible::after{transform:translateX(-50%) translateY(0)}
@media(max-width:640px){
.hd-tip::after{min-width:190px;max-width:calc(100vw - 16px)}
}
.brand-text{display:flex;flex-direction:column;line-height:1.05}
.brand-title{font-size:calc(14px + var(--font-adjust));font-weight:800;color:var(--tx);letter-spacing:.02em}
.brand-sub{font-size:calc(10px + var(--font-adjust));color:var(--txd);font-weight:700;letter-spacing:.18em;text-transform:uppercase}
.brand-alert{display:inline-flex;align-items:center;gap:6px;padding:6px 10px;border-radius:999px;border:1px solid color-mix(in srgb,var(--err) 52%,var(--brd));background:linear-gradient(180deg,color-mix(in srgb,var(--err) 28%,#3a2323),color-mix(in srgb,var(--err) 18%,#281919));color:var(--errfg);font-size:calc(11px + var(--font-adjust));font-weight:900;letter-spacing:.06em;text-transform:uppercase;box-shadow:0 0 0 1px color-mix(in srgb,var(--err) 20%,transparent),0 0 18px color-mix(in srgb,var(--err) 25%,transparent);animation:brand-alert-pulse 1.3s ease-in-out infinite}
.brand-alert-dot{width:8px;height:8px;border-radius:50%;background:var(--err);box-shadow:0 0 8px color-mix(in srgb,var(--err) 60%,transparent)}
@keyframes brand-alert-pulse{0%,100%{transform:translateY(0);box-shadow:0 0 0 1px color-mix(in srgb,var(--err) 20%,transparent),0 0 18px color-mix(in srgb,var(--err) 25%,transparent)}50%{transform:translateY(-1px);box-shadow:0 0 0 1px color-mix(in srgb,var(--err) 35%,transparent),0 0 24px color-mix(in srgb,var(--err) 40%,transparent)}}
.hd-nav{display:flex;align-items:center;justify-content:center;flex-wrap:wrap;justify-self:center;border-radius:10px;background:var(--nav-shell-bg);border:1px solid var(--brd);box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}
.hd-nav a{padding:8px 13px;min-height:36px;border-radius:9px;font-size:calc(14px + var(--font-adjust));border:1px solid transparent;cursor:pointer;color:var(--txd);background:transparent;transition:.14s;font-family:inherit;display:flex;align-items:center;gap:7px;text-decoration:none;font-weight:600;white-space:nowrap}
.hd-nav a:hover{background:var(--s2);color:var(--tx);border-color:var(--brd)}
.hd-nav .on{background:linear-gradient(180deg,#3c3c3c,#2a2a2a);color:var(--ac)!important;font-weight:700;border-color:#5a5a5a;box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.hd-right{display:flex;align-items:center;gap:8px;margin-left:auto}
.hd-right .top-nav-actions{display:flex;gap:6px;align-items:center;margin-left:0;flex-wrap:wrap}
.hd-right .bt{min-height:32px;padding:6px 10px;font-size:12px}
.hd-right form{margin:0}
.hd-mobile-toggle{display:none;align-items:center;justify-content:center;gap:8px;min-height:38px;padding:0 12px;border-radius:10px;border:1px solid var(--brd);background:linear-gradient(180deg,#333,#252525);color:var(--tx);font-size:13px;font-weight:700;cursor:pointer}
.hd-mobile-toggle .menu-ico{font-size:16px;line-height:1}
.hd-mobile-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.48);z-index:320}
.hd-mobile-menu{display:none;position:fixed;left:10px;right:10px;top:calc(58px + env(safe-area-inset-top));max-height:calc(100dvh - 68px - env(safe-area-inset-top));overflow:auto;background:linear-gradient(180deg,var(--mobile-menu-bg1),var(--mobile-menu-bg2));border:1px solid var(--brd);border-radius:14px;padding:12px;z-index:330;box-shadow:var(--shadow)}
.hd-mobile-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px;padding-bottom:10px;border-bottom:1px solid var(--brd)}
.hd-mobile-title{font-size:12px;font-weight:800;letter-spacing:.08em;text-transform:uppercase;color:var(--txd)}
.hd-mobile-links,.hd-mobile-actions{display:grid;grid-template-columns:1fr;gap:8px}
.hd-mobile-links a,.hd-mobile-actions .bt{width:100%;min-height:42px;padding:10px 12px;font-size:calc(13px + var(--font-adjust));font-weight:700;text-align:left}
.hd-mobile-links a,.hd-mobile-actions .bt{display:grid;grid-template-columns:18px minmax(0,1fr);align-items:center;column-gap:8px}
.hd-mobile-links a{border-radius:10px;border:1px solid var(--brd);background:linear-gradient(180deg,#333,#292929);color:var(--tx)}
.hd-mobile-actions form{margin:0}
.hd-mobile-menu .top-nav-ic{display:inline-flex;align-items:center;justify-content:center;width:18px;line-height:1}
.hd-mobile-links a.on{border-color:color-mix(in srgb,var(--ac) 55%,var(--brd));color:var(--ac)}
body.mobile-menu-open{overflow:hidden}
body.mobile-menu-open .hd-mobile-overlay,body.mobile-menu-open .hd-mobile-menu{display:block}
.sp-status{display:flex;align-items:center;gap:6px;padding:7px 12px;border-radius:999px;font-size:calc(11px + var(--font-adjust));font-weight:700;border:1px solid transparent;white-space:nowrap;background:linear-gradient(180deg,#2c2c2c,#232323);box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
.sp-status.ok{background:var(--okbg);color:var(--okfg);border-color:color-mix(in srgb,var(--ok) 35%,transparent)}
.sp-status.err{background:var(--errbg);color:var(--errfg);border-color:color-mix(in srgb,var(--err) 35%,transparent)}
.sp-status .sp-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}.sp-status.ok .sp-dot{background:var(--ok)}.sp-status.err .sp-dot{background:var(--err)}
@media(max-width:480px){.sp-status .sp-lbl{display:none}.brand-sub{display:none}}
.hm-notif,.hm-info{display:inline-flex;align-items:center;justify-content:center;min-height:40px;border-radius:10px;border:1px solid var(--brd);background:var(--s1);color:var(--txd);cursor:pointer;transition:.18s}
.hm-notif{min-width:40px;padding:0 10px;font-size:calc(18px + var(--font-adjust));background:var(--s2)}
.hm-info{min-width:34px;padding:0 8px;font-size:calc(14px + var(--font-adjust));background:var(--s2)}
.hm-notif:hover,.hm-info:hover{border-color:var(--ac);color:var(--ac)}
.notif-help-step{background:var(--s2);padding:12px;border-radius:8px;margin-bottom:12px;border-left:3px solid var(--ac)}
.notif-help-step strong{display:block;margin-bottom:6px;color:var(--ac)}
.notif-help-step code{background:var(--bg);padding:2px 6px;border-radius:4px;font-family:'Consolas','Cascadia Mono',monospace;font-size:calc(12px + var(--font-adjust))}
.app{width:100%;margin:0;padding:8px;display:grid;grid-template-columns:300px minmax(0,1fr);gap:8px;align-items:start}
.sd{background:linear-gradient(180deg,var(--sidebar-bg1),var(--sidebar-bg2));border:1px solid var(--brd);border-radius:14px;display:flex;flex-direction:column;max-height:calc(100vh - 102px);height:calc(100vh - 102px);overflow-y:auto;overflow-x:hidden;box-shadow:var(--shadow)}
.top-nav{background:linear-gradient(180deg,var(--s1),var(--s2));border:1px solid var(--brd);padding:9px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:1px -1px 8px;border-radius:12px;box-shadow:var(--shadow-soft)}
.top-nav-links{display:flex;gap:8px;flex-wrap:wrap;align-items:center;flex:1 1 auto}
.top-nav-actions{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-left:auto}
.top-nav-note{display:inline-flex;align-items:center;min-height:32px;padding:6px 10px;border:1px solid color-mix(in srgb,var(--warn) 40%,var(--brd));border-radius:999px;background:color-mix(in srgb,var(--warn) 12%,var(--s2));color:var(--warnfg);font-size:11px;font-weight:700}
.top-nav a,.top-nav button{padding:9px 12px;min-height:36px;border-radius:9px;font-size:calc(13px + var(--font-adjust));border:1px solid transparent;cursor:pointer;color:var(--txd);background:transparent;transition:.14s;font-family:inherit;display:flex;align-items:center;gap:8px;text-decoration:none;font-weight:600}
.top-nav a:hover,.top-nav button:hover{background:var(--s2);color:var(--tx);border-color:var(--brd)}
.top-nav .on{background:linear-gradient(180deg,#3a3a3a,#292929);color:var(--ac)!important;font-weight:700;border-color:#5a5a5a;box-shadow:inset 0 1px 0 rgba(255,255,255,.05)}
.top-nav .danger,.hd-right .danger{color:var(--err)}
.top-nav .danger:hover,.hd-right .danger:hover{background:var(--errbg)!important;color:var(--errfg)!important;border-color:color-mix(in srgb,var(--err) 40%,transparent)!important}
.top-nav .troubleshoot-btn,.hd-right .troubleshoot-btn{background:linear-gradient(180deg,#4d4d4d,#373737);color:#f3f3f3;border:1px solid #5b5b5b;font-weight:700;box-shadow:inset 0 1px 0 rgba(255,255,255,.06)}
.top-nav .troubleshoot-btn:hover,.hd-right .troubleshoot-btn:hover{filter:brightness(1.06);border-color:#6a6a6a;color:#fff;background:linear-gradient(180deg,#5a5a5a,#414141)}
.top-nav-ic{font-size:14px;line-height:1}
.sd-info{padding:10px;border:1px solid var(--brd);border-radius:12px;background:linear-gradient(180deg,#2d2d2d,#252525);display:flex;flex-direction:column;flex:1 1 auto;min-height:0;overflow:hidden;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}
.sd-info-title{font-size:10px;font-weight:800;color:var(--txd);text-transform:uppercase;letter-spacing:.18em;margin-bottom:8px}
.sd-info-list{display:flex;flex-direction:column;gap:6px;flex:1 1 auto;min-height:0;overflow-y:auto;padding-right:2px}
.sd,.sd-info-list{scrollbar-width:thin;scrollbar-color:#4f4f4f #191919}
.sd::-webkit-scrollbar,.sd-info-list::-webkit-scrollbar{width:10px;height:10px}
.sd::-webkit-scrollbar-track,.sd-info-list::-webkit-scrollbar-track{background:#191919;border-radius:999px}
.sd::-webkit-scrollbar-thumb,.sd-info-list::-webkit-scrollbar-thumb{background:linear-gradient(180deg,#4f4f4f,#383838);border-radius:999px;border:2px solid #191919}
.sd::-webkit-scrollbar-thumb:hover,.sd-info-list::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,#616161,#444)}
.sd-info-item{border:1px solid var(--brd);border-left:3px solid var(--brd);border-radius:10px;background:linear-gradient(180deg,#303030,#262626);padding:8px 9px}
.sd-info-item.success{border-left-color:var(--ok)}.sd-info-item.error{border-left-color:var(--err)}
.sd-info-item-meta{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px;font-size:10px;color:var(--txd)}
.sd-info-item-type{font-weight:700;text-transform:uppercase;letter-spacing:.25px}
.sd-info-item-text{font-size:11px;line-height:1.35;color:var(--tx);word-break:break-word}
.sd-info-empty{font-size:11px;color:var(--txd);line-height:1.35}
.pf{margin-left:auto;position:relative;flex:0 0 auto}
.pf-btn{padding:0 11px;min-height:40px;border-radius:10px;border:1px solid var(--brd);background:linear-gradient(180deg,var(--s1),#1f1f1f);color:var(--txd);font-size:calc(16px + var(--font-adjust));cursor:pointer;box-shadow:inset 0 1px 0 rgba(255,255,255,.04)}
.pf-btn:hover{border-color:var(--ac);color:var(--ac)}
.pf-menu{display:none;position:absolute;right:0;top:calc(100% + 8px);min-width:200px;background:linear-gradient(180deg,var(--s1),#1f1f1f);border:1px solid var(--brd);border-radius:12px;box-shadow:var(--shadow);padding:8px;z-index:120}
.pf.open .pf-menu{display:block}
.pf-item{display:flex;align-items:center;width:100%;min-height:40px;text-align:left;padding:9px 11px;border-radius:8px;color:var(--txd);font-size:calc(14px + var(--font-adjust));background:transparent;border:none;cursor:pointer;text-decoration:none}
.pf-item:hover{background:var(--s2);color:var(--tx)}
.pf-logout{margin-top:10px;padding-top:10px;border-top:1px solid var(--brd)}.pf-logout button{width:100%;justify-content:flex-start}
.ct{max-width:none;margin:0;padding:0;min-width:0}
.fl{padding:11px 13px;border-radius:10px;margin-bottom:12px;font-size:calc(13px + var(--font-adjust));border:1px solid}
.fl.success{background:var(--okbg);border-color:color-mix(in srgb,var(--ok) 38%,transparent);color:var(--okfg)}
.fl.error{background:var(--errbg);border-color:color-mix(in srgb,var(--err) 40%,transparent);color:var(--errfg)}
.cd{background:linear-gradient(180deg,var(--s1),#202020);border:1px solid var(--brd);border-radius:14px;padding:7px 7px;margin-bottom:7px;content-visibility:auto;contain-intrinsic-size:220px;box-shadow:var(--shadow-soft)}
.cd-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}.cd-row .cd{margin-bottom:0}
.cd-t{font-size:calc(14px + var(--font-adjust));font-weight:700;margin-bottom:12px;padding-bottom:9px;border-bottom:1px solid var(--brd);color:var(--tx);letter-spacing:.02em}
.dash-hero{background:linear-gradient(180deg,#2f2f2f 0%,#242424 100%);border:1px solid #4d4d4d;border-radius:14px;padding:16px 18px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:16px;box-shadow:var(--shadow)}
.dash-hero-main{flex:1 1 auto;min-width:0}.dash-hero h2{font-size:calc(22px + var(--font-adjust));margin-bottom:6px;color:var(--tx)}.dash-hero p{font-size:calc(13px + var(--font-adjust));color:var(--txd);max-width:860px}
.dash-links{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.dash-hero .dash-links{margin-top:0;justify-content:flex-end;align-self:center;flex:0 0 auto}
.dash-stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-bottom:12px}
.dash-stat{background:linear-gradient(180deg,#2f2f2f,#242424);border:1px solid var(--brd);border-radius:12px;padding:13px 14px;min-width:0;box-shadow:var(--shadow-soft)}
.dash-stat-value{font-size:calc(24px + var(--font-adjust));font-weight:800;color:var(--tx);line-height:1.05}
.dash-stat-label{font-size:calc(11px + var(--font-adjust));color:var(--txd);margin-top:6px;text-transform:uppercase;letter-spacing:.08em}
.dash-sections{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
.dash-summary{font-size:calc(12px + var(--font-adjust));color:var(--txd);margin-bottom:10px}.dash-list{display:flex;flex-direction:column;gap:8px}.dash-item{display:flex;gap:7px;font-size:calc(12px + var(--font-adjust));color:var(--tx)}.dash-item::before{content:'•';color:var(--ac);font-weight:800;flex-shrink:0}
.admin-scroll-pane{max-height:420px;overflow:auto;border:1px solid var(--brd);border-radius:12px;background:linear-gradient(180deg,var(--s1),#202020)}
.admin-scroll-pane table{width:100%;border-collapse:collapse}.admin-scroll-pane thead{position:sticky;top:0;z-index:1;background:var(--s2)}
.fg{margin-bottom:8px}.fg label{display:block;font-size:calc(13px + var(--font-adjust));color:var(--txd);margin-bottom:4px;font-weight:700}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:9px}.fr3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:9px}
input[type=text],input[type=password],input[type=email],input[type=number],select,textarea{width:100%;padding:9px 11px;min-height:36px;background:linear-gradient(180deg,var(--control-bg),var(--control-bg2));border:1px solid var(--brd);border-radius:10px;color:var(--tx);font-size:calc(13px + var(--font-adjust));font-family:inherit;box-shadow:inset 0 1px 0 rgba(255,255,255,.03)}
input[type=file].file-input{width:100%;padding:8px;border:1px solid var(--brd);border-radius:10px;background:linear-gradient(180deg,var(--control-bg),var(--control-bg2));color:var(--tx);font-size:calc(13px + var(--font-adjust))}
input[type=file].file-input::file-selector-button{margin-right:10px;padding:8px 12px;border:none;border-radius:7px;background:var(--ac);color:#fff;cursor:pointer;font-family:inherit}
input[type=file].file-input::file-selector-button:hover{background:var(--ach)}
textarea{resize:vertical;min-height:120px;font-family:'Consolas','Cascadia Mono',monospace;font-size:calc(13px + var(--font-adjust))}
/* Ensure font-size preference applies to form field content on every page, even where local CSS/inline styles set fixed sizes. */
input[type=text],
input[type=password],
input[type=email],
input[type=number],
input[type=search],
input[type=url],
input[type=tel],
input[type=file],
select,
textarea,
input[type=file].file-input,
input[type=file].file-input::file-selector-button{font-size:calc(13px + var(--font-adjust)) !important}
input::placeholder,
textarea::placeholder{font-size:inherit}
select option,
select optgroup{font-size:calc(13px + var(--font-adjust))}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--ac);box-shadow:var(--ring)}
.bt{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:8px 12px;min-height:32px;min-width:58px;border-radius:10px;font-size:calc(12px + var(--font-adjust));font-weight:700;letter-spacing:.02em;border:1px solid #555;cursor:pointer;transition:.14s;font-family:inherit;box-shadow:inset 0 1px 0 rgba(255,255,255,.04);background:linear-gradient(180deg,#353535,#272727);color:var(--tx)}
.bt:hover{background:linear-gradient(180deg,#404040,#2e2e2e);color:var(--tx);border-color:#666}
.google-signin{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:10px;width:100%;min-height:42px;padding:10px 14px;border-radius:8px;border:1px solid #dadce0;background:#ffffff;color:#3c4043!important;font-size:14px;font-weight:700;letter-spacing:.01em;text-decoration:none;box-shadow:0 1px 2px rgba(60,64,67,.2);transition:box-shadow .16s ease,border-color .16s ease,transform .16s ease}
.google-signin:hover{background:#ffffff;border-color:#c6c9cc;color:#202124!important;box-shadow:0 2px 6px rgba(60,64,67,.28);transform:translateY(-1px)}
.google-signin:focus-visible{outline:none;border-color:#4285f4;box-shadow:0 0 0 3px rgba(66,133,244,.25)}
.google-signin:active{transform:translateY(0);box-shadow:0 1px 2px rgba(60,64,67,.24)}
.google-signin .g-icon{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;flex-shrink:0}
.google-signin .g-label{line-height:1.2}
.google-signin.is-disabled,.google-signin:disabled{cursor:not-allowed;opacity:.62;color:#6f7275!important;box-shadow:none;transform:none;pointer-events:none}
.login-divider{display:flex;align-items:center;gap:10px;margin:16px 0;color:var(--txd);font-size:11px}.login-divider::before,.login-divider::after{content:'';flex:1;height:1px;background:var(--brd)}.login-divider span{white-space:nowrap;text-transform:uppercase;letter-spacing:.08em;font-weight:700}
.bp{background:linear-gradient(180deg,var(--ac),#379a51);border-color:#4fb968;color:#fff}.bp:hover{background:linear-gradient(180deg,var(--ach),#42a95d)}
.bd{background:linear-gradient(180deg,#c85d5d,#aa4646);border-color:#d17b7b;color:#fff}.bd:hover{background:linear-gradient(180deg,#d87272,#b95454)}
.bg{background:linear-gradient(180deg,#353535,#272727);color:var(--txd);border:1px solid #555}.bg:hover{background:linear-gradient(180deg,#404040,#2e2e2e);color:var(--tx)}
.bo{background:linear-gradient(180deg,#ae8750,#8a693c);border-color:#bf9a63;color:#fff}.bo:hover{background:linear-gradient(180deg,#bd955b,#987242)}
.bs{background:linear-gradient(180deg,#4ebc69,#37944e);border-color:#5dca78;color:#fff}.bs:hover{background:linear-gradient(180deg,#5acb77,#41a55b)}
.bw{background:linear-gradient(180deg,#8d7447,#6f5b37);border-color:#a18757;color:#fff}.bw:hover{background:linear-gradient(180deg,#9a8050,#7b643d)}
.bsm{padding:6px 9px;font-size:calc(11px + var(--font-adjust))}
body[data-theme='light'] .hd-mobile-links a{background:linear-gradient(180deg,#ffffff,#f2f6fd)}
body[data-theme='light'] .top-nav .troubleshoot-btn,body[data-theme='light'] .hd-right .troubleshoot-btn{background:linear-gradient(180deg,#f8fbff,#eaf1fb);color:#26354a;border-color:#c8d4e6;box-shadow:inset 0 1px 0 rgba(255,255,255,.85)}
body[data-theme='light'] .top-nav .troubleshoot-btn:hover,body[data-theme='light'] .hd-right .troubleshoot-btn:hover{background:linear-gradient(180deg,#ffffff,#eef4fd);border-color:#b9c9df;color:#1b2a3f}
body[data-theme='light'] .sd-info{background:linear-gradient(180deg,#ffffff,#f3f7ff)}
body[data-theme='light'] .dash-hero{background:linear-gradient(180deg,#ffffff 0%,#eef4fc 100%);border-color:#c6d3e6}
body[data-theme='light'] .sd-info-title,body[data-theme='light'] .cd h2,body[data-theme='light'] .cd h3,body[data-theme='light'] .cd h4,body[data-theme='light'] .subtab .subtab-title,body[data-theme='light'] .lb h2{color:var(--tx)}
body[data-theme='light'] .ct h1,body[data-theme='light'] .ct h2,body[data-theme='light'] .ct h3,body[data-theme='light'] .ct h4{color:var(--tx)}
body[data-theme='light'] .sd-info-item{background:linear-gradient(180deg,#ffffff,#edf3fb);border-color:#c6d3e6;border-left-color:#b4c6de}
body[data-theme='light'] .sd-info-item-meta{color:#47607c}
body[data-theme='light'] .sd-info-item-text{color:#1b2a3f}
body[data-theme='light'] .sd-info-empty{color:#4f6076}
body[data-theme='light'] .sd,body[data-theme='light'] .sd-info-list{scrollbar-color:#b9c9de #eaf1fa}
body[data-theme='light'] .sd::-webkit-scrollbar-track,body[data-theme='light'] .sd-info-list::-webkit-scrollbar-track{background:#eaf1fa}
body[data-theme='light'] .sd::-webkit-scrollbar-thumb,body[data-theme='light'] .sd-info-list::-webkit-scrollbar-thumb{background:linear-gradient(180deg,#c2d2e6,#aebfd7);border-color:#eaf1fa}
body[data-theme='light'] .sd::-webkit-scrollbar-thumb:hover,body[data-theme='light'] .sd-info-list::-webkit-scrollbar-thumb:hover{background:linear-gradient(180deg,#b2c4db,#9fb3cd)}
body[data-theme='light'] .cd{background:linear-gradient(180deg,#ffffff,#f2f6fc)}
body[data-theme='light'] .dash-stat{background:linear-gradient(180deg,#ffffff,#f3f7ff)}
body[data-theme='light'] .admin-scroll-pane{background:linear-gradient(180deg,#ffffff,#f4f8ff)}
body[data-theme='light'] .bt,body[data-theme='light'] .bg{background:linear-gradient(180deg,#f6faff,#e8eff9);border-color:#c6d2e3;color:#233247;box-shadow:inset 0 1px 0 rgba(255,255,255,.8)}
body[data-theme='light'] .bt:hover,body[data-theme='light'] .bg:hover{background:linear-gradient(180deg,#ffffff,#edf3fb);border-color:#b8c9de;color:#16243a}
body[data-theme='light'] .hd-nav .on,body[data-theme='light'] .top-nav .on{background:linear-gradient(180deg,#eaf7ef,#dff2e6);border-color:#9fcdaf;color:#1c6b3a!important;box-shadow:inset 0 1px 0 rgba(255,255,255,.88)}
body[data-theme='light'] .hd .ver{background:linear-gradient(180deg,#f6faff,#e8eff9);color:#1b2a3f;border-color:#bfd0e6}
body[data-theme='light'] .hd-mobile-toggle{background:linear-gradient(180deg,#ffffff,#edf3fb);border-color:#c6d2e3;color:#233247}
body[data-theme='light'] .tb tr:hover td{background:#edf3fb}
body[data-theme='light'] .lb{background:linear-gradient(180deg,#ffffff,#f3f7ff)}
table.tb{width:100%;border-collapse:collapse}
.tb th{text-align:left;font-size:calc(11px + var(--font-adjust));font-weight:800;color:var(--txd);text-transform:uppercase;letter-spacing:.12em;padding:10px 12px;border-bottom:1px solid var(--brd);background:var(--table-head-bg)}
.tb td{padding:10px 12px;font-size:calc(13px + var(--font-adjust));border-bottom:1px solid var(--brd);vertical-align:middle}
.tb tr:hover td{background:#303030}
.bge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:calc(10px + var(--font-adjust));font-weight:700}
.bge-on{background:var(--okbg);color:var(--okfg);border:1px solid color-mix(in srgb,var(--ok) 32%,transparent)}
.bge-off{background:var(--errbg);color:var(--errfg);border:1px solid color-mix(in srgb,var(--err) 35%,transparent)}
.bge-down{background:var(--warnbg);color:var(--warnfg);border:1px solid color-mix(in srgb,var(--warn) 35%,transparent)}
.bge-p{background:color-mix(in srgb,var(--ac) 15%,transparent);color:var(--ac)}.bge-v6{background:color-mix(in srgb,var(--v6) 16%,transparent);color:var(--v6)}
.lw{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:26px}
.lb{width:450px;background:linear-gradient(160deg,var(--s1) 0%,#1a1a1a 100%);border:1px solid var(--brd);border-top:2.5px solid color-mix(in srgb,var(--ac) 48%,transparent);border-radius:18px;padding:34px 32px 28px;box-shadow:var(--shadow),0 0 40px rgba(0,0,0,.18),inset 0 1px 0 rgba(255,255,255,.05)}
.lb-logo{display:flex;flex-direction:column;align-items:center;margin-bottom:26px;gap:9px}
.lb-logo-icon{width:58px;height:58px;background:color-mix(in srgb,var(--ac) 11%,transparent);border:1.5px solid color-mix(in srgb,var(--ac) 30%,transparent);border-radius:16px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 22px color-mix(in srgb,var(--ac) 14%,transparent)}
.lb-logo-title{font-size:22px;font-weight:800;letter-spacing:-.3px;color:var(--tx)}
.lb-logo-badge{display:inline-flex;align-items:center;padding:2px 9px;border-radius:999px;background:color-mix(in srgb,var(--ac) 11%,transparent);border:1px solid color-mix(in srgb,var(--ac) 24%,transparent);font-size:10.5px;font-weight:700;color:var(--ac);letter-spacing:.04em}
.lb-logo-sub{font-size:12px;color:var(--txd);text-align:center}
.lb-iw{position:relative}
.lb-iw .lb-ico{position:absolute;left:11px;top:50%;transform:translateY(-50%);color:var(--txd);pointer-events:none;line-height:0}
.lb-iw input{padding-left:36px!important}
.lb-iw .lb-eye{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;color:var(--txd);cursor:pointer;padding:5px 6px;display:flex;align-items:center;border-radius:6px;line-height:0;transition:color .14s}
.lb-iw .lb-eye:hover{color:var(--tx)}
body.login-mode{overflow:hidden}
body.login-mode .lw{min-height:100dvh;padding:0;align-items:stretch;justify-content:stretch}
body.login-mode .lb{width:min(100vw,560px);margin:auto;box-shadow:var(--shadow)}
.setup-box{width:min(1000px,96vw);max-width:1000px}
.setup-step-label{margin-bottom:16px;color:var(--txd);font-size:12px;font-weight:700;letter-spacing:.2px}
.setup-actions{display:flex;gap:8px;margin-top:12px}
.setup-actions .bt,.setup-actions a.bt{flex:1;justify-content:center;text-align:center;text-decoration:none;color:inherit}
.setup-list{display:grid;gap:8px}
.setup-list-row{display:grid;grid-template-columns:minmax(240px,1.2fr) minmax(280px,1fr);gap:10px;align-items:center}
.setup-list-row>label{margin:0;font-size:12px;color:var(--txd);font-weight:700}
.mo{display:none;position:fixed;inset:0;background:rgba(0,0,0,.72);z-index:400;align-items:center;justify-content:center}
.mo.on{display:flex}
.md{background:linear-gradient(180deg,var(--s1),#cfcfcf);border:1px solid var(--brd);border-radius:16px;padding:22px;width:500px;max-width:92vw;max-height:90vh;overflow-y:auto;box-shadow:var(--shadow)}
#tgtM .md{width:min(720px,95vw)}
#tgtM .target-form-main{display:grid;grid-template-columns:1fr 1fr;gap:12px}
#tgtM .target-form-main .fg{margin-bottom:0}
#tgtM .target-form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:10px}
#tgtM .target-form-actions .bt{min-width:120px}
.md h3{margin-bottom:12px;font-size:calc(17px + var(--font-adjust))}
.tb2{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:6px}
.pre{background:linear-gradient(180deg,#191919,#151515);border:1px solid var(--brd);border-radius:10px;padding:12px;font-family:'Consolas','Cascadia Mono',monospace;font-size:calc(12px + var(--font-adjust));line-height:1.55;white-space:pre-wrap;max-height:360px;overflow-y:auto;color:var(--txd)}
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:12px}
.sc{background:linear-gradient(180deg,#2f2f2f,#252525);border:1px solid var(--brd);border-radius:10px;padding:12px;text-align:center}
.sc .n{font-size:calc(26px + var(--font-adjust));font-weight:800;color:var(--ac)}.sc .l{font-size:calc(11px + var(--font-adjust));color:var(--txd);margin-top:3px}
.cc{background:linear-gradient(180deg,var(--s1),#202020);border:1px solid var(--brd);border-radius:12px;padding:12px;margin-bottom:8px;display:flex;justify-content:space-between;align-items:center;transition:.14s;box-shadow:var(--shadow-soft)}
.cc:hover{border-color:color-mix(in srgb,var(--ac) 36%,var(--brd))}
.cc h3{font-size:calc(15px + var(--font-adjust));margin-bottom:2px}.cc .mt{font-size:calc(11px + var(--font-adjust));color:var(--txd)}
.ca{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.ck{display:flex;align-items:center;gap:6px;padding:4px 0}.ck input[type=checkbox]{width:15px;height:15px;accent-color:var(--ac)}
.st-dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;animation:pulse 2s ease-in-out infinite}
.st-dot.ok{background:var(--ok)}.st-dot.err{background:var(--err)}.st-dot.warn{background:var(--warn)}.st-dot.inactive{background:var(--txd)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.7}}
.bc{font-size:calc(12px + var(--font-adjust));color:var(--txd);margin-bottom:12px}.bc a{color:var(--ac)}
.dl{font-size:calc(12px + var(--font-adjust));color:var(--txd);cursor:pointer;padding:5px 9px;background:linear-gradient(180deg,#353535,#272727);border-radius:8px;border:1px solid var(--brd);display:inline-flex;align-items:center;min-height:34px}
.dl:hover{background:var(--ac);color:#fff;border-color:var(--ac)}
.down-info{font-size:calc(12px + var(--font-adjust));color:var(--warn);background:color-mix(in srgb,var(--warn) 10%,var(--s2));padding:8px 10px;border-radius:10px;margin-top:6px;font-family:monospace;white-space:pre-wrap}
@media(max-width:1100px){.dash-stats{grid-template-columns:repeat(3,minmax(0,1fr))}.dash-sections,.cd-row{grid-template-columns:1fr 1fr}.app{grid-template-columns:270px minmax(0,1fr)}}
@media(max-width:900px){
    .hd{height:auto;padding:10px 12px;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:8px}
    .hd-nav,.hd-right{display:none}
    .hd-mobile-toggle{display:inline-flex}
    .app{display:flex;flex-direction:column;align-items:stretch;padding:10px;gap:10px}
    .ct,.sd{width:100%;max-width:100%;min-width:0}
    .ct{order:1}
    .sd{order:2;border-right:none;padding:10px;max-height:none;height:auto;margin-top:0;margin-bottom:0;overflow:visible}
    .sd-info{max-height:35vh}
    .top-nav{margin-bottom:8px}
    .top-nav-actions{margin-left:0}
    #tgtM{align-items:flex-end}#tgtM .md{width:100vw;max-width:100vw;max-height:92vh;border-radius:14px 14px 0 0;padding:16px}#tgtM .target-form-main{grid-template-columns:1fr}#tgtM .target-form-actions{flex-direction:column-reverse}#tgtM .target-form-actions .bt{width:100%}
    .pf{margin-left:0;position:relative;width:90%}.pf-btn{width:100%;justify-content:flex-start}.pf-menu{position:static;box-shadow:none;border:1px solid var(--brd);margin-top:6px}
    .ct{padding:0}.cd{padding:10px}.cd-row{grid-template-columns:1fr}
    .tb2{align-items:flex-start}.ca{justify-content:flex-start}.tb2>div:last-child{width:100%;display:flex;flex-wrap:wrap;gap:8px}.tb2>div:last-child .bt{flex:1 1 calc(50% - 8px)}
    .md{width:96vw;padding:16px}
}
@media(max-width:760px){.setup-list-row{grid-template-columns:1fr}}
@media(max-width:640px){
    .hd{padding:8px 10px;min-height:52px}.hd h1{font-size:calc(14px + var(--font-adjust))}
    .brand-alert{font-size:calc(10px + var(--font-adjust));padding:5px 8px}
    .hd-nav a{flex:1 1 calc(50% - 6px);justify-content:center;text-align:center}
    .hd-right .top-nav-actions{width:100%}
    .top-nav{padding:7px;gap:6px}
    .top-nav a,.top-nav button{flex:1 1 calc(50% - 6px);justify-content:center;text-align:center}
    .top-nav-actions{width:100%}
    .top-nav-note{width:100%;justify-content:center}
    .fr,.fr3{grid-template-columns:1fr}.sg{grid-template-columns:repeat(2,1fr)}.dash-stats,.dash-sections{grid-template-columns:1fr}.dash-hero{flex-direction:column;align-items:flex-start}.dash-hero .dash-links{width:100%;justify-content:flex-start}
    .app{padding:8px;gap:8px}
    .ct,.sd,.sd-info{width:100%;max-width:100%;min-width:0}
    .ct{padding:0}
    .sd{padding:0;border:none;background:transparent;box-shadow:none}
    .sd-info{padding:10px}
    .cd{padding:11px}
    .bt{padding:10px 14px;min-height:40px;font-size:calc(13px + var(--font-adjust))}
    input[type=text],input[type=password],input[type=email],input[type=number],select,textarea{padding:8px 10px;min-height:40px;font-size:calc(13px + var(--font-adjust))}
    body.login-mode .lw{padding:max(10px,env(safe-area-inset-top)) max(10px,env(safe-area-inset-right)) max(10px,env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left))}
    body.login-mode .lb{width:100%;min-height:calc(100dvh - env(safe-area-inset-top) - env(safe-area-inset-bottom) - 20px);border-radius:16px;padding:24px 18px;display:flex;flex-direction:column;justify-content:center}
    body.login-mode .lb h2{font-size:28px}
    body.login-mode .lb .sub{font-size:15px;margin-bottom:20px}
    body.login-mode .lb input[type=text],
    body.login-mode .lb input[type=password]{min-height:52px;font-size:18px;padding:12px 14px}
    body.login-mode .lb .bt{min-height:52px;font-size:17px}
}
@media (prefers-reduced-motion: reduce){*{animation:none!important;transition:none!important;scroll-behavior:auto!important}}
</style>
<script>
function copyLink(url){navigator.clipboard.writeText(window.location.origin+url);var b=event.target;b.textContent='Gekopieerd!';setTimeout(()=>b.textContent='Link',1500);}
function openM(id){document.getElementById(id).classList.add('on');}
function closeM(id){document.getElementById(id).classList.remove('on');}
function showEditUser(uid, username, role, email){
    document.getElementById('euUserId').value=uid;
    document.getElementById('euUsername').value=username;
    document.getElementById('euRole').value=role;
    document.getElementById('euEmail').value=email||'';
    openM('editUserM');
}
function toggleProfileMenu(){
    var el=document.getElementById('profileMenuWrap');
    if(!el) return;
    el.classList.toggle('open');
}
function closeMobileMainMenu(){
    document.body.classList.remove('mobile-menu-open');
}
function toggleMobileMainMenu(ev){
    if(ev){ ev.preventDefault(); ev.stopPropagation(); }
    document.body.classList.toggle('mobile-menu-open');
}
document.addEventListener('DOMContentLoaded',function(){
    var nav=document.getElementById('mainNav');
    if(nav){
        nav.querySelectorAll('a').forEach(function(link){
            link.addEventListener('click',function(){
                var pf=document.getElementById('profileMenuWrap');
                if(pf) pf.classList.remove('open');
            });
        });
    }
    document.querySelectorAll('.js-close-mobile-menu').forEach(function(el){
        el.addEventListener('click',function(){ closeMobileMainMenu(); });
    });
    document.querySelectorAll('.log-actions-mobile').forEach(function(el){
        el.addEventListener('toggle', function(){
            if(!el.open){
                el.classList.remove('open-up');
                return;
            }
            document.querySelectorAll('.log-actions-mobile').forEach(function(other){
                if(other !== el){
                    other.open = false;
                    other.classList.remove('open-up');
                }
            });
            var panel = el.querySelector('.log-actions-mobile-panel');
            if(!panel) return;
            el.classList.remove('open-up');
            requestAnimationFrame(function(){
                var rect = panel.getBoundingClientRect();
                if(rect.bottom > (window.innerHeight - 8)){
                    el.classList.add('open-up');
                }
                requestAnimationFrame(function(){
                    el.scrollIntoView({block:'nearest', inline:'nearest'});
                });
            });
        });
    });
    updateFullscreenButtonLabel();
});
document.addEventListener('click',function(e){
    if(document.body.classList.contains('mobile-menu-open')){
        var menu=document.getElementById('mobileMainMenu');
        var btn=document.getElementById('mobileMainMenuBtn');
        if(menu && btn && !menu.contains(e.target) && !btn.contains(e.target)){
            closeMobileMainMenu();
        }
    }
    var el=document.getElementById('profileMenuWrap');
    if(!el) return;
    if(!el.contains(e.target)) el.classList.remove('open');
});
document.addEventListener('keydown',function(e){
    if(e.key==='Escape'){
        closeMobileMainMenu();
        var el=document.getElementById('profileMenuWrap');
        if(el) el.classList.remove('open');
    }
});
function updateFullscreenButtonLabel(){
    var btn=document.getElementById('fullscreenToggleBtn');
    if(!btn) return;
    var isFull=!!document.fullscreenElement;
    btn.textContent=isFull ? '⤢ Venster' : '⛶ Volledig scherm';
    btn.setAttribute('aria-pressed', isFull ? 'true' : 'false');
}
async function toggleFullscreenMode(){
    try{
        if(!document.fullscreenElement){
            await document.documentElement.requestFullscreen();
        } else {
            await document.exitFullscreen();
        }
    } catch(err) {
        console.warn('Fullscreen niet beschikbaar', err);
    } finally {
        updateFullscreenButtonLabel();
    }
}
document.addEventListener('fullscreenchange', updateFullscreenButtonLabel);
</script>
</head><body class="<?=in_array($page,['login','public_target_add','set_password'],true)?'login-mode':''?>"<?=($theme!=='auto'?' data-theme="'.e($theme).'"':'')?><?=' data-fontsize="'.e($fontsize).'"'?> >

<?php if($page==='login'):?>
<div class="lw"><div class="lb">
<div class="lb-logo"><div class="lb-logo-icon"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M2 12h3l3-7 4 14 3-9 2 2h5" stroke="var(--ac)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg></div><div class="lb-logo-title"><?=APP_TITLE?></div><span class="lb-logo-badge"><?=APP_VERSION?></span><div class="lb-logo-sub">Log in om SmokePing te beheren</div></div>
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>
<?php $googleAuthSettings = getGoogleAuthSettings($db); $googleAuthReady = !empty($googleAuthSettings['enabled']) && $googleAuthSettings['client_id'] !== '' && $googleAuthSettings['client_secret'] !== ''; ?>
<form method="POST" onsubmit="var b=this.querySelector('[type=submit]');if(b){b.disabled=true;b.textContent='Bezig\u2026';}"><input type="hidden" name="action" value="login">
<div class="fg"><label>Gebruikersnaam</label><div class="lb-iw"><span class="lb-ico"><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><circle cx="12" cy="8" r="4" stroke="currentColor" stroke-width="2"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></span><input type="text" name="username" required autofocus placeholder="Gebruikersnaam"></div></div>
<div class="fg"><label>Wachtwoord</label><div class="lb-iw"><span class="lb-ico"><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><rect x="5" y="11" width="14" height="10" rx="2" stroke="currentColor" stroke-width="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></span><input type="password" name="password" id="lp-pw" required placeholder="Wachtwoord"><button type="button" class="lb-eye" onclick="var f=document.getElementById('lp-pw');var s=this.querySelectorAll('svg');f.type=f.type==='password'?'text':'password';s[0].style.display=f.type==='password'?'':'none';s[1].style.display=f.type==='password'?'none':'';" aria-label="Wachtwoord tonen/verbergen"><svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/></svg><svg width="15" height="15" viewBox="0 0 24 24" fill="none" style="display:none"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" stroke="currentColor" stroke-width="2" stroke-linecap="round"/><line x1="1" y1="1" x2="23" y2="23" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button></div></div>
<div style="margin-top:10px">
<button type="submit" class="bt bp" style="width:100%;justify-content:center;min-height:42px;font-size:14px">Inloggen</button>
</div>
</form>
<div class="login-divider"><span>of</span></div>
<?php if($googleAuthReady): ?>
<a href="?p=google_auth" class="google-signin" aria-label="Inloggen met Google">
<span class="g-icon" aria-hidden="true">
<svg width="18" height="18" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" role="img" focusable="false">
<path fill="#EA4335" d="M24 9.5c3.54 0 6.73 1.22 9.25 3.6l6.9-6.9C35.95 2.3 30.4 0 24 0 14.6 0 6.5 5.4 2.56 13.28l8.03 6.24C12.5 13.78 17.76 9.5 24 9.5z"/>
<path fill="#4285F4" d="M46.5 24.55c0-1.64-.15-3.22-.42-4.73H24v9h12.7c-.55 2.97-2.23 5.49-4.76 7.18l7.3 5.67c4.27-3.93 6.76-9.72 6.76-17.12z"/>
<path fill="#FBBC05" d="M10.59 28.48A14.5 14.5 0 0 1 9.8 24c0-1.56.27-3.08.79-4.48l-8.03-6.24A24.03 24.03 0 0 0 0 24c0 3.88.93 7.55 2.56 10.72l8.03-6.24z"/>
<path fill="#34A853" d="M24 48c6.48 0 11.92-2.13 15.9-5.8L32.6 36.5c-2.02 1.35-4.63 2.15-8.6 2.15-6.24 0-11.5-4.28-13.4-10.02l-8.03 6.24C6.5 42.6 14.6 48 24 48z"/>
</svg>
</span>
<span class="g-label">Inloggen met Google</span>
</a>
<p style="margin:10px 0 0;font-size:12px;color:var(--txd)">Nieuwe Google-registraties komen eerst in de goedkeuringswachtrij van de beheerder.</p>
<?php else: ?>
<button type="button" class="google-signin is-disabled" disabled aria-label="Inloggen met Google (uitgeschakeld)">
<span class="g-icon" aria-hidden="true">
<svg width="18" height="18" viewBox="0 0 48 48" xmlns="http://www.w3.org/2000/svg" role="img" focusable="false">
<path fill="#EA4335" d="M24 9.5c3.54 0 6.73 1.22 9.25 3.6l6.9-6.9C35.95 2.3 30.4 0 24 0 14.6 0 6.5 5.4 2.56 13.28l8.03 6.24C12.5 13.78 17.76 9.5 24 9.5z"/>
<path fill="#4285F4" d="M46.5 24.55c0-1.64-.15-3.22-.42-4.73H24v9h12.7c-.55 2.97-2.23 5.49-4.76 7.18l7.3 5.67c4.27-3.93 6.76-9.72 6.76-17.12z"/>
<path fill="#FBBC05" d="M10.59 28.48A14.5 14.5 0 0 1 9.8 24c0-1.56.27-3.08.79-4.48l-8.03-6.24A24.03 24.03 0 0 0 0 24c0 3.88.93 7.55 2.56 10.72l8.03-6.24z"/>
<path fill="#34A853" d="M24 48c6.48 0 11.92-2.13 15.9-5.8L32.6 36.5c-2.02 1.35-4.63 2.15-8.6 2.15-6.24 0-11.5-4.28-13.4-10.02l-8.03 6.24C6.5 42.6 14.6 48 24 48z"/>
</svg>
</span>
<span class="g-label">Inloggen met Google</span>
</button>
<p style="margin:10px 0 0;font-size:12px;color:var(--txd)">Google-aanmelding is nog niet geactiveerd door de beheerder.</p>
<?php endif; ?></div></div>
<?php elseif($page==='set_password'):
    $inviteToken = trim((string)($_GET['t'] ?? $_POST['invite_token'] ?? ''));
    $inviteInfo = findValidUserInviteByToken($db, $inviteToken);
?>
<div class="lw"><div class="lb">
<h2>🔐 Eerste wachtwoord instellen</h2><p class="sub">Stel je wachtwoord in voor je eerste login</p>
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>
<?php if(!$inviteInfo): ?>
<div class="fl error">Deze uitnodigingslink is ongeldig of verlopen. Vraag de beheerder om een nieuwe link.</div>
<div style="margin-top:10px"><a class="bt bg" href="?p=login">Terug naar login</a></div>
<?php else: ?>
<form method="POST">
<input type="hidden" name="action" value="set_initial_password">
<input type="hidden" name="invite_token" value="<?=e($inviteToken)?>">
<div class="fg"><label>Gebruikersnaam</label><input type="text" value="<?=e((string)($inviteInfo['username'] ?? ''))?>" disabled></div>
<div class="fg"><label>E-mailadres</label><input type="text" value="<?=e((string)($inviteInfo['email'] ?? ''))?>" disabled></div>
<div class="fg"><label>Nieuw wachtwoord</label><input type="password" name="new_password" minlength="6" required></div>
<div class="fg"><label>Bevestig wachtwoord</label><input type="password" name="confirm_password" minlength="6" required></div>
<p style="margin:8px 0 0;font-size:12px;color:var(--txd)">Deze link is geldig tot <?=e((string)($inviteInfo['expires_at'] ?? '-'))?>.</p>
<button type="submit" class="bt bp" style="width:100%;justify-content:center;margin-top:10px">Wachtwoord opslaan</button>
</form>
<?php endif; ?>
</div></div>
<?php elseif($page==='public_target_add'):
    $publicToken = trim((string)($_GET['k'] ?? $_POST['public_token'] ?? ''));
    $tokenValid = isPublicTargetTokenValid($db, $publicToken);
    $publicCats = [];
    if ($tokenValid) {
        foreach (getCats($db) as $cat) {
            if ((int)($cat['enabled'] ?? 1) === 1) $publicCats[] = $cat;
        }
    }
?>
<div class="lw"><div class="lb">
<h2>⊞ Target Toevoegen</h2><p class="sub">Publieke invoerpagina zonder login</p>
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>
<?php if(!$tokenValid): ?>
<div class="fl error">Deze link is ongeldig. Vraag een nieuwe openbare link aan de beheerder.</div>
<?php elseif(empty($publicCats)): ?>
<div class="fl error">Er zijn geen actieve categorieen beschikbaar voor invoer.</div>
<?php else: ?>
<form method="POST">
<input type="hidden" name="action" value="public_submit_target">
<input type="hidden" name="public_token" value="<?=e($publicToken)?>">
<input type="text" name="website" value="" autocomplete="off" tabindex="-1" style="position:absolute;left:-9999px;opacity:0" aria-hidden="true">
<div class="fg"><label>Categorie</label><select name="category_id" required><?php foreach($publicCats as $pc): ?><option value="<?=(int)$pc['id']?>"><?=e((string)$pc['display_name'])?></option><?php endforeach; ?></select></div>
<div class="fg"><label>Target naam</label><input type="text" name="display_name" maxlength="120" required placeholder="Bijv. Router kantoor"></div>
<div class="fg"><label>IPv4 of hostnaam</label><input type="text" name="host" placeholder="Bijv. 192.168.10.1 of router.local"></div>
<div class="fg"><label>IPv6 (optioneel)</label><input type="text" name="host_ipv6" placeholder="Bijv. fd00::10"></div>
<div class="fg"><label>Klantnummer/opmerking (optioneel)</label><input type="text" name="remark" maxlength="180" placeholder="Bijv. Klant 1001"></div>
<button type="submit" class="bt bp" style="width:100%;justify-content:center;margin-top:6px">Target indienen</button>
<p style="margin:10px 0 0;font-size:12px;color:var(--txd)">Inzendingen worden standaard inactief toegevoegd zodat beheer eerst kan controleren.</p>
</form>
<?php endif; ?>
</div></div>
<?php elseif($page==='setup'): 
    $step=$_GET['step']??'1';
    if(!in_array($step,['1','2','3','4','5','6','complete'],true)) $step='1';
?>
<div class="lw"><div class="lb setup-box">
<h2>🚀 Installatie</h2>
<p class="sub">Maak SmokePing Manager klaar voor gebruik</p>
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>

<?php if($step==='1'): ?>
<div class="setup-step-label">Stap 1 van 6: Kies je thema</div>
<form method="POST"><input type="hidden" name="action" value="setup_wizard_theme"><?=csrfField()?>
<div class="setup-list-row"><label>Thema</label>
<select name="theme">
<option value="auto" <?=$theme==='auto'?'selected':''?>>Automatisch (volg systeem)</option>
<option value="light" <?=$theme==='light'?'selected':''?>>Licht</option>
<option value="dark" <?=$theme==='dark'?'selected':''?>>Donker</option>
</select></div>
<div class="setup-actions"><button type="submit" class="bt bp">Volgende</button><a href="?p=setup&step=2" class="bt">Overslaan</a></div>
</form>
<?php elseif($step==='2'): ?>
<div class="setup-step-label">Stap 2 van 6: Gebruikersnaam & Wachtwoord</div>
<form method="POST"><input type="hidden" name="action" value="setup_wizard_credentials"><?=csrfField()?>
<div class="setup-list-row"><label>Gebruikersnaam (leeg = admin)</label><input type="text" name="newuser" placeholder="admin"></div>
<div class="setup-list-row"><label>Wachtwoord</label><input type="password" name="newpass" required></div>
<div class="setup-actions"><button type="submit" class="bt bp">Volgende</button><a href="?p=setup&step=3" class="bt">Overslaan</a></div>
</form>
<?php elseif($step==='3'): ?>
<div class="setup-step-label">Stap 3 van 6: Email Instellingen</div>
<form method="POST" id="emailForm"><input type="hidden" name="action" value="setup_wizard_email"><?=csrfField()?>
<div class="fg" style="border:1px solid var(--brd);border-radius:8px;padding:12px;background:var(--bg);margin-bottom:12px">
<div style="font-weight:700;margin:0 0 8px">SMTP Email instellingen</div>
<p style="font-size:12px;color:var(--txd);margin:0 0 10px">Deze instellingen zijn voor uitval- en statusmails.</p>
<div class="setup-list-row"><label>Email Provider</label>
<select name="email_provider" id="emailProvider" onchange="updateProviderFields()">
<option value="gmail" selected>Gmail</option>
<option value="outlook">Outlook / Hotmail</option>
<option value="yahoo">Yahoo Mail</option>
<option value="custom">Custom SMTP</option>
</select></div>
<div class="setup-list-row"><label>Email Adres (mailadres + wachtwoord voor inloggen)</label><input type="email" name="email_address" required placeholder="your.email@gmail.com"></div>
<div class="setup-list-row"><label>Wachtwoord</label><input type="password" name="email_password" required placeholder="app password of wachtwoord"></div>
<div id="customFields" style="display:none">
<div class="setup-list-row"><label>SMTP Host</label><input type="text" name="custom_smtp_host" placeholder="smtp.example.com"></div>
<div class="setup-list-row"><label>SMTP Port</label><input type="number" name="custom_smtp_port" value="587"></div>
<div class="setup-list-row"><label>Encryptie</label>
<select name="custom_smtp_encryption">
<option value="tls" selected>TLS</option>
<option value="ssl">SSL</option>
<option value="none">Geen</option>
</select></div>
</div>
</div>

<div class="fg" style="border:1px solid var(--brd);border-radius:8px;padding:12px;background:var(--bg)">
<div style="font-weight:700;margin:0 0 8px">Google Auth instellingen</div>
<p style="font-size:12px;color:var(--txd);margin:0 0 10px">Deze instellingen zijn alleen voor inloggen met Google en staan los van SMTP email.</p>
<div class="setup-list-row"><label>Google Auth inschakelen</label>
<label style="display:flex;align-items:center;gap:8px;margin:0;color:var(--tx)"><input type="checkbox" name="google_auth_enabled" value="1" checked>Google login activeren</label></div>
<div class="setup-list-row"><label>Google Client ID</label><input type="text" name="google_client_id" placeholder="xxxxx.apps.googleusercontent.com"></div>
<div class="setup-list-row"><label>Google Client Secret</label><input type="password" name="google_client_secret" placeholder="Client secret"></div>
<div class="setup-list-row"><label>Redirect URI</label><input type="text" name="google_redirect_uri" value="<?=e(buildGoogleRedirectUri($db))?>" placeholder="<?=e(buildGoogleRedirectUri($db))?>"></div>
<p style="font-size:12px;color:var(--txd);margin:8px 0 0">Als Google login actief is, vul dan Client ID en Secret in om door te kunnen naar de volgende stap.</p>
</div>

<div class="setup-actions"><button type="submit" class="bt bp">Volgende</button><a href="?p=setup&step=4" class="bt">Overslaan</a></div>
</form>

<?php elseif($step==='4'): ?>
<div class="setup-step-label">Stap 4 van 6: Database & Presentatie afstemmen</div>
<form method="POST" id="wizardTuningForm" onsubmit="return confirmWizardTuningSubmit()"><input type="hidden" name="action" value="setup_wizard_smokeping_tuning"><?=csrfField()?>

<div class="fg" style="border:1px solid var(--brd);border-radius:8px;padding:12px;background:var(--bg)">
<label style="display:flex;align-items:center;gap:8px;font-weight:600"><input type="checkbox" name="apply_database_tuning" value="1" checked>Database instellingen aanpassen</label>
<p style="font-size:12px;color:var(--txd);margin:8px 0 10px">Default: elke <strong>10 seconden</strong> een meetronde, met <strong>5 pings</strong> per ronde.  
Dit betekent gemiddeld ongeveer 1 ping per <strong>2 seconden</strong> tijdens die meetronde.</p>

<div class="setup-list-row"><label>Voorinstelling</label>
<select name="db_profile" id="dbProfile" onchange="updateDbPresetHint()">
<option value="default_300_20">Standaard - 5 minuten, 20 pings</option>
<option value="fast_10_5" selected>Sneller - 10 seconden, 5 pings (ongeveer 1 ping per 2s)</option>
<option value="custom">Aangepast - zelf step en pings kiezen</option>
</select></div>

<div class="setup-list">
<div class="setup-list-row"><label>Meetinterval (step in seconden)</label><input type="number" name="db_step" id="dbStep" value="10" min="10" max="3600"></div>
<div class="setup-list-row"><label>Aantal pings per meting</label><input type="number" name="db_pings" id="dbPings" value="5" min="1" max="100"></div>
</div>
<div id="dbHint" style="font-size:12px;color:var(--txd)">Bij deze keuze is dat ongeveer 1 ping per 2 seconden tijdens een meetronde.</div>
</div>

<div class="fg" style="border:1px solid var(--brd);border-radius:8px;padding:12px;background:var(--bg)">
<label style="display:flex;align-items:center;gap:8px;font-weight:600"><input type="checkbox" name="apply_presentation_tuning" value="1" checked>Presentation grafiekranges aanpassen</label>
<p style="font-size:12px;color:var(--txd);margin:8px 0 10px">Pas de zichtbare grafiekperiodes aan. Formaat per regel: <code>Label|Range</code>.  
Voorbeeld: <code>Last 1 Hour|1h</code>.</p>
<div style="font-size:12px;background:#fff4e5;border:1px solid #f1c27d;color:#8a5a00;padding:8px 10px;border-radius:6px;margin-bottom:10px">
Let op: bij toepassen van Presentation wijzigingen worden bestaande grafieken verwijderd (.rrd), daarna wordt SmokePing automatisch herstart.
</div>
<div class="setup-list-row"><label>Grafiek opties</label>
<textarea name="presentation_ranges" rows="10">Last 1 Hour|1h
Last 3 Hours|3h
Last 24 Hours|1d
Last 30 Days|30d
Last 180 Days|180d
Last 360 Days|360d</textarea>
</div>
</div>

<div class="setup-actions"><button type="submit" class="bt bp">Volgende</button><a href="?p=setup&step=5" class="bt">Overslaan</a></div>
</form>

<script>
function updateDbPresetHint(){
    var profile = document.getElementById('dbProfile').value;
    var stepEl = document.getElementById('dbStep');
    var pingsEl = document.getElementById('dbPings');
    if(profile === 'default_300_20'){ stepEl.value = 300; pingsEl.value = 20; }
    if(profile === 'fast_10_5'){ stepEl.value = 10; pingsEl.value = 5; }
    var step = Math.max(1, parseInt(stepEl.value || '1', 10));
    var pings = Math.max(1, parseInt(pingsEl.value || '1', 10));
    var interval = (step / pings).toFixed(2);
    if(interval.endsWith('.00')) interval = interval.slice(0, -3);
    document.getElementById('dbHint').textContent = 'Bij deze keuze is dat ongeveer 1 ping per ' + interval + ' seconden tijdens een meetronde.';
}
function confirmWizardTuningSubmit(){
    var presentationCheckbox = document.querySelector('input[name="apply_presentation_tuning"]');
    if (presentationCheckbox && presentationCheckbox.checked) {
        return confirm('Let op: bestaande grafiekdata wordt verwijderd om de nieuwe grafiekinstellingen toe te passen. Daarna wordt SmokePing automatisch herstart. Doorgaan?');
    }
    return true;
}
document.addEventListener('DOMContentLoaded', function(){
    var s = document.getElementById('dbStep');
    var p = document.getElementById('dbPings');
    if(s) s.addEventListener('input', updateDbPresetHint);
    if(p) p.addEventListener('input', updateDbPresetHint);
    updateDbPresetHint();
});
</script>

<?php elseif($step==='5'): ?>
<div class="setup-step-label">Stap 5 van 6: Targets importeren</div>
<form method="POST" id="targetsImportForm" enctype="multipart/form-data"><input type="hidden" name="action" value="setup_wizard_targets_import"><?=csrfField()?>
<div class="setup-list-row"><label>Importeer bestaand Targets bestand of backup</label><input type="file" class="file-input" name="targets_import_file" accept=".conf,.txt,.backup,.cfg"></div>
<p style="font-size:12px;color:var(--txd);margin:8px 0 14px">Upload hier je bestaande Targets bestand om categorieen en targets tijdens de wizard in te laden.</p>
<div class="setup-actions"><button type="submit" class="bt bp">Volgende</button><button type="button" onclick="document.getElementById('skipForm').submit()" class="bt">Overslaan</button></div>
</form>
<form method="GET" id="skipForm" style="display:none"><input type="hidden" name="p" value="setup"><input type="hidden" name="step" value="6"></form>
<?php elseif($step==='6'): ?>
<div class="setup-step-label">Stap 6 van 6: Automatische backups</div>
<form method="POST"><input type="hidden" name="action" value="setup_wizard_backup_schedule"><?=csrfField()?>
<div class="fg" style="border:1px solid var(--brd);border-radius:8px;padding:12px;background:var(--bg)">
<p style="font-size:12px;color:var(--txd);margin:0 0 10px">Slim schema: bewaar altijd de laatste items, daarna alle dagelijkse backups voor een korte periode, vervolgens 1 per week en daarna 1 per maand.</p>
<div class="setup-list">
    <div class="setup-list-row">
        <label>Automatische full backups inschakelen</label>
        <label style="display:flex;align-items:center;gap:8px;margin:0;color:var(--tx)"><input type="checkbox" name="auto_backup_enabled" value="1" checked>Ingeschakeld</label>
    </div>
    <div class="setup-list-row">
        <label>Nieuwe backup maken</label>
        <select name="auto_backup_frequency"><option value="daily" selected>Elke dag</option><option value="weekly">Elke week</option><option value="monthly">Elke maand</option></select>
    </div>
    <div class="setup-list-row">
        <label>Behoud altijd laatste x items</label>
        <input type="number" name="auto_backup_keep_latest" value="10" min="1" max="100">
    </div>
    <div class="setup-list-row">
        <label>Alle dagelijkse backups bewaren (dagen)</label>
        <input type="number" name="auto_backup_retain_daily" value="14" min="0" max="365">
    </div>
    <div class="setup-list-row">
        <label>Daarna 1 per week bewaren (weken)</label>
        <input type="number" name="auto_backup_retain_weekly" value="8" min="0" max="104">
    </div>
    <div class="setup-list-row">
        <label>Daarna 1 per maand bewaren (maanden)</label>
        <input type="number" name="auto_backup_retain_monthly" value="6" min="0" max="36">
    </div>
</div>
</div>
<div class="setup-actions"><button type="submit" class="bt bp">Voltooien</button><a href="?p=setup&step=complete" class="bt">Overslaan</a></div>
</form>
<?php elseif($step==='complete'): ?>
<div style="text-align:center;padding:20px 0">
<div style="font-size:32px;margin-bottom:12px">✓</div>
<h3>Voltooid!</h3>
<p>SmokePing Manager is gereed. Veel succes met monitoren!</p>
<form method="POST" style="margin-top:16px"><input type="hidden" name="action" value="setup_wizard_complete"><?=csrfField()?><button type="submit" class="bt bp" style="width:100%">Naar Overzicht</button></form>
</div>
<?php endif; ?>
</div></div>
<?php else: requireLogin();
$_spActive = (int)@shell_exec('pgrep -c "smokeping" 2>/dev/null') > 0;
$_spStatusTip = $_spActive
    ? 'Groen: SmokePing service draait en reageert normaal.'
    : 'Rood: SmokePing service draait niet of reageert niet.';
?>
<div class="hd">
<h1>
    <span class="brand-mark <?=$_spActive?'ok':'err'?>" data-tip="<?=htmlspecialchars($_spStatusTip, ENT_QUOTES)?>" tabindex="0" aria-label="<?=htmlspecialchars($_spStatusTip, ENT_QUOTES)?>">●</span>
        <?php if(!$_spActive): ?>
        <span class="brand-alert hd-tip" data-tip="SmokePing is inactief. Herstart of rebuild de service om metingen te hervatten." aria-label="SmokePing is inactief. Herstart of rebuild de service om metingen te hervatten"><span class="brand-alert-dot"></span>Smokeping inactief</span>
        <?php endif; ?>
    <span class="brand-text"><span class="brand-title ver"><?=APP_TITLE?> <?=APP_VERSION?></span></span>
</h1>
<button type="button" class="hd-mobile-toggle" id="mobileMainMenuBtn" onclick="toggleMobileMainMenu(event)"><span class="menu-ico">☰</span> Menu</button>
<nav class="hd-nav" id="mainNav">
<a href="?p=dash" class="<?=$page==='dash'?'on':''?> hd-tip" data-tip="Overzicht: samenvatting van status, aantallen en snelle links" aria-label="Overzicht: samenvatting van status, aantallen en snelle links"><span class="top-nav-ic">⌂</span>Overzicht</a>
<a href="?p=targets" class="<?=in_array($page,['targets','cat'])?'on':''?> hd-tip" data-tip="Targets: beheer categorieen, targets en monitoring instellingen" aria-label="Targets: beheer categorieen, targets en monitoring instellingen"><span class="top-nav-ic">⊞</span>Targets</a>
<?php if(canManage($db)): ?><a href="?p=database" class="<?=$page==='database'?'on':''?> hd-tip" data-tip="Database: bekijk en beheer opgeslagen meetgegevens" aria-label="Database: bekijk en beheer opgeslagen meetgegevens"><span class="top-nav-ic">🗄</span>Database</a><?php endif; ?>
<?php if(canManage($db)): ?><a href="?p=settings" class="<?=$page==='settings'?'on':''?> hd-tip" data-tip="Instellingen: systeem-, notificatie- en backupopties" aria-label="Instellingen: systeem-, notificatie- en backupopties"><span class="top-nav-ic">⚙</span>Instellingen</a><?php endif; ?>
<?php if(isAdmin($db)): ?><a href="?p=admin" class="<?=$page==='admin'?'on':''?> hd-tip" data-tip="Admin Debug: technische controles, logging en diagnostiek" aria-label="Admin Debug: technische controles, logging en diagnostiek"><span class="top-nav-ic">🔧</span>Admin Debug</a><?php endif; ?>
</nav>
<div class="hd-right">
<div class="top-nav-actions">
    <button type="button" class="bt bsm hd-tip" id="fullscreenToggleBtn" onclick="toggleFullscreenMode()" data-tip="Schermvullend tonen of weer terug naar venster" aria-label="Schermvullend tonen of weer terug naar venster" aria-pressed="false">⛶ Volledig scherm</button>
    <?php if(hasActionPermission($db, 'act_config_manage')): ?>
        <form method="POST"><input type="hidden" name="action" value="reload"><?=csrfField()?><button class="bt bsm troubleshoot-btn hd-tip" type="submit" data-tip="Herstelactie: herbouw configuratie en herstart SmokePing" aria-label="Herstelactie: herbouw configuratie en herstart SmokePing">🛠 Rebuild</button></form>
        <form method="POST"><input type="hidden" name="action" value="restart"><?=csrfField()?><button class="bt bsm troubleshoot-btn hd-tip" type="submit" data-tip="Herstelactie: herstart alleen de SmokePing service" aria-label="Herstelactie: herstart alleen de SmokePing service">🛠 Restart</button></form>
    <?php endif; ?>
        <form method="POST"><input type="hidden" name="action" value="logout"><button type="submit" class="bt bsm danger hd-tip" data-tip="Uitloggen: beeindig je sessie en ga terug naar het inlogscherm" aria-label="Uitloggen: beeindig je sessie en ga terug naar het inlogscherm">⇥ Uitloggen</button></form>
</div>
</div>
</div>
<div class="hd-mobile-overlay" id="mobileMainMenuOverlay" onclick="closeMobileMainMenu()"></div>
<div class="hd-mobile-menu" id="mobileMainMenu" role="dialog" aria-label="Hoofdmenu">
    <div class="hd-mobile-head">
        <div class="hd-mobile-title">Hoofdmenu</div>
        <button type="button" class="bt bg bsm" onclick="closeMobileMainMenu()">Sluiten</button>
    </div>
    <div class="hd-mobile-links" style="margin-bottom:10px">
        <a href="?p=dash" class="<?=$page==='dash'?'on':''?> js-close-mobile-menu hd-tip" data-tip="Overzicht: samenvatting van status, aantallen en snelle links" aria-label="Overzicht: samenvatting van status, aantallen en snelle links"><span class="top-nav-ic">⌂</span>Overzicht</a>
        <a href="?p=targets" class="<?=in_array($page,['targets','cat'])?'on':''?> js-close-mobile-menu hd-tip" data-tip="Targets: beheer categorieen, targets en monitoring instellingen" aria-label="Targets: beheer categorieen, targets en monitoring instellingen"><span class="top-nav-ic">⊞</span>Targets</a>
        <?php if(canManage($db)): ?><a href="?p=database" class="<?=$page==='database'?'on':''?> js-close-mobile-menu hd-tip" data-tip="Database: bekijk en beheer opgeslagen meetgegevens" aria-label="Database: bekijk en beheer opgeslagen meetgegevens"><span class="top-nav-ic">🗄</span>Database</a><?php endif; ?>
        <?php if(canManage($db)): ?><a href="?p=settings" class="<?=$page==='settings'?'on':''?> js-close-mobile-menu hd-tip" data-tip="Instellingen: systeem-, notificatie- en backupopties" aria-label="Instellingen: systeem-, notificatie- en backupopties"><span class="top-nav-ic">⚙</span>Instellingen</a><?php endif; ?>
        <?php if(isAdmin($db)): ?><a href="?p=admin" class="<?=$page==='admin'?'on':''?> js-close-mobile-menu hd-tip" data-tip="Admin Debug: technische controles, logging en diagnostiek" aria-label="Admin Debug: technische controles, logging en diagnostiek"><span class="top-nav-ic">🔧</span>Admin Debug</a><?php endif; ?>
    </div>
    <div class="hd-mobile-actions">
        <button type="button" class="bt bsm troubleshoot-btn" onclick="toggleFullscreenMode()"><span class="top-nav-ic">⛶</span><span>Volledig scherm</span></button>
        <?php if(hasActionPermission($db, 'act_config_manage')): ?>
        <form method="POST"><input type="hidden" name="action" value="reload"><?=csrfField()?><button class="bt bsm troubleshoot-btn" type="submit"><span class="top-nav-ic">🛠</span><span>Rebuild</span></button></form>
        <form method="POST"><input type="hidden" name="action" value="restart"><?=csrfField()?><button class="bt bsm troubleshoot-btn" type="submit"><span class="top-nav-ic">🛠</span><span>Restart</span></button></form>
        <?php endif; ?>
        <form method="POST"><input type="hidden" name="action" value="logout"><button type="submit" class="bt bsm danger"><span class="top-nav-ic">⇥</span><span>Uitloggen</span></button></form>
    </div>
</div>
<?php if(!empty($updateNotice)): ?>
<div class="mo on" id="updateNoticeM" onclick="if(event.target===this)closeM('updateNoticeM')" style="z-index:1300">
    <div class="md" style="width:min(560px,92vw)">
        <h3>Nieuwe versie beschikbaar</h3>
        <p style="margin-bottom:10px;color:var(--txd);font-size:13px">Je draait versie <strong><?=e(APP_VERSION)?></strong>, maar op de server staat versie <strong><?=e((string)$updateNotice['latest'])?></strong>.</p>
        <div style="border:1px solid var(--brd);border-radius:10px;padding:10px 12px;background:var(--s1);font-size:12px;color:var(--txd);line-height:1.5;margin-bottom:14px">
            Als admin kun je de update installeren door het update-script opnieuw uit te voeren op de server.
        </div>
        <div style="display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap">
            <button type="button" class="bt bg" onclick="closeM('updateNoticeM')">Later</button>
            <?php if(!empty($updateNotice['url'])): ?><a class="bt bp" href="<?=e((string)$updateNotice['url'])?>" target="_blank" rel="noopener noreferrer">Update-script openen</a><?php endif; ?>
        </div>
    </div>
</div>
<?php endif; ?>
<div class="app">
<aside class="sd">
<div class="sd-info">
<div class="sd-info-title">Info</div>
<?php if(!empty($flashHistory)): ?>
<div class="sd-info-list">
<?php foreach(array_reverse($flashHistory) as $msg): $msgType=in_array(($msg['type']??'success'),['success','error'],true)?$msg['type']:'success'; ?>
<div class="sd-info-item <?=$msgType?>">
    <div class="sd-info-item-meta">
        <span class="sd-info-item-type"><?=e($msgType)?></span>
        <span><?=date('d-m-Y H:i:s', (int)($msg['ts'] ?? time()))?></span>
    </div>
    <div class="sd-info-item-text"><?=e((string)($msg['msg'] ?? ''))?></div>
</div>
<?php endforeach; ?>
</div>
<?php else: ?><div class="sd-info-empty">Geen meldingen beschikbaar.</div><?php endif;?>
</div>
</aside>
<div class="ct">
<?php
// Pre-compute default email for forms (available in all page contexts)
$_uid=(int)($_SESSION['uid']??0);
$_formDefaultEmail='';
if($_uid>0){$_s=$db->prepare('SELECT email FROM users WHERE id=:id');$_s->bindValue(':id',$_uid,SQLITE3_INTEGER);$_r=$_s->execute()->fetchArray(SQLITE3_ASSOC);$_formDefaultEmail=trim((string)($_r['email']??''));}
if($_formDefaultEmail==='')$_formDefaultEmail=getDefaultNotifyRecipientList($db);
// ========== DASHBOARD ==========
if($page==='dash'):
    smPerfStart('dash_prep_ms');
    $dashboard = getDashboardOverviewDataCached($db, 180);
    smPerfStop('dash_prep_ms');
?>
<div class="dash-hero">
<div class="dash-hero-main">
<h2>Wat zit er in deze tool?</h2>
<p>Dit overzicht toont live welke onderdelen nu beschikbaar zijn in SmokePing Manager. Aantallen en backupinformatie worden direct uit de database en bestanden gelezen, zodat deze startpagina actueel blijft met de huidige inrichting.</p>
</div>
<div class="dash-links">
<a href="?p=targets&tab=targets" class="bt bp">Open Targets</a>
<?php if(isAdmin($db)): ?><a href="?p=settings&stab=backups" class="bt bs">Open Backups</a><?php endif; ?>
</div>
</div>

<div class="dash-stats">
<?php foreach($dashboard['stats'] as $stat): ?>
<div class="dash-stat">
<div class="dash-stat-value"><?=e((string)$stat['value'])?></div>
<div class="dash-stat-label"><?=e($stat['label'])?></div>
</div>
<?php endforeach; ?>
</div>

<div class="dash-sections">
<?php foreach($dashboard['sections'] as $section): ?>
<div class="cd dash-section">
<div class="cd-t"><?=e($section['title'])?></div>
<div class="dash-summary"><?=e($section['summary'])?></div>
<div class="dash-list">
<?php foreach($section['items'] as $item): ?>
<div class="dash-item"><?=e($item)?></div>
<?php endforeach; ?>
</div>
<?php if(!empty($section['links'])): ?>
<div class="dash-links">
<?php foreach($section['links'] as $link): ?>
<?php if($link['href']==='?p=admin' && !isAdmin($db)) continue; ?>
<a href="<?=e($link['href'])?>" class="bt bg bsm"><?=e($link['label'])?></a>
<?php endforeach; ?>
</div>
<?php endif; ?>
</div>
<?php endforeach; ?>
</div>

<?php
// ========== CATEGORY DETAIL ==========
elseif($page==='cat'):
    $cid=(int)($_GET['id']??0); $s=$db->prepare('SELECT * FROM categories WHERE id=:id');$s->bindValue(':id',$cid);$cat=$s->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$cat){flash('Niet gevonden.','error');redir('targets');}
    $targets=getTargetsForCat($db,$cid); $allCats=getCats($db); $probeList=getProbes($db); $alertList=getAlerts($db);
?>
<div class="bc"><a href="?p=targets">Targets</a> → <?=e($cat['display_name'])?></div>
<div class="tb2"><div><h2 style="font-size:16px;display:inline"><?=e($cat['display_name'])?></h2></div>
<div style="display:flex;gap:4px">
<button class="bt bg bsm" onclick="openM('catM');resetCatForm()">+ Categorie</button>
<button class="bt bp bsm" onclick="openM('tgtM');resetTgtForm();document.getElementById('etCat').value=<?=$cid?>;">+ Target</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Grafiekdata van alle targets in deze categorie wissen?')"><input type="hidden" name="action" value="clear_rrd_web"><?=csrfField()?><input type="hidden" name="scope" value="category"><input type="hidden" name="category_id" value="<?=(int)$cid?>"><button type="submit" class="bt bw bsm">🗑 Grafiekdata</button></form>
</div>
</div>
<?php if(empty($targets)):?><div class="cd"><p style="color:var(--txd);text-align:center;padding:20px">Geen targets.</p></div>
<?php else:?><div class="cd" style="padding:0;overflow-x:auto"><table class="tb">
<thead><tr><th>Naam</th><th>Host</th><th>IPv6</th><th>Probe</th><th>Status</th><th style="text-align:right">Acties</th></tr></thead><tbody>
<?php
$cfgStale = max(20, (int)getSetting($db, 'outage_stale_seconds', '20'));
$probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes WHERE enabled=1');
if ($probeStepSec <= 0) $probeStepSec = (int)$db->querySingle('SELECT MAX(step) FROM probes');
if ($probeStepSec <= 0) $probeStepSec = 300;
$staleThresholdSec = max($cfgStale, 120, $probeStepSec * 2);
foreach($targets as $t):
    $st = getTargetStatus($cat['name'], $t['name']);
    $isOutage = $t['enabled'] && ((((int)($st['sample_ts'] ?? 0) > 0) && (time() - (int)$st['sample_ts'] > $staleThresholdSec)) || ($st['loss'] !== null && $st['loss'] >= 1.0));
    $statusBadge = 'bge-off';
    $statusLabel = 'Uit';
    $health = 'inactive';
    if ($t['enabled']) {
        if (!$st['exists'] || (int)($st['sample_ts'] ?? 0) <= 0 || $st['loss'] === null) {
            $statusBadge = 'bge-down';
            $statusLabel = 'Wacht op 1e meting';
            $health = 'warn';
        } elseif ((((int)($st['sample_ts'] ?? 0) > 0) && (time() - (int)$st['sample_ts'] > $staleThresholdSec)) || ($st['loss'] !== null && $st['loss'] >= 1.0)) {
            $statusBadge = 'bge-off';
            $statusLabel = 'Uitval';
            $health = 'err';
        } elseif ($st['loss'] > 0) {
            $statusBadge = 'bge-down';
            $statusLabel = round($st['loss'] * 100, 0) . '% loss';
            $health = 'warn';
        } else {
            $statusBadge = 'bge-on';
            $statusLabel = 'Actief';
            $health = 'ok';
        }
    }
    $downInfo = '';
    if ($isOutage) {
        $stDown = getTargetStatus($cat['name'], $t['name'], true);
        $downInfo = trim((string)($stDown['downtime_str'] ?? ''));
    }
?><tr>
<td><strong><?=e($t['display_name'])?></strong><div style="font-size:10px;color:var(--txd)"><?=e($t['name'])?><?php if(!empty($t['remark'])):?> — <?=e($t['remark'])?><?php endif;?></div></td>
<td><code style="font-size:12px"><?=e($t['host'])?></code></td>
<td><?php if(!empty($t['host_ipv6'])):?><code style="font-size:10px"><?=e($t['host_ipv6'])?></code><?php else:?>—<?php endif;?></td>
<td><?=!empty($t['probe'])?e($t['probe']):'<span style="color:var(--txd)">inherit</span>'?></td>
<td>
<span class="st-dot <?=$health?>" title="<?=e($statusLabel)?>"></span>
<?php if($isOutage && $downInfo!==''): ?>
<div class="down-info" style="margin-top:4px;font-size:11px"><?=e($downInfo)?></div>
<?php endif; ?>
</td>
<td><div style="display:flex;gap:4px;justify-content:flex-end">
<button class="bt bg bsm" onclick='var d=<?=e(json_encode($t))?>;document.getElementById("etA").value="edit_tgt";document.getElementById("etTitle").textContent="Bewerken";document.getElementById("etBtn").textContent="Opslaan";document.getElementById("etId").value=d.id;document.getElementById("etCat").value=d.category_id;document.getElementById("etD").value=d.display_name;document.getElementById("etH").value=d.host;document.getElementById("etH6").value=d.host_ipv6||"";document.getElementById("etR").value=d.remark||"";document.getElementById("etAl").value=d.alert||"";document.getElementById("etSD").value=d.session_duration||"unlimited";document.getElementById("etSNE").checked=(d.session_notify_enabled==1);document.getElementById("etSNEml").value=d.session_notify_email||<?=e(json_encode($_formDefaultEmail))?>;document.getElementById("etEn").checked=d.enabled==1;document.getElementById("etER").style.display="flex";openM("tgtM")'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Grafiekdata van dit target wissen?')"><input type="hidden" name="action" value="clear_rrd_web"><?=csrfField()?><input type="hidden" name="scope" value="target"><input type="hidden" name="category_id" value="<?=(int)$cid?>"><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><button class="bt bw bsm">🗑</button></form>
<form method="POST" style="display:inline" onsubmit="return confirm('Verwijderen?')"><input type="hidden" name="action" value="del_tgt"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$t['id']?>"><input type="hidden" name="category_id" value="<?=$cid?>"><button class="bt bd bsm">×</button></form>
</div></td></tr><?php endforeach;?></tbody></table></div><?php endif;?>

<?php
$_catIntervalMap=[5=>'5 min',10=>'10 min',15=>'15 min',30=>'30 min',240=>'4 uur',480=>'8 uur',1440=>'1 dag',2880=>'2 dagen',10080=>'7 dagen'];
$_catIntervalRow=$db->query('SELECT outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
$_catIntervalMin=(int)($_catIntervalRow['outage_mail_interval']??5);
$_catIntervalLabel=$_catIntervalMap[$_catIntervalMin]??($_catIntervalMin.' min');
?>
<div class="mo" id="tgtM"><div class="md">
<h3 id="etTitle">Nieuw Target</h3>
<form method="POST" id="tgtForm" class="tgt-form"><input type="hidden" name="action" id="etA" value="add_tgt"><?=csrfField()?>
<input type="hidden" name="id" id="etId">
<div class="fg"><label>Categorie</label><select name="category_id" id="etCat">
<?php foreach($allCats as $c):?><option value="<?=(int)$c['id']?>" <?=$c['id']==$cid?'selected':''?>><?=e($c['display_name'])?></option><?php endforeach;?></select></div>
<div class="target-form-main">
<div class="fg"><label>Klantnummer</label><input type="text" name="remark" id="etR"></div>
<div class="fg"><label>Naam</label><input type="text" name="display_name" id="etD" required></div>
<div class="fg"><label>Host (IPv4)</label><input type="text" name="host" id="etH"></div>
<div class="fg"><label>Host IPv6</label><input type="text" name="host_ipv6" id="etH6" placeholder="bijv. 2606:4700::1111"></div>
</div>
<div class="fg"><label>🔔 Alert Configuratie</label><select name="alert" id="etAl"><option value="">Geen alert</option>
<?php foreach($alertList as $al):?><option value="<?=e($al['name'])?>" <?=((string)$al['name']===(string)getDefaultTargetAlertName($db))?'selected':''?>><?=e($al['display_name'])?></option><?php endforeach;?></select></div>
<div class="fg"><label>Sessieduur</label><select name="session_duration" id="etSD">
<option value="unlimited">Onbeperkt</option>
<option value="1m">1 min</option>
<option value="1h">1 uur</option>
<option value="6h">6 uur</option>
<option value="12h">12 uur</option>
<option value="24h">24 uur</option>
<option value="7d">7 dagen</option>
<option value="30d">30 dagen</option>
</select></div>
<div class="fr"><div class="fg ck"><input type="checkbox" name="session_notify_enabled" id="etSNE" checked><label for="etSNE">Mail bij sessie start/einde</label></div>
<div class="fg" style="flex:1"><label>Notificatie e-mailadres(sen)</label><input type="text" name="session_notify_email" id="etSNEml" value="<?=e($_formDefaultEmail)?>" placeholder="bijv. admin@example.com, monitor@example.com"></div></div>
<div class="fg"><label>Uitval mail interval</label><select name="outage_mail_interval" id="etOI"><option value="">Globaal (<?=e($_catIntervalLabel)?>)</option><?php foreach([5=>'5 min',10=>'10 min',15=>'15 min',30=>'30 min',240=>'4 uur',480=>'8 uur',1440=>'1 dag',2880=>'2 dagen',10080=>'7 dagen'] as $v=>$l):?><option value="<?=$v?>"><?=e($l)?></option><?php endforeach;?></select></div>
<div class="fg ck" id="etER" style="display:none"><input type="checkbox" name="enabled" id="etEn" checked><label for="etEn">Actief</label></div>
<div class="target-form-actions">
<button type="button" class="bt bg" onclick="closeM('tgtM')">Annuleren</button>
<button type="submit" class="bt bp" id="etBtn">Toevoegen</button></div></form></div></div>

<?php
// ========== ADMIN PANEL ==========
elseif($page==='admin'):
    requireLogin();
    if (!isAdmin($db)) { flash('Geen rechten.','error'); redir('targets',['tab'=>'targets']); }
    
    // Password verification gate
    $adminVerified = (int)($_SESSION['admin_verified'] ?? 0) === 1;
    $adminVerifiedAt = (int)($_SESSION['admin_verified_at'] ?? 0);
    
    if (!$adminVerified || (time() - $adminVerifiedAt) > $sessionTimeoutSeconds) {
        if (!$adminVerified) {
            $_SESSION['admin_verified'] = 0;
            $_SESSION['admin_verified_at'] = 0;
        }
        
        $usr = $db->prepare('SELECT password FROM users WHERE id=:id');
        $usr->bindValue(':id', $_SESSION['uid'], SQLITE3_INTEGER);
        $userRow = $usr->execute()->fetchArray(SQLITE3_ASSOC);
        $userPassword = $userRow['password'] ?? '';
        
        $require_action = $_POST['admin_pwd_action'] ?? '';
        $require_pwd = trim($_POST['admin_pwd'] ?? '');
        
        if ($require_action === 'verify_admin_pwd' && !empty($require_pwd)) {
            if (password_verify($require_pwd, $userPassword)) {
                $_SESSION['admin_verified'] = 1;
                $_SESSION['admin_verified_at'] = time();
                $adminVerified = true;
            } else {
                flash('Wachtwoord onjuist.', 'error');
            }
        }
        
        if (!$adminVerified) {
            ?>
<h2 style="font-size:16px;margin-bottom:14px">🔐 Admin Panel - Verificatie Vereist</h2>
<div class="cd" style="max-width:400px;margin:0 auto">
    <div class="cd-t">Beveiligd Gebied</div>
    <form method="POST" style="padding:20px">
        <?=csrfField()?>
        <div style="margin-bottom:16px">
            <label style="display:block;margin-bottom:6px;font-weight:500">Voer je wachtwoord in:</label>
            <input type="password" name="admin_pwd" placeholder="Wachtwoord" style="width:100%;padding:8px;border:1px solid var(--brd);border-radius:4px;font-size:14px" autofocus>
        </div>
        <button type="submit" name="admin_pwd_action" value="verify_admin_pwd" class="bt bg" style="width:100%;padding:10px">Verificatie</button>
    </form>
</div>
            <?php
            exit;
        }
    }
    
    $emailSettings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
    
    $allTargets = getAllTargets($db);
    $mailLogs = [];
    $mailLogRes = $db->query('SELECT id,type,target_name,email_to,subject,status,message,debug_output,body,created_at,datetime(created_at, \'localtime\') AS created_at_local FROM mail_log ORDER BY id DESC LIMIT 100');
    while ($mailLogRes && ($ml = $mailLogRes->fetchArray(SQLITE3_ASSOC))) $mailLogs[] = $ml;
    
    ?>
<h2 style="font-size:16px;margin-bottom:14px">🔧 Admin Panel - Database Gegevens</h2>
<div style="background:var(--s2);padding:8px;border-radius:4px;margin-bottom:16px;border-left:3px solid var(--ac);font-size:13px;color:var(--txd)">
    ✅ Geverifieerd. Sessie verloopt na <?=e($uiSessionTimeoutLabel)?>. <a href="?p=targets&amp;tab=targets" style="color:var(--ac)">Terug</a>
</div>

<!-- Email Settings Table -->
<div class="cd">
    <div class="cd-t">📧 Email Instellingen (Alle Details)</div>
    <div style="overflow-x:auto;font-size:12px">
    <table style="width:100%;border-collapse:collapse">
    <tbody>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);width:160px;font-weight:500">SMTP Enabled</td><td style="padding:8px"><code><?=($emailSettings['smtp_enabled'] ? '✅ YES' : '❌ NO')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Host</td><td style="padding:8px"><code><?=htmlspecialchars($emailSettings['smtp_host'] ?? '')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Port</td><td style="padding:8px"><code><?=(int)($emailSettings['smtp_port'] ?? 0)?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Encryption</td><td style="padding:8px"><code><?=htmlspecialchars($emailSettings['smtp_encryption'] ?? 'tls')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Username</td><td style="padding:8px"><code><?=htmlspecialchars($emailSettings['smtp_username'] ?? '')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">From Email</td><td style="padding:8px"><code><?=htmlspecialchars($emailSettings['smtp_from_email'] ?? '')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">From Name</td><td style="padding:8px"><code><?=htmlspecialchars($emailSettings['smtp_from_name'] ?? 'SmokePing Manager')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Alert Enabled</td><td style="padding:8px"><code><?=($emailSettings['alert_enabled'] ? '✅' : '❌')?></code></td></tr>
    <tr style="border-bottom:1px solid var(--brd)"><td style="padding:8px;color:var(--txd);font-weight:500">Alert Threshold %</td><td style="padding:8px"><code><?=(float)($emailSettings['alert_threshold'] ?? 95)?></code></td></tr>
    <tr><td style="padding:8px;color:var(--txd);font-weight:500">Default Recipients</td><td style="padding:8px;font-size:11px"><code style="word-break:break-all"><?=htmlspecialchars($emailSettings['alert_recipients'] ?? '(empty)')?></code></td></tr>
    </tbody>
    </table>
    </div>
</div>

<!-- All Targets -->
<div class="cd">
    <div class="cd-t">🎯 All Targets (<?=count($allTargets)?>) - Session & Alert Status</div>
    <div class="admin-scroll-pane" style="font-size:11px">
    <table>
    <thead style="background:var(--s2);border-bottom:2px solid var(--brd)">
    <tr>
    <th style="text-align:left;padding:6px">ID</th>
    <th style="text-align:left;padding:6px">Category</th>
    <th style="text-align:left;padding:6px">Target</th>
    <th style="text-align:left;padding:6px">Host</th>
    <th style="text-align:center;padding:6px">Enabled</th>
    <th style="text-align:center;padding:6px">Duration</th>
    <th style="text-align:center;padding:6px">Notify</th>
    <th style="text-align:left;padding:6px">Email</th>
    <th style="text-align:left;padding:6px">Started</th>
    <th style="text-align:center;padding:6px">Start</th>
    <th style="text-align:center;padding:6px">End</th>
    </tr>
    </thead>
    <tbody>
    <?php foreach($allTargets as $t):
        $durRaw = normalizeSessionDuration((string)($t['session_duration'] ?? 'unlimited'));
        $dur = sessionDurationLabel($durRaw);
        $notify = (int)($t['session_notify_enabled'] ?? 0);
        $startSent = (int)($t['session_start_notified'] ?? 0);
        $endSent = (int)($t['session_end_notified'] ?? 0);
        $isEnabled = (int)$t['enabled'] === 1;
        $startedAt = trim((string)($t['session_started_at'] ?? ''));

        $startLabel = '-';
        $startColor = 'var(--txd)';
        if ($notify === 1) {
            if ($startSent === 1) { $startLabel = '✅'; $startColor = 'var(--ok)'; }
            elseif ($isEnabled && $durRaw !== 'unlimited') { $startLabel = '⏳'; $startColor = 'var(--warn)'; }
            else { $startLabel = '❌'; $startColor = 'var(--err)'; }
        }

        $endLabel = '-';
        $endColor = 'var(--txd)';
        if ($notify === 1 && $durRaw !== 'unlimited') {
            if ($endSent === 1) { $endLabel = '✅'; $endColor = 'var(--ok)'; }
            elseif ($isEnabled) { $endLabel = '⏳'; $endColor = 'var(--warn)'; }
            else { $endLabel = '❌'; $endColor = 'var(--err)'; }
        }
    ?>
    <tr style="border-bottom:1px solid var(--brd)">
    <td style="padding:6px"><code><?=(int)$t['id']?></code></td>
    <td style="padding:6px"><?=htmlspecialchars($t['cat_display'])?></td>
    <td style="padding:6px"><?=htmlspecialchars($t['display_name'])?></td>
    <td style="padding:6px;font-size:10px"><code><?=htmlspecialchars($t['host'])?></code></td>
    <td style="padding:6px;text-align:center"><span style="color:<?=($isEnabled?'var(--ok)':'var(--err)')?>"><?=($isEnabled?'✅':'❌')?></span></td>
    <td style="padding:6px;text-align:center"><code style="font-size:10px"><?=$dur?></code></td>
    <td style="padding:6px;text-align:center"><span style="color:<?=($notify?'var(--ok)':'var(--txd)')?>"><?=($notify?'✅':'—')?></span></td>
    <td style="padding:6px;font-size:10px"><code style="word-break:break-all"><?=htmlspecialchars($t['session_notify_email'] ?? 'default')?></code></td>
    <td style="padding:6px;font-size:10px"><code><?=htmlspecialchars($startedAt !== '' ? $startedAt : '-')?></code></td>
    <td style="padding:6px;text-align:center"><span style="color:<?=$startColor?>" title="<?=($startLabel==='⏳'?'Startmail nog niet verwerkt of wacht op volgende check':'')?>"><?=$startLabel?></span></td>
    <td style="padding:6px;text-align:center"><span style="color:<?=$endColor?>" title="<?=($endLabel==='⏳'?'Einde bereikt maar nog niet verwerkt; wordt afgehandeld bij volgende paginalaad of cron':'')?>"><?=$endLabel?></span></td>
    </tr>
    <?php endforeach; ?>
    </tbody>
    </table>
    </div>
</div>

<!-- Mail Log -->
<div class="cd">
    <div class="cd-t">📋 Mail Log (Last 100 Entries)</div>
    <?php if(empty($mailLogs)): ?>
    <div style="padding:16px;color:var(--txd);font-size:13px">No mail attempts logged.</div>
    <?php else: ?>
    <div class="admin-scroll-pane" style="font-size:10px">
    <table>
    <thead style="background:var(--s2);border-bottom:2px solid var(--brd)">
    <tr>
    <th style="text-align:left;padding:5px">DateTime</th>
    <th style="text-align:left;padding:5px">Type</th>
    <th style="text-align:left;padding:5px">Target</th>
    <th style="text-align:left;padding:5px">To Email</th>
    <th style="text-align:center;padding:5px">Status</th>
    <th style="text-align:left;padding:5px">Message</th>
    <th style="text-align:center;padding:5px">Mail</th>
    </tr>
    </thead>
    <tbody>
    <?php
    $typeLabels = ['session_start'=>'📧 Ses.Start','session_end'=>'📧 Ses.End','session_end_manual'=>'⏹ Ses.Handmatig','session_summary'=>'📨 Tussenstand','outage_start'=>'⚠️ Out.Start','outage_end'=>'✅ Out.End','outage_batch'=>'📦 Out.Batch','ping_loss'=>'📉 Pingverlies','test_email'=>'🧪 Test','notification'=>'📬 Notify'];
    foreach($mailLogs as $ml):
        $isOk = $ml['status'] === 'success';
        $typeLabel = $typeLabels[$ml['type']] ?? htmlspecialchars($ml['type']);
        $hasBody = !empty(trim((string)($ml['body'] ?? '')));
        $bodyJson = $hasBody ? htmlspecialchars(json_encode((string)$ml['body'], JSON_UNESCAPED_UNICODE|JSON_HEX_TAG|JSON_HEX_AMP|JSON_HEX_APOS|JSON_HEX_QUOT), ENT_QUOTES) : '';
        $subjectEsc = htmlspecialchars((string)($ml['subject'] ?? ''), ENT_QUOTES);
        $toEsc = htmlspecialchars((string)($ml['email_to'] ?? ''), ENT_QUOTES);
        $dateEsc = htmlspecialchars($ml['created_at_local'] ?? $ml['created_at'], ENT_QUOTES);
    ?>
    <tr style="border-bottom:1px solid var(--brd)">
    <td style="padding:5px;white-space:nowrap"><code><?=htmlspecialchars($ml['created_at_local'] ?? $ml['created_at'])?></code></td>
    <td style="padding:5px"><?=$typeLabel?></td>
    <td style="padding:5px"><code style="font-size:9px"><?=htmlspecialchars($ml['target_name'])?></code></td>
    <td style="padding:5px"><code style="font-size:9px"><?=htmlspecialchars($ml['email_to'])?></code></td>
    <td style="padding:5px;text-align:center"><span style="color:<?=($isOk?'var(--ok)':'var(--err)')?>;font-weight:700"><?=($isOk?'✓':'✗')?></span></td>
    <td style="padding:5px;font-size:9px" title="<?=htmlspecialchars($ml['message'])?>"><?=htmlspecialchars(substr($ml['message'], 0, 220))?></td>
    <td style="padding:5px;text-align:center"><?php if($isOk): ?><button type="button" class="bt bg bsm mail-preview-btn" style="font-size:9px;padding:3px 7px" data-body="<?=htmlspecialchars(json_encode((string)($ml['body'] ?? ''), JSON_UNESCAPED_UNICODE), ENT_QUOTES)?>" data-subject="<?=$subjectEsc?>" data-to="<?=$toEsc?>" data-date="<?=$dateEsc?>" data-has-body="<?=$hasBody?1:0?>">👁 Bekijk</button><?php else: ?><span style="color:var(--txd)">—</span><?php endif; ?></td>
    </tr>
    <?php endforeach; ?>
    </tbody>
    </table>
    </div>
    <?php endif; ?>
</div>

<!-- Mail Preview Modal -->
<div class="mo" id="mailPreviewM" onclick="if(event.target===this)closeM('mailPreviewM')" style="z-index:1200">
<div class="md" style="max-width:860px;width:95vw">
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
    <h3 style="margin:0;font-size:14px">📧 E-mail inhoud</h3>
    <button type="button" class="bt bg bsm" onclick="closeM('mailPreviewM')">Sluiten</button>
</div>
<div id="mailPreviewMeta" style="font-size:11px;color:var(--txd);margin-bottom:10px;display:grid;grid-template-columns:60px 1fr;gap:4px 10px"></div>
<div style="display:flex;gap:6px;margin-bottom:8px">
    <button type="button" class="bt bg bsm" id="mailPrevTabHtml" onclick="switchMailTab('html')" style="font-size:11px">HTML weergave</button>
    <button type="button" class="bt bw bsm" id="mailPrevTabSrc" onclick="switchMailTab('src')" style="font-size:11px">Broncode</button>
</div>
<div id="mailPreviewHtml" style="border:1px solid var(--brd);border-radius:6px;overflow:auto;max-height:60vh;background:#fff">
    <iframe id="mailPreviewFrame" sandbox="allow-same-origin" style="width:100%;min-height:400px;border:none"></iframe>
</div>
<div id="mailPreviewSrc" style="display:none;border:1px solid var(--brd);border-radius:6px;overflow:auto;max-height:60vh;background:var(--s1)">
    <pre id="mailPreviewSrcPre" style="font-size:10px;padding:10px;margin:0;white-space:pre-wrap;word-break:break-word"></pre>
</div>
</div>
</div>
<script>
var _mailPrevMode = 'html';
function showMailPreview(body, subject, to, date, hasBody) {
    hasBody = hasBody === true || hasBody === 'true' || hasBody === 1 || hasBody === '1';
    document.getElementById('mailPreviewMeta').innerHTML =
        '<span style="font-weight:700">Aan:</span><span>'+escHtmlAdmin(to)+'</span>'+
        '<span style="font-weight:700">Onderwerp:</span><span>'+escHtmlAdmin(subject)+'</span>'+
        '<span style="font-weight:700">Datum:</span><span>'+escHtmlAdmin(date)+'</span>';
    
    if (!hasBody || !body || body.trim() === '') {
        var noBodyMsg = '<div style="padding:20px;text-align:center;color:var(--txd);font-size:12px">' +
            '<p style="margin-bottom:10px">⚠️ Body niet beschikbaar</p>' +
            '<p style="font-size:11px;line-height:1.5">Deze mail is succesvol verzonden, maar de inhoud is niet opgeslagen.' +
            '<br>Dit gebeurt voor mails die vóór deze feature zijn verzonden.' +
            '<br><br><strong>Bekende informatie:</strong>' +
            '<br>Onderwerp: ' + escHtmlAdmin(subject) +
            '<br>Aan: ' + escHtmlAdmin(to) + '</p>' +
            '</div>';
        document.getElementById('mailPreviewSrcPre').textContent = '(Body niet opgeslagen)';
        var frame = document.getElementById('mailPreviewFrame');
        frame.srcdoc = noBodyMsg;
    } else {
        document.getElementById('mailPreviewSrcPre').textContent = body;
        var frame = document.getElementById('mailPreviewFrame');
        frame.srcdoc = body;
    }
    switchMailTab('html');
    openM('mailPreviewM');
}
function switchMailTab(mode) {
    _mailPrevMode = mode;
    document.getElementById('mailPreviewHtml').style.display = mode === 'html' ? '' : 'none';
    document.getElementById('mailPreviewSrc').style.display = mode === 'src' ? '' : 'none';
    document.getElementById('mailPrevTabHtml').className = 'bt bsm ' + (mode === 'html' ? 'bg' : 'bw');
    document.getElementById('mailPrevTabSrc').className = 'bt bsm ' + (mode === 'src' ? 'bg' : 'bw');
}
function escHtmlAdmin(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// Handle mail preview button clicks
document.addEventListener('click', function(e) {
    if (e.target && e.target.classList && e.target.classList.contains('mail-preview-btn')) {
        e.preventDefault();
        try {
            var btn = e.target;
            var body = btn.getAttribute('data-body') || '';
            var subject = btn.getAttribute('data-subject') || '';
            var to = btn.getAttribute('data-to') || '';
            var date = btn.getAttribute('data-date') || '';
            var hasBody = btn.getAttribute('data-has-body') === '1';
            
            // Parse body if it's JSON encoded
            try {
                body = JSON.parse(body);
            } catch (ex) {
                // Not JSON, use as-is
            }
            
            showMailPreview(body, subject, to, date, hasBody);
        } catch (err) {
            console.error('Mail preview error:', err);
            alert('Fout bij het openen van mail preview');
        }
    }
});
</script>

<?php

// ========== PROBES (redirect to settings) ==========
elseif($page==='probes'):
    redir('settings',['stab'=>'configuratie']);
    exit;
// ========== CONFIG ==========
elseif($page==='config'):
    redir('settings',['stab'=>'configuratie','file'=>($_GET['file']??'')]);
    exit;
// ========== BACKUP ==========
elseif($page==='backup'):
    redir('settings',['stab'=>'backups']);
    exit;
// ========== DATABASE PAGE ==========
elseif($page==='database'):
    requireLogin();
    $dbTable = strtolower(trim((string)($_GET['table'] ?? '')));
    $validTables = ['users','categories','targets','email_settings','activity_log','mail_log','target_outages','target_ping_loss_events','settings','target_draft_queue'];
    if ($dbTable !== '' && !in_array($dbTable, $validTables, true)) $dbTable = '';
?>
<style>
.db-view-container{display:grid;grid-template-columns:220px 1fr;gap:12px;margin-bottom:20px}
.db-tables-sidebar{border:1px solid var(--brd);border-radius:10px;overflow:hidden;background:var(--s1);height:fit-content;position:sticky;top:14px}
.db-tables-header{background:var(--s2);padding:12px;font-weight:700;font-size:13px;border-bottom:1px solid var(--brd)}
.db-tables-list{max-height:600px;overflow-y:auto}
.db-table-item{padding:10px 12px;border-bottom:1px solid rgba(0,0,0,.05);cursor:pointer;font-size:12px;color:var(--tx);text-decoration:none;display:block;transition:background .15s}
.db-table-item:hover{background:var(--s2)}
.db-table-item.active{background:var(--ac);color:#fff;font-weight:600}
.db-table-item .count{float:right;font-size:11px;color:var(--txd);opacity:.7}
.db-table-item.active .count{color:rgba(255,255,255,.6)}
.db-main{border:1px solid var(--brd);border-radius:10px;overflow:hidden;background:var(--s1)}
.db-header{background:var(--s2);padding:12px;border-bottom:1px solid var(--brd);display:flex;justify-content:space-between;align-items:center}
.db-title{font-weight:700;font-size:13px}
.db-actions{display:flex;gap:6px}
.db-content{overflow:auto;max-height:700px}
.db-table-view{width:100%;border-collapse:collapse;font-size:11px}
.db-table-view th{background:var(--s2);padding:8px;text-align:left;font-weight:700;color:var(--txd);border-bottom:1px solid var(--brd);position:sticky;top:0;white-space:nowrap}
.db-table-view td{padding:8px;border-bottom:1px solid var(--brd)}
.db-table-view tbody tr:hover{background:rgba(0,0,0,.05)}
.db-code{font-family:'Fira Code',monospace;font-size:10px;color:var(--txd);max-width:350px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:inline-block}
.db-no-selection{padding:40px;text-align:center;color:var(--txd)}
.db-null{color:var(--txd);font-style:italic}
</style>
<h2 style="font-size:16px;margin-bottom:14px">🗄 Database Explorer</h2>
<div class="db-view-container">
    <div class="db-tables-sidebar">
        <div class="db-tables-header">📊 Tabellen</div>
        <div class="db-tables-list">
        <?php 
        $tableStats = [];
        foreach ($validTables as $tbl) {
            $count = (int)$db->querySingle('SELECT COUNT(*) FROM ' . $tbl);
            $tableStats[$tbl] = $count;
        ?>
            <a href="?p=database&table=<?=urlencode($tbl)?>" class="db-table-item<?=($dbTable===$tbl?' active':'')?>">
                <?=htmlspecialchars(ucfirst(str_replace('_', ' ', $tbl)))?>
                <span class="count"><?=$count?></span>
            </a>
        <?php } ?>
        </div>
    </div>

    <div class="db-main">
        <?php if ($dbTable === ''): ?>
        <div class="db-no-selection">
            <p style="font-size:14px;margin-bottom:8px">📊 Selecteer een tabel aan de linkerkant</p>
            <p style="font-size:12px;color:var(--txd)">Kies een tabel om de gegevens te bekijken</p>
        </div>
        <?php else: ?>
        <div class="db-header">
            <span class="db-title"><?=htmlspecialchars(ucfirst(str_replace('_', ' ', $dbTable)))?> (<?=$tableStats[$dbTable]?> rijen)</span>
            <div class="db-actions">
                <button type="button" class="bt bg bsm" onclick="exportTableAsCSV('<?=$dbTable?>')">📥 CSV Export</button>
            </div>
        </div>
        <div class="db-content">
            <table class="db-table-view">
                <thead>
                <tr>
                <?php 
                $resultTest = $db->query('SELECT * FROM ' . $dbTable . ' LIMIT 1');
                $columns = [];
                if ($resultTest) {
                    for ($i = 0; $i < $resultTest->numColumns(); $i++) {
                        $columns[] = $resultTest->columnName($i);
                        echo '<th>' . htmlspecialchars($resultTest->columnName($i)) . '</th>';
                    }
                }
                ?>
                </tr>
                </thead>
                <tbody>
                <?php 
                $rows = [];
                $result = $db->query('SELECT * FROM ' . $dbTable . ' LIMIT 500');
                while ($result && ($row = $result->fetchArray(SQLITE3_ASSOC))) {
                    $rows[] = $row;
                    echo '<tr>';
                    foreach ($columns as $col) {
                        $val = $row[$col];
                        $display = $val === null ? '<span class="db-null">NULL</span>' : '<span class="db-code" title="' . htmlspecialchars((string)$val) . '">' . htmlspecialchars(substr((string)$val, 0, 100)) . '</span>';
                        echo '<td>' . $display . '</td>';
                    }
                    echo '</tr>';
                }
                if (empty($rows)) {
                    echo '<tr><td colspan="' . count($columns) . '" style="text-align:center;color:var(--txd);padding:20px">Geen gegevens</td></tr>';
                }
                ?>
                </tbody>
            </table>
        </div>
        <?php endif; ?>
    </div>
</div>

<script>
function exportTableAsCSV(tableName) {
    var table = document.querySelector('.db-table-view');
    if (!table) return;
    var csv = [];
    var rows = table.querySelectorAll('thead tr, tbody tr');
    rows.forEach(function(row) {
        var cols = [];
        row.querySelectorAll('th, td').forEach(function(cell) {
            var text = cell.textContent || '';
            text = text.replace(/"/g, '""');
            cols.push('"' + text + '"');
        });
        csv.push(cols.join(','));
    });
    var csvContent = 'data:text/csv;charset=utf-8,' + encodeURIComponent(csv.join('\n'));
    var link = document.createElement('a');
    link.setAttribute('href', csvContent);
    link.setAttribute('download', tableName + '_' + new Date().toISOString().slice(0, 10) + '.csv');
    link.click();
}
</script>

<?php
// ========== TARGETS PAGE ==========
elseif($page==='targets'):
    smPerfStart('targets_prep_ms');
    $uiCanTargetsAdd = hasActionPermission($db, 'act_targets_add');
    $uiCanTargetsQueue = hasActionPermission($db, 'act_targets_queue');
    $uiCanTargetsEdit = hasActionPermission($db, 'act_targets_edit');
    $uiCanTargetsDelete = hasActionPermission($db, 'act_targets_delete');
    $uiCanTargetsMove = hasActionPermission($db, 'act_targets_move');
    $uiCanTargetsToggle = hasActionPermission($db, 'act_targets_toggle');
    $uiCanCategoriesManage = hasActionPermission($db, 'act_categories_manage');
    $uiCanGraphsManage = hasActionPermission($db, 'act_graphs_manage');
    $uiCanRrdManage = hasActionPermission($db, 'act_rrd_manage');
    $uiCanMailUse = hasActionPermission($db, 'act_mail_use');
    $cats = getCats($db);
    $catTargets = [];
    foreach ($cats as $cat) {
        $catTargets[$cat['id']] = [];
        $catMap[(int)$cat['id']] = $cat;
    }
    $allCats=$cats;
    $alertList=getAlerts($db);
    $targetEmailSettings = $db->query('SELECT batch_outage_notifications, outage_mail_interval FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC) ?: [];
    $targetsBatchOutageEnabled = (int)($targetEmailSettings['batch_outage_notifications'] ?? 1) === 1;
    $targetsOutageIntervalMin = (int)($targetEmailSettings['outage_mail_interval'] ?? 5);
    $targetsIntervalMap = [5=>'5 min',10=>'10 min',15=>'15 min',30=>'30 min',240=>'4 uur',480=>'8 uur',1440=>'1 dag',2880=>'2 dagen',10080=>'7 dagen'];
    $targetsOutageIntervalLabel = $targetsIntervalMap[$targetsOutageIntervalMin] ?? ($targetsOutageIntervalMin . ' min');
    $targetDraftQueue = getTargetDraftQueue();
    $targetDraftQueueCount = count($targetDraftQueue);
    $publicPendingTargets = getPublicPendingTargets($db);
    $publicPendingCount = count($publicPendingTargets);
    $combinedQueueCount = $targetDraftQueueCount + $publicPendingCount;
    $targetDraftDefaults = getTargetDraftDefaults($db);
    $publicTargetToken = getPublicTargetToken($db);
    $publicScheme = 'http';
    if (!empty($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
        $publicScheme = strtolower(trim((string)explode(',', (string)$_SERVER['HTTP_X_FORWARDED_PROTO'])[0])) === 'https' ? 'https' : 'http';
    } elseif (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        $publicScheme = 'https';
    }
    $publicHost = trim((string)($_SERVER['HTTP_X_FORWARDED_HOST'] ?? $_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost'));
    if (strpos($publicHost, ',') !== false) $publicHost = trim((string)explode(',', $publicHost)[0]);
    if ($publicHost === '') $publicHost = 'localhost';
    $publicBasePath = rtrim(str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/'))), '/');
    if ($publicBasePath === '.' || $publicBasePath === '/') $publicBasePath = '';
    $publicTargetUrl = $publicScheme . '://' . $publicHost . $publicBasePath . '/?p=public_target_add&k=' . urlencode($publicTargetToken);
    $flatTargets = [];
    foreach (getAllTargets($db) as $targetRow) {
        $catId = (int)($targetRow['category_id'] ?? 0);
        if (!isset($catMap[$catId])) continue;
        $catTargets[$catId][] = $targetRow;
        $flatTargets[] = ['cat' => $catMap[$catId], 't' => $targetRow];
    }
    smPerfStop('targets_prep_ms');
?>
<style>
.targets-intro{margin-bottom:2px}
.targets-subtabs{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.targets-subtab{display:inline-flex;align-items:center;gap:6px;padding:8px 12px;border-radius:8px;border:1px solid var(--brd);background:var(--s1);color:var(--tx);text-decoration:none;font-size:12px;font-weight:600}
.targets-subtab.active{background:var(--ac);border-color:var(--ac);color:#fff}
.targets-subtab:not(.active):hover{background:var(--s2)}
.public-url-field.copied{background:#d1fae5!important;border-color:#16a34a!important;transition:background .15s ease,border-color .15s ease}
.search-box{padding:10px 14px;border:1px solid var(--brd);border-radius:4px;background:var(--bg);color:var(--tx);font-size:13px;width:300px;max-width:100%}
.search-box:focus{outline:none;border-color:var(--ac)}
.targets-tab-search{width:100%;max-width:100%;padding:8px 10px;border:1px solid var(--brd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px;margin-bottom:0}
.targets-tab-search:focus{outline:none;border-color:var(--ac)}
.targets-search-row{width:100%;margin-bottom:6px}
.draft-queue-card{margin-bottom:14px}
.draft-queue-intro{font-size:12px;color:var(--txd);margin-bottom:12px}
.draft-queue-layout{display:grid;grid-template-columns:1fr;gap:12px}
.draft-queue-section{border:1px solid var(--brd);border-radius:10px;background:rgba(0,0,0,.07);padding:10px}
.draft-queue-section-title{font-size:12px;font-weight:700;color:var(--tx);margin-bottom:8px}
.draft-queue-list{border:1px solid var(--brd);border-radius:10px;overflow:hidden;background:rgba(0,0,0,.08)}
.draft-queue-row{display:grid;grid-template-columns:minmax(120px,.9fr) minmax(150px,1.1fr) minmax(180px,1.4fr) minmax(80px,.6fr) auto;gap:10px;align-items:center;padding:10px 12px;border-bottom:1px solid var(--brd)}
.draft-queue-row:last-child{border-bottom:none}
.draft-queue-head{background:var(--table-head-bg);color:var(--txd);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.draft-queue-main{font-size:13px;color:var(--tx);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.draft-queue-sub{display:block;font-size:11px;color:var(--txd);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.draft-queue-actions{display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap}
.draft-queue-empty{padding:12px;border:1px dashed var(--brd);border-radius:10px;color:var(--txd);font-size:12px;background:rgba(255,255,255,.02)}
.draft-queue-apply{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}
.draft-queue-apply form{display:flex}
.draft-bulk-form{display:grid;gap:10px}
.draft-bulk-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.draft-bulk-form textarea{min-height:180px}
.draft-bulk-hint{font-size:11px;color:var(--txd);line-height:1.5}
.queue-open-btn{white-space:nowrap}
.custom-graph-list{display:grid;gap:8px}
.custom-graph-row{display:grid;grid-template-columns:minmax(180px,1fr) minmax(150px,.9fr) minmax(110px,.6fr) auto;gap:10px;align-items:center;padding:10px 12px;border:1px solid var(--brd);border-radius:10px;background:linear-gradient(180deg,var(--s1),var(--s2))}
.custom-graph-title{font-size:13px;color:var(--tx);font-weight:700}
.custom-graph-sub{display:block;font-size:11px;color:var(--txd);margin-top:2px}
.custom-graph-actions{display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap}
@media(max-width:860px){.custom-graph-row{grid-template-columns:1fr;gap:8px}.custom-graph-actions{justify-content:flex-start}}
@media(max-width:760px){.draft-bulk-grid{grid-template-columns:1fr}.draft-queue-row{grid-template-columns:1fr;gap:6px}.draft-queue-actions{justify-content:flex-start}}
</style>

<div class="targets-intro"></div>

<?php if(canManage($db)): ?>
<div class="cd" style="margin-bottom:12px">
    <div class="cd-t">Openbare target-invoer zonder login - Inzendingen via deze link worden automatisch als <strong>inactief</strong> toegevoegd.</div>
    <div class="fr" style="grid-template-columns:1fr auto;align-items:end;gap:8px">
        <div class="fg" style="margin:0"><label>Deel deze link met gebruikers</label><input type="text" id="publicTargetUrlInput" class="public-url-field" readonly value="<?=e($publicTargetUrl)?>" onclick="copyPublicTargetUrl(this)" title="Klik om te kopieren"></div>
        <a class="bt bg" href="<?=$publicTargetUrl?>" target="_blank" rel="noopener">Open pagina</a>
    </div>
</div>
<script>
function copyPublicTargetUrl(input){
    if(!input) return;
    input.focus();
    input.select();
    var text = input.value || '';
    var done = function(){
        input.classList.add('copied');
        window.setTimeout(function(){ input.classList.remove('copied'); }, 2000);
    };
    if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(text).then(done).catch(function(){
            try { document.execCommand('copy'); } catch(e) {}
            done();
        });
    } else {
        try { document.execCommand('copy'); } catch(e) {}
        done();
    }
}
</script>
<?php endif; ?>



<?php
usort($flatTargets, static function(array $a, array $b): int {
    $aGroup = (string)($a['cat']['display_name'] ?? $a['cat']['name'] ?? '');
    $bGroup = (string)($b['cat']['display_name'] ?? $b['cat']['name'] ?? '');
    $cmpGroup = strcasecmp($aGroup, $bGroup);
    if ($cmpGroup !== 0) return $cmpGroup;
    $aTarget = (string)($a['t']['display_name'] ?? $a['t']['name'] ?? '');
    $bTarget = (string)($b['t']['display_name'] ?? $b['t']['name'] ?? '');
    $cmpTarget = strcasecmp($aTarget, $bTarget);
    if ($cmpTarget !== 0) return $cmpTarget;
    return ((int)($a['t']['id'] ?? 0)) <=> ((int)($b['t']['id'] ?? 0));
});
?>
<style>
.targets-toolbar{display:flex;gap:8px;align-items:center;justify-content:space-between;margin-bottom:10px;flex-wrap:wrap}
.targets-actions{display:flex;gap:6px;align-items:center;flex-wrap:wrap}
.targets-primary-actions{display:grid;grid-template-columns:repeat(3,minmax(160px,1fr));gap:6px;min-width:min(720px,100%)}
.targets-primary-actions .bt{width:100%;justify-content:center}
.targets-secondary-actions{display:flex;justify-content:flex-end;width:100%;margin-top:6px}
.targets-search{width:260px;max-width:100%;padding:8px 10px;border:1px solid var(--brd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px}
.targets-search:focus{outline:none;border-color:var(--ac)}
.targets-list{border:1px solid var(--brd);border-radius:var(--r);overflow-x:auto;overflow-y:visible}
.targets-head,.target-row{display:grid;grid-template-columns:34px minmax(120px,0.9fr) minmax(120px,1fr) minmax(160px,1.2fr) minmax(200px,1.8fr) minmax(80px,0.6fr) minmax(90px,0.7fr) minmax(120px,0.9fr) minmax(120px,1fr);gap:6px;align-items:center;padding:2px 7px}
.targets-head{background:var(--s2);font-size:11px;font-weight:700;color:var(--txd);text-transform:uppercase;letter-spacing:.35px;border-bottom:1px solid var(--brd)}
.target-row{background:var(--s1);border-bottom:1px solid var(--brd)}
.target-row:last-child{border-bottom:none}
.target-row:hover{background:var(--s2)}
.target-row.target-inactive{opacity:0.65;background:rgba(0,0,0,.05)}
.target-row.target-inactive:hover{background:rgba(0,0,0,.08)}
.targets-head>div,.target-cell{min-width:0;padding:0 2px}
.col-sort-btn{display:inline-flex;align-items:center;gap:4px;width:100%;justify-content:flex-start;background:transparent;border:none;color:inherit;font:inherit;font-weight:inherit;letter-spacing:inherit;text-transform:inherit;padding:0;cursor:pointer}
.col-sort-btn .sort-arrow{opacity:.45;transition:.15s;line-height:1}
.col-sort-btn.active .sort-arrow{opacity:1;color:var(--ac)}
.target-cell{font-size:12px}
.target-main{font-weight:600;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.target-sub{font-family:'Fira Code',monospace;font-size:11px;color:var(--txd);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.target-host{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.target-actions{position:relative;display:flex;justify-content:flex-end}
.action-menu-btn{min-width:94px;justify-content:center}
.target-actions-pop{display:none;position:absolute;top:calc(100% + 4px);right:0;z-index:30;min-width:230px;background:var(--s1);border:1px solid var(--brd);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.16);padding:6px;gap:4px;flex-direction:column}
.target-actions.open .target-actions-pop{display:flex}
.target-actions-pop form{margin:0}
.target-actions-pop .action-item{width:100%;display:flex;align-items:center;justify-content:flex-start;gap:8px;padding:8px 10px;font-size:12px;border:1px solid transparent;border-radius:6px;background:transparent;color:var(--tx);cursor:pointer;text-align:left;line-height:1.25}
.target-actions-pop .action-item .ico{width:18px;min-width:18px;display:inline-flex;align-items:center;justify-content:center;font-size:14px;line-height:1}
.target-actions-pop .action-item .lbl{flex:1;min-width:0}
.target-actions-pop .action-item:hover{background:var(--s2);border-color:var(--brd)}
.target-actions-pop .action-item.danger{color:var(--errfg)}
.status-wrap{display:flex;align-items:center;gap:5px;white-space:nowrap}
.targets-head>div:last-child{text-align:right}
@media(max-width:1100px){
    .targets-head{display:none}
    .target-row{grid-template-columns:34px repeat(2,minmax(0,1fr));row-gap:7px;column-gap:10px;align-items:start;padding:10px}
    .target-row{border-radius:10px;border:1px solid var(--brd);margin:8px;background:var(--bg)}
    .target-row:hover{background:var(--s2)}
    .target-cell{min-width:0}
    .target-cell[data-col="group"]{grid-column:2;grid-row:1}
    .target-cell[data-col="remark"]{grid-column:3;grid-row:1}
    .target-cell[data-col="target"]{grid-column:2;grid-row:2}
    .target-cell[data-col="host"]{grid-column:2/-1;grid-row:3}
    .target-cell[data-col="probe"]{grid-column:2;grid-row:4}
    .target-cell[data-col="status"]{grid-column:3;grid-row:4}
    .target-cell[data-col="mailint"]{grid-column:2;grid-row:5}
    .target-cell[data-col="actions"]{grid-column:2/-1;grid-row:6;padding-top:4px}
    .target-cell[data-col="group"] .target-main,
    .target-cell[data-col="remark"] .target-main,
    .target-cell[data-col="target"] .target-main,
    .target-cell[data-col="host"]{font-size:12px;font-weight:600;line-height:1.25}
    .target-cell[data-col="group"]::before,
    .target-cell[data-col="remark"]::before,
    .target-cell[data-col="target"]::before,
    .target-cell[data-col="host"]::before,
    .target-cell[data-col="probe"]::before,
    .target-cell[data-col="status"]::before,
    .target-cell[data-col="mailint"]::before{display:block;font-size:10px;color:var(--txd);font-weight:600;text-transform:uppercase;letter-spacing:.35px;margin-bottom:2px}
    .target-cell[data-col="group"]::before{content:'Categorie'}
    .target-cell[data-col="remark"]::before{content:'Klantnummer'}
    .target-cell[data-col="target"]::before{content:'Target'}
    .target-cell[data-col="host"]::before{content:'Host'}
    .target-cell[data-col="probe"]::before{content:'Probe'}
    .target-cell[data-col="status"]::before{content:'Status'}
    .target-cell[data-col="mailint"]::before{content:'Uitval mail'}
    .target-cell[data-col="probe"],.target-cell[data-col="status"]{font-size:11px}
    .target-actions{justify-content:flex-start}
    .target-actions-pop{left:0;right:auto;min-width:250px}
}
@media(max-width:640px){
    .targets-toolbar{gap:10px;align-items:stretch}
    .targets-toolbar .targets-actions{width:100%;display:flex;flex-wrap:wrap;gap:6px}
    .targets-toolbar .targets-actions:first-child .bt{flex:1 1 calc(50% - 6px);justify-content:center}
    .targets-primary-actions{grid-template-columns:1fr 1fr;min-width:0;width:100%}
    .targets-secondary-actions{justify-content:stretch}
    .targets-secondary-actions .bt{width:100%;justify-content:center}
    .targets-toolbar .targets-actions #bulkCount{order:3;width:100%;text-align:center;margin:2px 0 0 0;padding-top:2px}
    .targets-list{margin:0 -12px;border-radius:0;border-left:none;border-right:none}
    .target-row{grid-template-columns:24px 1.3fr;padding:10px 10px;margin:0;row-gap:3px;border-radius:0;border-left:none;border-right:none}
    .target-row{position:relative;padding-top:36px}
    .target-cell[data-col="remark"]{position:absolute;left:46px;top:10px;right:38%;grid-column:auto;grid-row:auto;padding:0;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .target-cell[data-col="group"]{position:absolute;right:28px;top:5px;left:65%;grid-column:auto;grid-row:auto;padding:0;text-align:right;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .target-cell[data-col="target"]{grid-column:2;grid-row:1}
    .target-cell[data-col="host"]{grid-column:2;grid-row:2}
    .target-cell[data-col="probe"]{display:none}
    .target-cell[data-col="status"]{position:absolute;top:10px;right:10px;grid-column:auto;grid-row:auto;padding:0}
    .target-cell[data-col="status"]::before{display:none!important}
    .target-cell[data-col="status"] .status-wrap{gap:0}
    .target-cell[data-col="status"] .status-wrap span:last-child{display:none}
    .target-cell[data-col="status"] .st-dot{margin-right:0;width:11px;height:11px}
    .target-cell[data-col="mailint"]{grid-column:2;grid-row:3}
    .target-cell[data-col="actions"]{grid-column:2;grid-row:4}
    .target-cell[data-col="group"] .target-main,
    .target-cell[data-col="remark"] .target-main,
    .target-cell[data-col="target"] .target-main,
    .target-cell[data-col="host"]{font-size:12px;line-height:1.4;white-space:normal;word-break:break-word}
    .target-cell[data-col="group"] .target-main{display:block;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .target-cell[data-col="group"] .target-main,
    .target-cell[data-col="remark"] .target-main,
    .target-cell[data-col="target"] .target-main{display:inline}
    .target-cell[data-col="group"]::before,
    .target-cell[data-col="remark"]::before,
    .target-cell[data-col="target"]::before,
    .target-cell[data-col="host"]::before,
    .target-cell[data-col="mailint"]::before{font-size:11px;display:inline-block;width:96px;margin:0 4px 0 0;letter-spacing:0;text-transform:none}
    .target-cell[data-col="group"]::before{content:'';display:none}
    .target-cell[data-col="remark"]::before{content:'Klantnummer:'}
    .target-cell[data-col="target"]::before{content:'Target:'}
    .target-cell[data-col="host"]::before{content:'Host:'}
    .target-cell[data-col="mailint"]::before{content:'Uitval mail:'}
    .target-actions{width:100%}
    .action-menu-btn{width:100%;min-height:38px}
    .target-actions-pop{position:static;left:auto;right:auto;top:auto;min-width:0;width:100%;margin-top:6px;box-shadow:none}
    .target-actions-pop .action-item{font-size:13px;padding:10px}
    .target-row.swipe-flash-select{background:rgba(39,174,96,.22)!important;transition:background .35s}
    .target-row.swipe-flash-edit{background:rgba(52,152,219,.22)!important;transition:background .35s}
}
</style>
<div class="cd" style="padding:12px;overflow:visible">
    <?php if($uiCanTargetsAdd || $uiCanTargetsEdit || $uiCanTargetsDelete || $uiCanCategoriesManage || $uiCanGraphsManage || $uiCanRrdManage): ?>
    <form method="POST" id="bulkDeleteForm" style="display:none">
    <input type="hidden" name="action" value="bulk_del_tgt"><?=csrfField()?>
    <input type="hidden" name="bulk_ids" id="bulkDeleteIds" value="">
    </form>
    <div class="targets-toolbar">
        <div class="targets-actions">
            <div class="targets-search-row" style="display:flex;gap:6px;align-items:center">
                <input type="text" id="targetsSearchInput" class="targets-tab-search" placeholder="Zoek op naam, groep, host, probe of status..." style="flex:1">
                <select id="targetsFilterSelect" style="padding:8px 10px;border:1px solid var(--brd);border-radius:6px;background:var(--bg);color:var(--tx);font-size:12px;cursor:pointer;flex-shrink:0" onchange="filterTargetRows()">
                    <option value="all">Alle targets</option>
                    <option value="active">Alleen actief</option>
                    <option value="inactive">Alleen inactief</option>
                </select>
            </div>
            <?php if($uiCanTargetsDelete): ?>
            <button type="button" class="bt bg bsm" onclick="setAllTargetChecks(true)">Alles selecteren</button>
            <button type="button" class="bt bg bsm" onclick="setAllTargetChecks(false)">Alles deselecteren</button>
            <span id="bulkCount" style="font-size:12px;color:var(--txd);margin-left:4px">0 geselecteerd</span>
            <?php endif; ?>
        </div>
        <div class="targets-actions">
            <div class="targets-primary-actions">
                <?php if($uiCanTargetsAdd): ?>
                <button class="bt bp bsm" onclick="openM('tgtM');resetTgtForm()">+ Target toevoegen</button>
                <?php endif; ?>
                <?php if($uiCanTargetsDelete): ?>
                <button type="button" class="bt bd bsm" id="bulkDeleteBtn" onclick="submitBulkDeleteTargets()" disabled>Geselecteerde targets verwijderen</button>
                <?php endif; ?>
                <?php if($uiCanCategoriesManage): ?>
                <button class="bt bg bsm" onclick="openM('catM');resetCatForm()">+ Categorie</button>
                <?php endif; ?>
                <?php if($uiCanTargetsEdit): ?>
                <button type="button" class="bt bg bsm" onclick="openM('bulkEditM')">✎ Batch bewerken</button>
                <?php endif; ?>
                <?php if($uiCanGraphsManage): ?>
                <button type="button" class="bt bg bsm" onclick="openGraphComposerFromSelection()">◫ Batch grafiek</button>
                <?php endif; ?>
            </div>
            <div class="targets-secondary-actions">
                <?php if($uiCanRrdManage): ?>
                <button class="bt bw bsm" onclick="openM('clearRrdM')">🗑 Grafiekdata</button>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <?php if(!empty($publicPendingTargets)): ?>
    <style>
    .tgt-pending-card{border:1px solid var(--brd);border-top:2px solid var(--ac);border-radius:10px;background:var(--s1);margin-bottom:10px;overflow:hidden}
    .tgt-pending-header{display:flex;align-items:center;gap:10px;padding:8px 12px;border-bottom:1px solid var(--brd);background:var(--s2)}
    .tgt-pending-badge{display:inline-flex;align-items:center;justify-content:center;min-width:20px;height:20px;padding:0 6px;border-radius:10px;background:var(--ac);color:#000;font-size:11px;font-weight:700;line-height:1}
    .tgt-pending-title{font-size:13px;font-weight:700;color:var(--tx)}
    .tgt-pending-sub{font-size:11px;color:var(--txd);margin-left:auto}
    .tgt-pending-row{display:grid;grid-template-columns:minmax(120px,.9fr) minmax(140px,1fr) minmax(160px,1.2fr) minmax(80px,.6fr) auto;gap:10px;align-items:center;padding:8px 12px;border-bottom:1px solid var(--brd)}
    .tgt-pending-row:last-child{border-bottom:none}
    .tgt-pending-row:hover{background:var(--s2)}
    .tgt-pending-cell{font-size:12px;color:var(--tx);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
    .tgt-pending-cell strong{display:block;color:var(--tx);font-weight:600}
    .tgt-pending-cell span{display:block;font-size:11px;color:var(--txd);margin-top:1px}
    .tgt-pending-actions{display:flex;gap:5px;justify-content:flex-end;flex-wrap:wrap}
    @media(max-width:800px){.tgt-pending-row{grid-template-columns:1fr;gap:6px}.tgt-pending-actions{justify-content:flex-start}}
    </style>
    <div class="tgt-pending-card">
        <div class="tgt-pending-header">
            <span class="tgt-pending-badge"><?=count($publicPendingTargets)?></span>
            <span class="tgt-pending-title">In behandeling</span>
            <span class="tgt-pending-sub">Publieke aanvragen wachten op activering</span>
        </div>
        <div class="tgt-pending-list">
            <?php foreach($publicPendingTargets as $t): ?>
            <?php $pendingHostInfo = (string)($t['host'] ?? ''); if (!empty($t['host_ipv6'])) $pendingHostInfo .= ' | '.$t['host_ipv6']; ?>
            <div class="tgt-pending-row">
                <div class="tgt-pending-cell"><strong><?=e((string)($t['cat_display'] ?? 'Onbekend'))?></strong><span><?=e((string)($t['remark'] ?? '') !== '' ? (string)$t['remark'] : 'Geen klantnummer')?></span></div>
                <div class="tgt-pending-cell"><strong><?=e((string)($t['display_name'] ?? ''))?></strong><span><?=e((string)($t['name'] ?? ''))?></span></div>
                <div class="tgt-pending-cell"><?=e($pendingHostInfo !== '' ? $pendingHostInfo : 'Geen host')?></div>
                <div class="tgt-pending-cell"><span>Ingediend: <?=e((string)($t['created_at_local'] ?? $t['created_at'] ?? '—'))?></span></div>
                <div class="tgt-pending-actions">
                    <?php if($uiCanTargetsToggle): ?>
                    <form method="POST" style="display:inline"><input type="hidden" name="action" value="toggle_target_enabled"><?=csrfField()?><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><button type="submit" class="bt bp bsm" title="Activeer voor monitoring">✓ Activeren</button></form>
                    <?php endif; ?>
                    <?php if($uiCanTargetsEdit): ?>
                    <button type="button" class="bt bg bsm edit-tgt-btn" data-target='<?=e(json_encode($t))?>'>Bewerken</button>
                    <?php endif; ?>
                    <?php if($uiCanTargetsDelete): ?>
                    <form method="POST" style="display:inline"><input type="hidden" name="action" value="del_tgt"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$t['id']?>"><input type="hidden" name="category_id" value="<?=(int)$t['category_id']?>"><button type="submit" class="bt bd bsm" onclick="return confirm('Target verwijderen?')">Verwijderen</button></form>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        </div>
    </div>
    <?php endif; ?>

    <div class="targets-list">
        <div class="targets-head">
            <div></div>
            <div><button type="button" class="col-sort-btn active" data-sort-key="group">Groep <span class="sort-arrow">▲</span></button></div>
            <div><button type="button" class="col-sort-btn" data-sort-key="remark">Klantnummer <span class="sort-arrow">↕</span></button></div>
            <div><button type="button" class="col-sort-btn" data-sort-key="target">Target <span class="sort-arrow">↕</span></button></div>
            <div><button type="button" class="col-sort-btn" data-sort-key="host">Host <span class="sort-arrow">↕</span></button></div>
            <div><button type="button" class="col-sort-btn" data-sort-key="probe">Probe <span class="sort-arrow">↕</span></button></div>
            <div><button type="button" class="col-sort-btn" data-sort-key="status">Status <span class="sort-arrow">↕</span></button></div>
            <div>Uitval mail</div>
            <div style="text-align:right">Acties</div>
        </div>
        <?php foreach($flatTargets as $row):
            $cat = $row['cat'];
            $t = $row['t'];
            $targetKey = $cat['name'] . '|' . $t['name'];
            // Placeholder values - status will be loaded async
            $statusLabel = '⏳ Laden...';
            $health = 'inactive';
            $lossStr = '—';
            $medianStr = '—';
            $groupName = (string)($cat['display_name'] ?? $cat['name'] ?? '');
            $targetName = (string)($t['display_name'] ?? $t['name'] ?? '');
            $targetTech = safeName((string)($t['name'] ?? ''));
            $remarkText = trim((string)($t['remark'] ?? ''));
            $hostInfo = (string)($t['host'] ?? '');
            if (!empty($t['host_ipv6'])) $hostInfo .= ' | '.$t['host_ipv6'];
            $isInactive = ((int)($t['enabled'] ?? 0) === 0);
        ?>
        <div class="target-row<?=$isInactive ? ' target-inactive' : ''?>" data-target-id="<?=(int)$t['id']?>" data-enabled="<?=(int)$t['enabled']?>" data-source="<?=e(strtolower(trim((string)($t['submission_source'] ?? ''))))?>" title="<?=$isInactive ? '⏸ Inactief - wacht op activering' : ''?>">
            <div class="target-cell">
                <?php if($uiCanTargetsDelete): ?>
                <input type="checkbox" class="bulk-target-checkbox" value="<?=(int)$t['id']?>" onchange="updateBulkDeleteState()" title="Selecteer voor bulk verwijderen"><?php if($isInactive): ?><span style="margin-left:4px;font-size:10px;color:#999" title="Inactief">⏸</span><?php endif; ?>
                <?php endif; ?>
            </div>
            <div class="target-cell" data-col="group">
                <div class="target-main"><?=e($groupName)?></div>
            </div>
            <div class="target-cell" data-col="remark" title="<?=e($remarkText !== '' ? $remarkText : '<LEEG>')?>">
                <div class="target-main" style="font-weight:500"><?=e($remarkText !== '' ? $remarkText : '<LEEG>')?></div>
            </div>
            <div class="target-cell" data-col="target">
                <div class="target-main"><?=e($targetName)?></div>
            </div>
            <div class="target-cell target-host" data-col="host" title="<?=e($hostInfo)?>"><?=e($hostInfo)?></div>
            <div class="target-cell" data-col="probe"><?=!empty($t['probe'])?e($t['probe']):'inherit'?></div>
            <div class="target-cell" data-col="status" data-target-key="<?=htmlspecialchars($targetKey)?>" data-target-enabled="<?=(int)$t['enabled']?>" data-target-cat="<?=htmlspecialchars($cat['name'])?>" data-target-name="<?=htmlspecialchars($t['name'])?>">
                <div class="status-wrap"><span class="st-dot <?=$health?>" title="<?=e($statusLabel)?>"></span><span><?=e($statusLabel)?></span></div>
            </div>
            <?php
                $outageMailLabel = 'Uit';
                if ((int)($t['session_notify_enabled'] ?? 0) === 1) {
                        if ($targetsBatchOutageEnabled) {
                            $tgtInt = $t['outage_mail_interval'] ?? null;
                            $outageMailLabel = ($tgtInt !== null) ? ($targetsIntervalMap[(int)$tgtInt] ?? ((int)$tgtInt.' min')) : $targetsOutageIntervalLabel;
                        } else {
                            $outageMailLabel = 'Direct';
                        }
                }
            ?>
            <div class="target-cell" data-col="mailint"><span class="target-main" style="font-weight:500"><?=e($outageMailLabel)?></span></div>
            <div class="target-cell" data-col="actions">
                <?php if($uiCanTargetsEdit || $uiCanTargetsAdd || $uiCanTargetsToggle || $uiCanMailUse || $uiCanRrdManage || $uiCanTargetsDelete): ?>
                <div class="target-actions">
                    <button type="button" class="bt bg bsm action-menu-btn" onclick="toggleTargetActions(this,event)">Acties ▾</button>
                    <div class="target-actions-pop">
                        <?php if($uiCanTargetsEdit): ?>
                        <button type="button" class="action-item edit-tgt-btn" data-target='<?=e(json_encode($t))?>'><span class="ico" aria-hidden="true">✎</span><span class="lbl">Bewerken</span></button>
                        <?php endif; ?>
                        <?php if($uiCanTargetsAdd): ?>
                        <form method="POST"><input type="hidden" name="action" value="clone_tgt"><?=csrfField()?><input type="hidden" name="source_id" value="<?=(int)$t['id']?>"><button type="submit" class="action-item" onclick="return confirm('Target klonen?')"><span class="ico" aria-hidden="true">⧉</span><span class="lbl">Kloon target</span></button></form>
                        <?php endif; ?>
                        <?php if($uiCanTargetsToggle && (int)$t['enabled']===0): ?>
                        <form method="POST"><input type="hidden" name="action" value="toggle_target_enabled"><?=csrfField()?><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><button type="submit" class="action-item" style="color:var(--ok);font-weight:600"><span class="ico" aria-hidden="true">✓</span><span class="lbl">Activeren</span></button></form>
                        <?php elseif($uiCanMailUse && (int)$t['enabled']===1): ?>
                        <form method="POST"><input type="hidden" name="action" value="session_summary_now"><?=csrfField()?><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><input type="hidden" name="return_to" value="targets"><button type="submit" class="action-item" onclick="return confirm('Tussenstand van deze sessie nu per e-mail versturen?')"><span class="ico" aria-hidden="true">📨</span><span class="lbl">Verstuur tussenstand</span></button></form>
                        <form method="POST"><input type="hidden" name="action" value="manual_end_session"><?=csrfField()?><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><input type="hidden" name="return_to" value="targets"><button type="submit" class="action-item" onclick="return confirm('Sessie nu handmatig beëindigen en samenvatting mailen?')"><span class="ico" aria-hidden="true">⏹</span><span class="lbl">Beëindig sessie</span></button></form>
                        <?php endif; ?>
                        <?php if($uiCanRrdManage): ?>
                        <form method="POST"><input type="hidden" name="action" value="clear_rrd_web"><?=csrfField()?><input type="hidden" name="scope" value="target"><input type="hidden" name="category_id" value="<?=(int)$cat['id']?>"><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><button type="submit" class="action-item" onclick="return confirm('Grafiekdata van dit target wissen?')"><span class="ico" aria-hidden="true">🗑</span><span class="lbl">Wis grafiekdata</span></button></form>
                        <form method="POST"><input type="hidden" name="action" value="reset_target_rrd"><?=csrfField()?><input type="hidden" name="target_id" value="<?=(int)$t['id']?>"><button type="submit" class="action-item" onclick="return confirm('WAARSCHUWING: Dit verwijdert PERMANENT alle historische data (grafieken) van dit target!\n\nDit kan NIET ongedaan worden gemaakt!\n\nToelichting:\n- SmokePing zal stoppen\n- Het .rrd bestand wordt verwijderd\n- SmokePing zal opnieuw starten\n- Een terugzet bestand (.bak) wordt gemaakt\n\nWil je echt doorgaan?')"><span class="ico" aria-hidden="true">↻</span><span class="lbl">Reset RRD</span></button></form>
                        <?php endif; ?>
                        <?php if($uiCanTargetsDelete): ?>
                        <form method="POST"><input type="hidden" name="action" value="del_tgt"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$t['id']?>"><input type="hidden" name="category_id" value="<?=(int)$cat['id']?>"><button type="submit" class="action-item danger" onclick="return confirm('Verwijderen?')"><span class="ico" aria-hidden="true">×</span><span class="lbl">Verwijderen</span></button></form>
                        <?php endif; ?>
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>
        <?php endforeach; ?>
    </div>

    <script>
    function closeAllTargetActionMenus(){
        document.querySelectorAll('.target-actions.open').forEach(function(el){ el.classList.remove('open'); });
    }
    function toggleTargetActions(btn, ev){
        if(ev){ ev.preventDefault(); ev.stopPropagation(); }
        var wrap = btn ? btn.closest('.target-actions') : null;
        if(!wrap) return;
        var willOpen = !wrap.classList.contains('open');
        closeAllTargetActionMenus();
        if(willOpen) wrap.classList.add('open');
    }
    document.addEventListener('click', function(){ closeAllTargetActionMenus(); });
    document.addEventListener('keydown', function(e){ if(e.key === 'Escape') closeAllTargetActionMenus(); });
    document.querySelectorAll('.target-actions-pop').forEach(function(pop){
        pop.addEventListener('click', function(e){ e.stopPropagation(); });
    });

    var targetSortState = { key: 'group', dir: 'asc' };
    function getTargetCellValue(row, key){
        var cell = row.querySelector('.target-cell[data-col="' + key + '"]');
        if(!cell) return '';
        return (cell.textContent || '').trim().toLowerCase();
    }
    function updateTargetSortButtons(){
        document.querySelectorAll('.col-sort-btn').forEach(function(btn){
            var key = btn.getAttribute('data-sort-key');
            var arrow = btn.querySelector('.sort-arrow');
            btn.classList.toggle('active', key === targetSortState.key);
            if(!arrow) return;
            if(key !== targetSortState.key){ arrow.textContent = '↕'; return; }
            arrow.textContent = targetSortState.dir === 'asc' ? '▲' : '▼';
        });
    }
    function sortTargetRowsBy(key){
        var list = document.querySelector('.targets-list');
        if(!list) return;
        var rows = Array.from(list.querySelectorAll('.target-row'));
        if(rows.length <= 1) return;
        if(targetSortState.key === key){
            targetSortState.dir = targetSortState.dir === 'asc' ? 'desc' : 'asc';
        } else {
            targetSortState.key = key;
            targetSortState.dir = 'asc';
        }
        var dir = targetSortState.dir === 'asc' ? 1 : -1;
        rows.forEach(function(row, idx){ row.dataset.sortIndex = String(idx); });
        rows.sort(function(a, b){
            var av = getTargetCellValue(a, key);
            var bv = getTargetCellValue(b, key);
            var cmp = av.localeCompare(bv, 'nl', {numeric:true, sensitivity:'base'});
            if(cmp !== 0) return cmp * dir;
            return (parseInt(a.dataset.sortIndex || '0', 10) - parseInt(b.dataset.sortIndex || '0', 10));
        });
        rows.forEach(function(row){ list.appendChild(row); });
        updateTargetSortButtons();
    }
    function filterTargetRows(){
        var input = document.getElementById('targetsSearchInput');
        var sel = document.getElementById('targetsFilterSelect');
        var q = input ? (input.value || '').trim().toLowerCase() : '';
        var filter = sel ? (sel.value || 'all') : 'all';
        document.querySelectorAll('.targets-list .target-row').forEach(function(row){
            var enabled = row.getAttribute('data-enabled');
            var source = (row.getAttribute('data-source') || '').toLowerCase();
            var matchFilter = true;
            if(filter === 'active') matchFilter = enabled === '1';
            else if(filter === 'inactive') matchFilter = enabled === '0' && source !== 'public_queue';
            else if(filter === 'queue') matchFilter = source === 'public_queue';
            if(!matchFilter){ row.style.display = 'none'; return; }
            if(q === ''){ row.style.display = ''; return; }
            var text = (row.textContent || '').toLowerCase();
            row.style.display = text.indexOf(q) !== -1 ? '' : 'none';
        });
    }
    document.querySelectorAll('.col-sort-btn[data-sort-key]').forEach(function(btn){
        btn.addEventListener('click', function(){
            var key = btn.getAttribute('data-sort-key');
            if(key) sortTargetRowsBy(key);
        });
    });
    var targetsSearchInput = document.getElementById('targetsSearchInput');
    if(targetsSearchInput){
        targetsSearchInput.addEventListener('input', filterTargetRows);
    }
    updateTargetSortButtons();
    </script>

    <?php if($uiCanTargetsDelete || $uiCanTargetsEdit): ?>
    <script>
    function getSelectedTargetIds(){
        var ids = [];
        document.querySelectorAll('.bulk-target-checkbox:checked').forEach(function(cb){
            if(cb && cb.value) ids.push(cb.value);
        });
        return ids;
    }
    function updateBulkDeleteState(){
        var selected = getSelectedTargetIds();
        var countEl = document.getElementById('bulkCount');
        var btn = document.getElementById('bulkDeleteBtn');
        if(countEl) countEl.textContent = selected.length + ' geselecteerd';
        if(btn) btn.disabled = selected.length === 0;
    }
    function setAllTargetChecks(state){
        document.querySelectorAll('.bulk-target-checkbox').forEach(function(cb){ cb.checked = state; });
        updateBulkDeleteState();
    }
    function submitBulkDeleteTargets(){
        var ids = getSelectedTargetIds();
        if(ids.length <= 0){ alert('Selecteer eerst minimaal 1 target.'); return; }
        if(!confirm('Weet je zeker dat je ' + ids.length + ' target(s) wilt verwijderen?')) return;
        var form = document.getElementById('bulkDeleteForm');
        var hid = document.getElementById('bulkDeleteIds');
        if(!form || !hid){ alert('Bulk verwijderen is tijdelijk niet beschikbaar.'); return; }
        hid.value = ids.join(',');
        form.submit();
    }
    updateBulkDeleteState();

    // Async load target statuses for performance optimization
    (function(){
        var statusCells = document.querySelectorAll('.target-cell[data-col="status"][data-target-key]');
        if(statusCells.length === 0) return;
        var batch = [];
        statusCells.forEach(function(cell){
            batch.push({
                cat: cell.getAttribute('data-target-cat'),
                name: cell.getAttribute('data-target-name'),
                enabled: parseInt(cell.getAttribute('data-target-enabled') || '0')
            });
        });
        var form = new FormData();
        form.append('action', 'get_target_statuses');
        form.append('targets', JSON.stringify(batch));
        fetch(window.location.href, {method:'POST', body:form})
            .then(r => r.json())
            .then(function(data){
                if(!Array.isArray(data)) return;
                data.forEach(function(item){
                    var cell = document.querySelector('.target-cell[data-col="status"][data-target-key="' + CSS.escape(item.key) + '"]');
                    if(!cell) return;
                    var wrap = cell.querySelector('.status-wrap');
                    if(!wrap) return;
                    var dot = wrap.querySelector('.st-dot');
                    var label = wrap.querySelector('span:last-child');
                    if(dot) {
                        dot.className = 'st-dot ' + item.class;
                        dot.title = item.label;
                    }
                    if(label) label.textContent = item.label;
                });
            })
            .catch(function(){});
    })();

    // Swipe: links→rechts = selecteren, rechts→links = bewerken
    (function(){
        var THRESHOLD=60,MAX_V=80,MAX_T=500;
        document.querySelectorAll('.target-row').forEach(function(row){
            var sx,sy,st;
            row.addEventListener('touchstart',function(e){
                var t=e.touches[0];sx=t.clientX;sy=t.clientY;st=Date.now();
            },{passive:true});
            row.addEventListener('touchend',function(e){
                if(sx===undefined)return;
                var t=e.changedTouches[0];
                var dx=t.clientX-sx,dy=Math.abs(t.clientY-sy),dt=Date.now()-st;
                sx=undefined;
                if(dy>MAX_V||dt>MAX_T)return;
                if(dx>=THRESHOLD){
                    var cb=row.querySelector('.bulk-target-checkbox');
                    if(cb){cb.checked=!cb.checked;updateBulkDeleteState();}
                    row.classList.add('swipe-flash-select');
                    setTimeout(function(){row.classList.remove('swipe-flash-select');},400);
                }else if(dx<=-THRESHOLD){
                    var eb=row.querySelector('.edit-tgt-btn');
                    if(eb)eb.click();
                    row.classList.add('swipe-flash-edit');
                    setTimeout(function(){row.classList.remove('swipe-flash-edit');},350);
                }
            },{passive:true});
        });
    })();
    </script>
    <?php endif; ?>
</div>
</div>

<?php if($uiCanTargetsEdit): ?>
<style>
#bulkEditM .md{max-width:none;width:98vw;height:92vh;display:flex;flex-direction:column;padding:12px}
#bulkEditM .bulk-head{display:flex;align-items:center;justify-content:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
#bulkEditM h3{margin:0;font-size:16px}
#bulkEditM .bulk-search{width:min(420px,92vw);max-width:100%;padding:8px 10px;height:34px;border:1px solid var(--brd);border-radius:8px;background:var(--bg);color:var(--tx);font-size:12px}
#bulkEditM .bulk-search:focus{outline:none;border-color:var(--ac)}
#bulkEditM .bulk-sub{font-size:11px;color:var(--txd);margin-bottom:8px;text-align:center}
#bulkEditM .bulk-wrap{flex:1;min-height:0;overflow:auto;border:1px solid var(--brd);border-radius:8px}
#bulkEditM .tb{width:100%;min-width:1460px;font-size:11px;line-height:1.2;table-layout:fixed}
#bulkEditM .tb th,#bulkEditM .tb td{padding:5px 7px;white-space:nowrap;vertical-align:middle;text-align:left}
#bulkEditM .tb th{background:var(--s2)}
#bulkEditM .bulk-sort-btn{display:inline-flex;align-items:center;justify-content:space-between;gap:5px;width:100%;padding:0;background:transparent;border:none;color:inherit;font:inherit;font-weight:700;cursor:pointer}
#bulkEditM .bulk-sort-btn .sort-arrow{opacity:.5}
#bulkEditM .bulk-sort-btn.active .sort-arrow{opacity:1;color:var(--ac)}
#bulkEditM input[type="text"],#bulkEditM input[type="number"],#bulkEditM select{font-size:11px;padding:4px 6px;height:30px}
#bulkEditM input[type="checkbox"]{transform:scale(.9)}
#bulkEditM .cell-fit{width:100%}
@media(max-width:900px){#bulkEditM .bulk-head{justify-content:flex-start}#bulkEditM .bulk-search{width:100%}}
</style>
<div class="mo" id="bulkEditM" onclick="if(event.target===this)closeM('bulkEditM')"><div class="md">
<div class="bulk-head">
<h3>Batch bewerken (meerdere targets in 1 keer)</h3>
<input type="text" id="bulkEditSearch" class="bulk-search" placeholder="Zoek in categorie, target, host, klantnummer, alert, e-mail...">
</div>
<p class="bulk-sub">Pas meerdere targets aan en klik daarna 1 keer op opslaan. De configuratie wordt daarna 1 keer opnieuw geladen.</p>
<form method="POST">
<input type="hidden" name="action" value="bulk_edit_tgt"><?=csrfField()?>
<div class="bulk-wrap">
<table class="tb" id="bulkEditTable">
<colgroup>
<col style="width:56px">
<col style="width:140px">
<col style="width:130px">
<col style="width:150px">
<col style="width:165px">
<col style="width:165px">
<col style="width:100px">
<col style="width:130px">
<col style="width:120px">
<col style="width:110px">
<col style="width:95px">
<col style="width:210px">
<col style="width:90px">
<col style="width:70px">
</colgroup>
<thead>
<tr>
<th><button type="button" class="bulk-sort-btn active" data-sort-key="id">ID <span class="sort-arrow">▲</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="category">Categorie <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="internal">Naam intern <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="display">Weergavenaam <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="host">IPv4/Host <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="ipv6">IPv6 <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="remark">Klantnummer <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="alert">Alert <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="mailint">Mail interval <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="session">Sessie <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="notify">Mail bij sessie <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="emails">Mailadressen <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="order">Volgorde <span class="sort-arrow">↕</span></button></th>
<th><button type="button" class="bulk-sort-btn" data-sort-key="active">Actief <span class="sort-arrow">↕</span></button></th>
</tr>
</thead>
<tbody id="bulkEditTbody">
<?php foreach($flatTargets as $idx=>$row): $cat=$row['cat']; $t=$row['t']; $tid=(int)$t['id'];
    $catLabel=(string)($cat['display_name'] ?? $cat['name'] ?? '');
    $internalLabel=(string)($t['name'] ?? '');
    $displayLabel=(string)($t['display_name'] ?? '');
    $hostLabel=(string)($t['host'] ?? '');
    $hostIpv6Label=(string)($t['host_ipv6'] ?? '');
    $remarkLabel=(string)($t['remark'] ?? '');
    $alertLabel=(string)($t['alert'] ?? '');
    $sessionLabel=(string)($t['session_duration'] ?? 'unlimited');
    $notifyLabel=((int)($t['session_notify_enabled'] ?? 0)===1)?'ja':'nee';
    $mailLabel=(string)($t['session_notify_email'] ?? '');
    $sortLabel=(int)($t['sort_order'] ?? 0);
    $activeLabel=((int)($t['enabled'] ?? 0)===1)?'ja':'nee';
    $tOmi=$t['outage_mail_interval']??null;
    $mailIntLabel=$tOmi===null ? ('globaal '.$targetsOutageIntervalLabel) : ((string)((int)$tOmi));
?>
<tr data-sort-index="<?=$idx?>" data-k-id="<?=$tid?>" data-k-category="<?=e(strtolower($catLabel))?>" data-k-internal="<?=e(strtolower($internalLabel))?>" data-k-display="<?=e(strtolower($displayLabel))?>" data-k-host="<?=e(strtolower($hostLabel))?>" data-k-ipv6="<?=e(strtolower($hostIpv6Label))?>" data-k-remark="<?=e(strtolower($remarkLabel))?>" data-k-alert="<?=e(strtolower($alertLabel))?>" data-k-mailint="<?=e(strtolower($mailIntLabel))?>" data-k-session="<?=e(strtolower($sessionLabel))?>" data-k-notify="<?=$notifyLabel?>" data-k-emails="<?=e(strtolower($mailLabel))?>" data-k-order="<?=$sortLabel?>" data-k-active="<?=$activeLabel?>">
<td>
<input type="hidden" name="target_ids[]" value="<?=$tid?>">
<code><?=$tid?></code>
</td>
<td>
<select name="be_category_id[<?=$tid?>]" class="cell-fit">
<?php foreach($allCats as $c): ?>
<option value="<?=(int)$c['id']?>" <?=((int)$c['id']===(int)$t['category_id'])?'selected':''?> style="max-width:120px"><?=e($c['display_name'])?></option>
<?php endforeach; ?>
</select>
</td>
<td><code><?=e($t['name'])?></code></td>
<td><input type="text" name="be_display_name[<?=$tid?>]" value="<?=e($t['display_name'])?>" class="cell-fit"></td>
<td><input type="text" name="be_host[<?=$tid?>]" value="<?=e($t['host'])?>" class="cell-fit"></td>
<td><input type="text" name="be_host_ipv6[<?=$tid?>]" value="<?=e($t['host_ipv6'] ?? '')?>" class="cell-fit"></td>
<td><input type="text" name="be_remark[<?=$tid?>]" value="<?=e($t['remark'] ?? '')?>" style="width:80px"></td>
<td>
<select name="be_alert[<?=$tid?>]" class="cell-fit">
<option value="">Geen</option>
<?php foreach($alertList as $al): ?>
<option value="<?=e($al['name'])?>" <?=((string)($t['alert'] ?? '') === (string)$al['name'])?'selected':''?>><?=e($al['display_name'])?></option>
<?php endforeach; ?>
</select>
</td>
<td>
<select name="be_outage_mail_interval[<?=$tid?>]" class="cell-fit">
<option value="" <?=$tOmi===null?'selected':''?>>Globaal (<?=e($targetsOutageIntervalLabel)?>)</option>
<?php foreach([5=>'5 min',10=>'10 min',15=>'15 min',30=>'30 min',240=>'4 uur',480=>'8 uur',1440=>'1 dag',2880=>'2 dagen',10080=>'7 dagen'] as $v=>$l):?>
<option value="<?=$v?>" <?=((int)($tOmi??-1)===$v)?'selected':''?>><?=e($l)?></option>
<?php endforeach;?>
</select>
</td>
<td>
<select name="be_session_duration[<?=$tid?>]" class="cell-fit">
<?php $sd=(string)($t['session_duration'] ?? 'unlimited'); ?>
<option value="unlimited" <?=$sd==='unlimited'?'selected':''?>>Onbeperkt</option>
<option value="1m" <?=$sd==='1m'?'selected':''?>>1m</option>
<option value="1h" <?=$sd==='1h'?'selected':''?>>1h</option>
<option value="6h" <?=$sd==='6h'?'selected':''?>>6h</option>
<option value="12h" <?=$sd==='12h'?'selected':''?>>12h</option>
<option value="24h" <?=$sd==='24h'?'selected':''?>>24h</option>
<option value="7d" <?=$sd==='7d'?'selected':''?>>7d</option>
<option value="30d" <?=$sd==='30d'?'selected':''?>>30d</option>
</select>
</td>
<td style="text-align:center"><input type="checkbox" name="be_session_notify_enabled[<?=$tid?>]" value="1" <?=((int)($t['session_notify_enabled'] ?? 0)===1)?'checked':''?>></td>
<td><input type="text" name="be_session_notify_email[<?=$tid?>]" value="<?=e($t['session_notify_email'] ?? '')?>" placeholder="mail1@x.nl, mail2@x.nl" class="cell-fit"></td>
<td><input type="number" name="be_sort_order[<?=$tid?>]" value="<?=(int)($t['sort_order'] ?? 0)?>" style="width:90px"></td>
<td style="text-align:center"><input type="checkbox" name="be_enabled[<?=$tid?>]" value="1" <?=((int)$t['enabled']===1)?'checked':''?>></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('bulkEditM')">Annuleren</button>
<button type="submit" class="bt bp" onclick="return confirm('Alle wijzigingen in 1 keer opslaan?')">Alles in 1 keer opslaan</button>
</div>
</form>
</div></div>
<script>
(function(){
    var modal = document.getElementById('bulkEditM');
    if(!modal) return;
    var tbody = document.getElementById('bulkEditTbody');
    var search = document.getElementById('bulkEditSearch');
    if(!tbody) return;
    var state = {key:'id',dir:'asc'};
    var numericKeys = {id:true,order:true};

    function getKey(row,key){
        return (row.getAttribute('data-k-' + key) || '').toLowerCase();
    }
    function updateSortButtons(){
        modal.querySelectorAll('.bulk-sort-btn').forEach(function(btn){
            var key = btn.getAttribute('data-sort-key');
            var arrow = btn.querySelector('.sort-arrow');
            var active = key === state.key;
            btn.classList.toggle('active', active);
            if(!arrow) return;
            arrow.textContent = active ? (state.dir === 'asc' ? '▲' : '▼') : '↕';
        });
    }
    function sortRows(key){
        var rows = Array.from(tbody.querySelectorAll('tr'));
        if(rows.length < 2) return;
        if(state.key === key){
            state.dir = state.dir === 'asc' ? 'desc' : 'asc';
        } else {
            state.key = key;
            state.dir = 'asc';
        }
        var dir = state.dir === 'asc' ? 1 : -1;
        rows.sort(function(a,b){
            var av = getKey(a,key);
            var bv = getKey(b,key);
            var cmp = 0;
            if(numericKeys[key]){
                cmp = (parseInt(av || '0',10) - parseInt(bv || '0',10));
            } else {
                cmp = av.localeCompare(bv, 'nl', {numeric:true, sensitivity:'base'});
            }
            if(cmp !== 0) return cmp * dir;
            return (parseInt(a.getAttribute('data-sort-index') || '0',10) - parseInt(b.getAttribute('data-sort-index') || '0',10));
        });
        rows.forEach(function(r){ tbody.appendChild(r); });
        updateSortButtons();
        applySearch();
    }
    function applySearch(){
        var q = ((search && search.value) ? search.value : '').trim().toLowerCase();
        Array.from(tbody.querySelectorAll('tr')).forEach(function(row){
            if(!q){ row.style.display=''; return; }
            var txt = (row.textContent || '').toLowerCase();
            row.style.display = txt.indexOf(q) !== -1 ? '' : 'none';
        });
    }
    modal.querySelectorAll('.bulk-sort-btn').forEach(function(btn){
        btn.addEventListener('click', function(){
            var key = btn.getAttribute('data-sort-key');
            if(key) sortRows(key);
        });
    });
    if(search){ search.addEventListener('input', applySearch); }
    updateSortButtons();
})();
</script>
<?php endif; ?>

<!-- Global JavaScript Helpers -->
<script>
// Form reset functions
function resetCatForm() {
    document.getElementById('ecA').value = 'add_cat';
    document.getElementById('ecTitle').textContent = 'Nieuwe Categorie';
    document.getElementById('ecBtn').textContent = 'Toevoegen';
    document.getElementById('catForm').reset();
    document.getElementById('ecER').style.display = 'none';
}

function resetTgtForm() {
    document.getElementById('etA').value = 'add_tgt';
    document.getElementById('etTitle').textContent = 'Nieuw Target toevoegen';
    document.getElementById('etBtn').textContent = 'Target toevoegen';
    document.getElementById('tgtForm').reset();
    document.getElementById('etQueueId').value = '';
    document.getElementById('etAfterAdd').value = '';
    document.getElementById('etCat').value = <?=json_encode((string)($targetDraftDefaults['category_id'] ?? ($allCats[0]['id'] ?? '')))?>;
    document.getElementById('etAl').value = <?=json_encode((string)($targetDraftDefaults['alert'] ?? getDefaultTargetAlertName($db)))?>;
    document.getElementById('etSD').value = <?=json_encode((string)($targetDraftDefaults['session_duration'] ?? 'unlimited'))?>;
    document.getElementById('etSNE').checked = <?=!empty($targetDraftDefaults['session_notify_enabled']) ? 'true' : 'false'?>;
    document.getElementById('etSNEml').value = <?=json_encode((string)($targetDraftDefaults['session_notify_email'] ?? $_formDefaultEmail))?>;
    document.getElementById('etOI').value = <?=json_encode((string)($targetDraftDefaults['outage_mail_interval'] ?? ''))?>;
    document.getElementById('etER').style.display = 'none';
    document.getElementById('etBtnNext').style.display = '';
}

function setTargetDraftSubmitMode(mode) {
    document.getElementById('etAfterAdd').value = mode || '';
}

// Global edit target handler - accessible from all tabs
function initEditTargetButtons() {
    document.querySelectorAll('.edit-tgt-btn').forEach(function(btn){
        btn.removeEventListener('click', handleEditTarget); // Prevent duplicates
        btn.addEventListener('click', handleEditTarget);
    });
    document.querySelectorAll('.edit-custom-graph-btn').forEach(function(btn){
        btn.removeEventListener('click', handleEditCustomGraph);
        btn.addEventListener('click', handleEditCustomGraph);
    });
}

function handleEditTarget(e) {
    e.stopPropagation();
    e.preventDefault();
    var d = JSON.parse(this.getAttribute('data-target'));
    document.getElementById("etA").value = "edit_tgt";
    document.getElementById("etTitle").textContent = "Target Bewerken";
    document.getElementById("etBtn").textContent = "Opslaan";
    document.getElementById("etQueueId").value = "";
    document.getElementById("etAfterAdd").value = "";
    document.getElementById("etId").value = d.id;
    document.getElementById("etCat").value = d.category_id;
    document.getElementById("etD").value = d.display_name;
    document.getElementById("etH").value = d.host;
    document.getElementById("etH6").value = d.host_ipv6 || "";
    document.getElementById("etR").value = d.remark || "";
    document.getElementById("etAl").value = d.alert || "";
    document.getElementById("etSD").value = d.session_duration || "unlimited";
    document.getElementById("etSNE").checked = (d.session_notify_enabled == 1);
    document.getElementById("etSNEml").value = d.session_notify_email || <?=json_encode($_formDefaultEmail)?>;
    document.getElementById("etOI").value = d.outage_mail_interval || "";
    document.getElementById("etEn").checked = d.enabled == 1;
    document.getElementById("etER").style.display = "flex";
    document.getElementById('etBtnNext').style.display = 'none';
    openM("tgtM");
}

function resetGraphComposerForm() {
    var form = document.getElementById('graphComposerForm');
    if(form) form.reset();
    document.getElementById('graphComposerId').value = '';
    document.getElementById('graphComposerTitle').textContent = 'Nieuwe samengestelde grafiek';
    document.getElementById('graphComposerName').value = '';
    document.getElementById('graphComposerGroup').value = 'Samengestelde grafieken';
    document.querySelectorAll('.graph-target-checkbox').forEach(function(cb){ cb.checked = false; });
    document.querySelectorAll('.graph-mode-select').forEach(function(sel){ sel.value = 'both'; });
    updateGraphComposerState();
}

function updateGraphComposerState() {
    var count = document.querySelectorAll('.graph-target-checkbox:checked').length;
    var label = document.getElementById('graphComposerCount');
    if(label) label.textContent = count + ' geselecteerd';
}

function filterGraphComposerTargets() {
    var input = document.getElementById('graphComposerSearch');
    var query = input ? (input.value || '').trim().toLowerCase() : '';
    document.querySelectorAll('.graph-target-row').forEach(function(row){
        if(!query){ row.style.display = ''; return; }
        row.style.display = (row.getAttribute('data-search') || '').indexOf(query) !== -1 ? '' : 'none';
    });
}

function graphComposerSelectVisible(state) {
    document.querySelectorAll('.graph-target-row').forEach(function(row){
        if(row.style.display === 'none') return;
        var cb = row.querySelector('.graph-target-checkbox');
        if(cb) cb.checked = state;
    });
    updateGraphComposerState();
}

function openGraphComposerFromSelection() {
    var ids = getSelectedTargetIds();
    if(ids.length <= 0){ alert('Selecteer eerst minimaal 1 target in het overzicht.'); return; }
    resetGraphComposerForm();
    ids.forEach(function(id){
        var cb = document.querySelector('.graph-target-checkbox[value="' + id + '"]');
        if(cb) cb.checked = true;
    });
    updateGraphComposerState();
    openM('graphComposerM');
}

function handleEditCustomGraph(e) {
    e.preventDefault();
    e.stopPropagation();
    var graph = JSON.parse(this.getAttribute('data-graph'));
    resetGraphComposerForm();
    document.getElementById('graphComposerTitle').textContent = 'Samengestelde grafiek bewerken';
    document.getElementById('graphComposerId').value = graph.id || '';
    document.getElementById('graphComposerName').value = graph.title || '';
    document.getElementById('graphComposerGroup').value = graph.group_name || 'Samengestelde grafieken';
    (graph.members || []).forEach(function(member){
        var cb = document.querySelector('.graph-target-checkbox[value="' + member.target_id + '"]');
        if(cb) cb.checked = true;
        var sel = document.querySelector('.graph-mode-select[data-target-id="' + member.target_id + '"]');
        if(sel) sel.value = member.mode || 'both';
    });
    updateGraphComposerState();
    openM('graphComposerM');
}

// Initialize on page load
if(document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initEditTargetButtons);
} else {
    initEditTargetButtons();
}
<?php if(isset($_GET['tgt_continue'])): ?>
document.addEventListener('DOMContentLoaded', function(){ resetTgtForm(); openM('tgtM'); document.getElementById('etD').focus(); });
<?php endif; ?>
</script>

<?php if($uiCanGraphsManage): ?>
<style>
#graphComposerM .md{max-width:none;width:96vw;max-height:92vh;display:flex;flex-direction:column;padding:14px}
#graphComposerM .graph-head{display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:10px}
#graphComposerM .graph-search{width:min(380px,92vw);padding:8px 10px;height:36px;border:1px solid var(--brd);border-radius:8px;background:var(--bg);color:var(--tx);font-size:12px}
#graphComposerM .graph-summary{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
#graphComposerM .graph-summary span{font-size:12px;color:var(--txd)}
#graphComposerM .graph-list{flex:1;min-height:0;overflow:auto;border:1px solid var(--brd);border-radius:10px;padding:8px;background:rgba(0,0,0,.08)}
#graphComposerM .graph-target-row{display:grid;grid-template-columns:minmax(260px,1.3fr) minmax(120px,.5fr);gap:10px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--brd)}
#graphComposerM .graph-target-row:last-child{border-bottom:none}
#graphComposerM .graph-target-main{display:flex;align-items:flex-start;gap:10px;color:var(--tx);font-size:13px;min-width:0}
#graphComposerM .graph-target-main input{margin-top:2px}
#graphComposerM .graph-target-main strong{display:block;font-size:13px;color:var(--tx)}
#graphComposerM .graph-target-main span span{display:block;font-size:11px;color:var(--txd);margin-top:2px;white-space:normal;word-break:break-word}
#graphComposerM .graph-mode-select{height:34px}
@media(max-width:800px){#graphComposerM .graph-target-row{grid-template-columns:1fr}}
</style>
<div class="mo" id="graphComposerM" onclick="if(event.target===this)closeM('graphComposerM')"><div class="md">
<div class="graph-head"><h3 id="graphComposerTitle">Nieuwe samengestelde grafiek</h3><input type="text" id="graphComposerSearch" class="graph-search" placeholder="Zoek op categorie, target, host of klantnummer" oninput="filterGraphComposerTargets()"></div>
<form method="POST" id="graphComposerForm" style="display:flex;flex-direction:column;min-height:0;flex:1">
<input type="hidden" name="action" value="save_custom_graph"><?=csrfField()?>
<input type="hidden" name="graph_id" id="graphComposerId">
<div class="fr">
<div class="fg"><label>Map / categorie</label><input type="text" name="graph_group_name" id="graphComposerGroup" value="Samengestelde grafieken" required></div>
<div class="fg"><label>Grafiektitel</label><input type="text" name="graph_title" id="graphComposerName" placeholder="Bijv. Datacenter core links" required></div>
</div>
<div class="graph-summary"><span id="graphComposerCount">0 geselecteerd</span><button type="button" class="bt bg bsm" onclick="graphComposerSelectVisible(true)">Zichtbare selecteren</button><button type="button" class="bt bg bsm" onclick="graphComposerSelectVisible(false)">Zichtbare deselecteren</button></div>
<div class="graph-list">
<?php foreach($flatTargets as $row): $cat=$row['cat']; $t=$row['t']; $tid=(int)$t['id']; $graphSearchText = strtolower(trim(($cat['display_name'] ?? '').' '.($t['display_name'] ?? '').' '.($t['host'] ?? '').' '.($t['host_ipv6'] ?? '').' '.($t['remark'] ?? ''))); ?>
<div class="graph-target-row" data-search="<?=e($graphSearchText)?>">
    <label class="graph-target-main"><input type="checkbox" class="graph-target-checkbox" name="graph_target_ids[]" value="<?=$tid?>" onchange="updateGraphComposerState()"><span><strong><?=e((string)($t['display_name'] ?? ''))?></strong><span><?=e((string)($cat['display_name'] ?? ''))?> · <?=e((string)($t['host'] ?? '') !== '' ? (string)$t['host'] : 'geen IPv4/host')?><?=!empty($t['host_ipv6']) ? ' · '.e((string)$t['host_ipv6']) : ''?><?=!empty($t['remark']) ? ' · '.e((string)$t['remark']) : ''?></span></span></label>
    <select name="graph_mode[<?=$tid?>]" class="graph-mode-select" data-target-id="<?=$tid?>"><option value="both">IPv4 + IPv6</option><option value="ipv4">Alleen IPv4</option><option value="ipv6">Alleen IPv6</option></select>
</div>
<?php endforeach; ?>
</div>
<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:12px"><button type="button" class="bt bg" onclick="closeM('graphComposerM')">Annuleren</button><button type="submit" class="bt bp" onclick="return confirm('Samengestelde grafiek opslaan en SmokePing-config opnieuw opbouwen?')">Grafiek opslaan</button></div>
</form>
</div></div>
<?php endif; ?>

<!-- MODALS -->

<?php if($uiCanCategoriesManage): ?>
<div class="mo" id="catM" onclick="if(event.target===this)closeM('catM')"><div class="md">
<h3 id="ecTitle">Nieuwe Categorie</h3>
<form method="POST" id="catForm"><input type="hidden" name="action" id="ecA" value="add_cat"><?=csrfField()?>
<input type="hidden" name="id" id="ecId">
<div class="fr"><div class="fg"><label>Naam (intern)</label><input type="text" name="name" id="ecN" required pattern="[a-zA-Z0-9_]+"></div>
<div class="fg"><label>Weergavenaam</label><input type="text" name="display_name" id="ecD" required></div></div>
<div class="fr"><div class="fg"><label>Volgorde</label><input type="number" name="sort_order" id="ecS" value="0"></div>
<div class="fg" style="color:var(--txd);font-size:12px"><em>Probe wordt per target bepaald.</em></div></div>
<div class="fg"><label>Opmerking</label><input type="text" name="remark" id="ecR"></div>
<div class="fg ck" id="ecER" style="display:none"><input type="checkbox" name="enabled" id="ecE" checked><label for="ecE">Actief</label></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('catM')">Annuleren</button>
<button type="submit" class="bt bp" id="ecBtn">Toevoegen</button></div>
</form></div></div>
<?php endif; ?>

<?php if($uiCanTargetsAdd): ?>
<div class="mo" id="tgtM" onclick="if(event.target===this)closeM('tgtM')"><div class="md">
<h3 id="etTitle">Nieuw Target toevoegen</h3>
<form method="POST" id="tgtForm" class="tgt-form"><input type="hidden" name="action" id="etA" value="add_tgt"><?=csrfField()?>
<input type="hidden" name="id" id="etId">
<input type="hidden" name="queue_id" id="etQueueId">
<input type="hidden" name="after_add" id="etAfterAdd" value="">
<div class="fg"><label>Categorie</label><select name="category_id" id="etCat">
<?php foreach($allCats as $c):?><option value="<?=(int)$c['id']?>"><?=e($c['display_name'])?></option><?php endforeach;?></select></div>
<div class="target-form-main">
<div class="fg"><label>Klantnummer</label><input type="text" name="remark" id="etR"></div>
<div class="fg"><label>Naam</label><input type="text" name="display_name" id="etD" required></div>
<div class="fg"><label>Host (IPv4)</label><input type="text" name="host" id="etH"></div>
<div class="fg"><label>Host IPv6</label><input type="text" name="host_ipv6" id="etH6" placeholder="bijv. 2606:4700::1111"></div>
</div>
<div class="fg"><label>🔔 Alert Configuratie</label><select name="alert" id="etAl"><option value="">Geen alert</option>
<?php foreach($alertList as $al):?><option value="<?=e($al['name'])?>" <?=((string)$al['name']===(string)getDefaultTargetAlertName($db))?'selected':''?>><?=e($al['display_name'])?></option><?php endforeach;?></select></div>
<div class="fg"><label>Sessieduur</label><select name="session_duration" id="etSD">
<option value="unlimited">Onbeperkt</option>
<option value="1m">1 min</option>
<option value="1h">1 uur</option>
<option value="6h">6 uur</option>
<option value="12h">12 uur</option>
<option value="24h">24 uur</option>
<option value="7d">7 dagen</option>
<option value="30d">30 dagen</option>
</select></div>
<div class="fr"><div class="fg ck"><input type="checkbox" name="session_notify_enabled" id="etSNE" checked><label for="etSNE">Mail bij sessie start/einde</label></div>
<div class="fg" style="flex:1"><label>Notificatie e-mailadres(sen)</label><input type="text" name="session_notify_email" id="etSNEml" value="<?=e($_formDefaultEmail)?>" placeholder="bijv. admin@example.com, monitor@example.com"></div></div>
<div class="fg"><label>Uitval mail interval</label><select name="outage_mail_interval" id="etOI"><option value="">Globaal (<?=e($targetsOutageIntervalLabel)?>)</option><?php foreach([5=>'5 min',10=>'10 min',15=>'15 min',30=>'30 min',240=>'4 uur',480=>'8 uur',1440=>'1 dag',2880=>'2 dagen',10080=>'7 dagen'] as $v=>$l):?><option value="<?=$v?>"><?=e($l)?></option><?php endforeach;?></select></div>
<div class="fg ck" id="etER" style="display:none"><input type="checkbox" name="enabled" id="etEn" checked><label for="etEn">Actief</label></div>
<div class="target-form-actions">
<button type="button" class="bt bg" onclick="closeM('tgtM')">Annuleren</button>
<button type="submit" class="bt bg" id="etBtnNext" onclick="setTargetDraftSubmitMode('stay')">Toevoegen en volgende</button>
<button type="submit" class="bt bp" id="etBtn" onclick="setTargetDraftSubmitMode('close')">Target toevoegen</button></div></form></div></div>
<?php endif; ?>

<?php if($uiCanRrdManage): ?>
<div class="mo" id="clearRrdM" onclick="if(event.target===this)closeM('clearRrdM')"><div class="md">
<h3>🗑 Grafiekdata Wissen</h3>
<p style="color:var(--txd);margin-bottom:16px;font-size:13px">Kies wat je wilt wissen:</p>
<div style="display:flex;flex-direction:column;gap:10px">
<form method="POST"><input type="hidden" name="action" value="clear_rrd_web"><input type="hidden" name="scope" value="all"><?=csrfField()?>
<button type="submit" class="bt bd" style="width:100%;justify-content:center;text-align:center" onclick="return confirm('Alle RRD bestanden en grafiekhistorie wissen?')">🗑 Alles wissen</button></form>
<div style="text-align:center;color:var(--txd);font-size:12px">of</div>
<div>
<label style="color:var(--txd);font-size:13px;margin-bottom:8px;display:block">Wis een categorie:</label>
<form method="POST" style="display:flex;gap:4px"><input type="hidden" name="action" value="clear_rrd_web"><input type="hidden" name="scope" value="category"><?=csrfField()?>
<select name="category_id" style="flex:1;padding:10px;min-height:44px;background:var(--bg);border:1px solid var(--brd);border-radius:var(--r);color:var(--tx);font-size:14px" required>
<option value="">-- Selecteer categorie --</option>
<?php foreach($allCats as $c):?><option value="<?=(int)$c['id']?>"><?=e($c['display_name'])?></option><?php endforeach;?>
</select>
<button type="submit" class="bt bw bsm" onclick="return confirm('Grafiekdata van deze categorie wissen?')">Wissen</button></form>
</div>
</div>
</div></div>
<?php endif; ?>

<?php
// ========== INSTELLINGEN ==========
elseif($page==='settings'):
    $stab=$_GET['stab']??'instellingen';
    $isAdminUi = isAdmin($db);
    $canManageUi = canManage($db);
    $uiCanConfigManage = hasActionPermission($db, 'act_config_manage');
    $uiCanBackupsManage = hasActionPermission($db, 'act_backups_manage');
    $uiCanMailUse = hasActionPermission($db, 'act_mail_use');
    $uiCanMailSettings = hasActionPermission($db, 'act_mail_settings');
    $uiCanAlertsManage = hasActionPermission($db, 'act_alerts_manage');
    $canOpenConfigUi = $isAdminUi || $uiCanConfigManage || $canManageUi;
    $canOpenBackupsUi = $isAdminUi || $uiCanBackupsManage;
    $canOpenBeheerUi = $isAdminUi || $uiCanMailUse || $uiCanMailSettings || $uiCanAlertsManage;
    $legacyMap=[
        'theme'=>'instellingen','fontsize'=>'instellingen','account'=>'instellingen','setup'=>'instellingen',
        'users'=>'beheer','alerts'=>'beheer','rrdlogs'=>'beheer',
        'system'=>'configuratie','config'=>'configuratie',
        'backup'=>'backups','email'=>'beheer','log'=>'logging'
    ];
    if(isset($legacyMap[$stab])) $stab=$legacyMap[$stab];
    $allowedStabs = ['instellingen'];
    if ($canOpenConfigUi) $allowedStabs[] = 'configuratie';
    if ($canOpenBackupsUi) $allowedStabs[] = 'backups';
    if ($canOpenBeheerUi) $allowedStabs[] = 'beheer';
    if ($isAdminUi) {
        $allowedStabs[] = 'logging';
        $allowedStabs[] = 'performance';
    }
    if(!in_array($stab,$allowedStabs,true)) $stab='instellingen';
    smPerfStart('settings_prep_ms');
    $files = [];
    $selFile = '';
    $content = '';
    $targetsBackups = [];
    $configBackups = [];
    $fullBackups = [];
    $autoBackupCfg = ['enabled'=>false,'frequency'=>'daily','keep_latest'=>10,'retain_daily'=>14,'retain_weekly'=>8,'retain_monthly'=>6,'last_period_key'=>'','last_run_at'=>'','last_result'=>''];
    $autoBackupDirs = [];
    $emailSettings = null;
    $allAlerts = [];
    $defaultTestEmail = '';
    $pendingApprovalCount = 0;
    $currentRoleForUi = getUserRole($db);
    if ($stab === 'configuratie') {
        $cacheVal = null;
        if (smCacheGet('settings:editable_files', 60, $cacheVal) && is_array($cacheVal)) {
            $files = $cacheVal;
        } else {
            smCacheMiss();
            $files = listEditableConfigFiles();
            smCacheSet('settings:editable_files', $files, 60);
        }
        $selFile = $_GET['file'] ?? ($files[0] ?? '');
        if ($stab === 'configuratie' && $selFile && in_array($selFile, $files, true)) {
            $content = @file_get_contents(SMOKEPING_CONF_DIR.'/'.$selFile);
        }
    }
    if ($stab === 'backups') {
        $cacheVal = null;
        if (smCacheGet('settings:targets_backups', 45, $cacheVal) && is_array($cacheVal)) {
            $targetsBackups = $cacheVal;
        } else {
            smCacheMiss();
            $targetsBackups = listTargetsFileBackups();
            smCacheSet('settings:targets_backups', $targetsBackups, 45);
        }
        $cacheVal = null;
        if (smCacheGet('settings:full_backups', 45, $cacheVal) && is_array($cacheVal)) {
            $fullBackups = $cacheVal;
        } else {
            smCacheMiss();
            foreach (glob(BACKUP_DIR.'/backup_*') ?: [] as $d) {
                if (is_dir($d)) $fullBackups[] = basename($d);
            }
            rsort($fullBackups);
            smCacheSet('settings:full_backups', $fullBackups, 45);
        }
        $autoBackupCfg = getAutoBackupSettings($db);
        $cacheVal = null;
        if (smCacheGet('settings:auto_backup_dirs', 45, $cacheVal) && is_array($cacheVal)) {
            $autoBackupDirs = $cacheVal;
        } else {
            smCacheMiss();
            $autoBackupDirs = listAutoFullBackupDirs();
            smCacheSet('settings:auto_backup_dirs', $autoBackupDirs, 45);
        }
    }
    if($stab === 'beheer' && $canOpenBeheerUi){
        if ($uiCanMailUse || $uiCanMailSettings || $isAdminUi) {
            $emailSettings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
            if(!$emailSettings) {
                $db->exec('INSERT INTO email_settings (id, smtp_host, smtp_port, smtp_encryption, smtp_from_name) VALUES (1, "smtp.gmail.com", 587, "tls", "SmokePing Manager")');
                $emailSettings = $db->query('SELECT * FROM email_settings WHERE id=1')->fetchArray(SQLITE3_ASSOC);
            }
            $defaultTestEmail = getDefaultTestEmail($db);
        }
        if ($uiCanAlertsManage || $isAdminUi) {
            $allAlerts = getAllAlerts($db);
        }
    }
    if (isAdmin($db)) {
        $pendingApprovalCount = (int)$db->querySingle('SELECT COUNT(*) FROM users WHERE approval_status="pending"');
    }
    $perfStats = ($stab === 'performance') ? summarizePerformanceMetrics(86400) : ['total'=>0,'avg_ms'=>0.0,'p95_ms'=>0.0,'p99_ms'=>0.0,'by_page'=>[],'top_slowest'=>[],'cache'=>['hits'=>0,'misses'=>0],'sql'=>['count'=>0,'ms'=>0.0],'server'=>['max_load1'=>0.0,'max_mem_mb'=>0.0],'blocks'=>[]];
    smPerfStop('settings_prep_ms');
?><h2 style="font-size:16px;margin-bottom:14px">Instellingen</h2>
<style>
.subtabs{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:10px}
.subtab{display:flex;flex-direction:column;align-items:flex-start;justify-content:center;gap:0px;padding:7px 10px;background:var(--s1);border:1px solid var(--brd);border-radius:10px;color:var(--txd);font-size:13px;cursor:pointer;transition:.16s}
.subtab:hover{color:var(--tx);border-color:color-mix(in srgb,var(--ac) 35%,var(--brd));background:var(--s2)}
.subtab.active{color:var(--tx);border-color:var(--ac);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--ac) 40%,transparent);background:linear-gradient(165deg,color-mix(in srgb,var(--ac) 12%,var(--s1)),var(--s1))}
.subtab .subtab-title{font-weight:700;font-size:calc(14px + var(--font-adjust));line-height:1.2}
.subtab .subtab-hint{font-size:calc(12px + var(--font-adjust));opacity:.8;line-height:1.2}
.subtab-badge{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 6px;border-radius:999px;margin-left:6px;background:var(--warnbg);color:var(--warnfg);border:1px solid color-mix(in srgb,var(--warn) 55%,var(--brd));font-size:10px;font-weight:800;line-height:1}
.sg-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px}
.settings-pref-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-bottom:12px}
.settings-pref-card{display:flex;flex-direction:column}
.settings-pref-card form{display:flex;flex-direction:column;gap:10px;flex:1}
.settings-pref-card .bt{margin-top:auto;align-self:flex-start}
.settings-inline-stack{display:flex;flex-direction:column;gap:10px}
.backup-overview{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}
.backup-kpi{background:linear-gradient(165deg,var(--s1),var(--s2));border:1px solid var(--brd);border-radius:10px;padding:10px 12px}
.backup-kpi strong{display:block;font-size:19px;color:var(--ac);line-height:1.05}
.backup-kpi span{font-size:11px;color:var(--txd)}
.backup-grid{display:grid;grid-template-columns:1fr;gap:14px}
.backup-panel{background:var(--s1);border:1px solid var(--brd);border-radius:10px;padding:10px}
.backup-panel .cd-t{margin-bottom:8px;padding-bottom:7px}
.backup-hint{font-size:11px;color:var(--txd);margin-bottom:8px;line-height:1.45}
.backup-action-row{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;margin-bottom:8px}
.backup-action-row form{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end}
.backup-action-row .fg{margin-bottom:0;min-width:190px;flex:1 1 220px}
.backup-scroll{max-height:440px;overflow:auto;border:1px solid var(--brd);border-radius:8px;background:var(--bg)}
.backup-table{width:100%;border-collapse:collapse}
.backup-table th,.backup-table td{padding:3px 6px;border-bottom:1px solid var(--brd);font-size:11px;vertical-align:middle}
.backup-table th{position:sticky;top:0;background:var(--s1);text-align:left;color:var(--txd);text-transform:uppercase;letter-spacing:.25px;z-index:1}
.backup-table tbody tr:nth-child(even){background:color-mix(in srgb, var(--s1) 55%, transparent)}
.backup-badge{display:inline-flex;align-items:center;padding:3px 7px;border:1px solid var(--brd);border-radius:999px;background:var(--s1);font-size:10px;font-weight:600}
.btype-auto{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:600;background:color-mix(in srgb,var(--ac) 18%,transparent);color:var(--ac);border:1px solid color-mix(in srgb,var(--ac) 35%,transparent)}
.btype-manual{display:inline-block;padding:2px 7px;border-radius:5px;font-size:10px;font-weight:600;background:color-mix(in srgb,var(--txd) 15%,transparent);color:var(--txd);border:1px solid color-mix(in srgb,var(--txd) 30%,transparent)}
.backup-filecell{min-width:140px;max-width:220px;word-break:break-word}
.backup-actions{display:flex;justify-content:flex-end;align-items:center}
.backup-menu{position:relative}
.backup-menu summary{list-style:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:82px;min-height:28px;padding:6px 9px;border:1px solid var(--brd);border-radius:7px;background:var(--s1);color:var(--tx);font-size:11px;font-weight:600;cursor:pointer}
.backup-menu summary::-webkit-details-marker{display:none}
.backup-menu[open] summary{background:var(--s2);border-color:var(--ac)}
.backup-menu:not([open]) .backup-menu-panel{display:none}
.backup-menu-panel{position:absolute;right:0;top:calc(100% + 6px);min-width:150px;padding:6px;background:var(--s1);border:1px solid var(--brd);border-radius:8px;box-shadow:0 10px 24px rgba(0,0,0,.12);z-index:4;display:flex;flex-direction:column;gap:5px}
.backup-menu-panel form{display:flex}
.backup-menu-panel .bt{width:100%;min-width:0;min-height:28px;padding:6px 9px;font-size:11px;justify-content:flex-start}
.backup-primary-form{display:grid;grid-template-columns:minmax(180px,220px) minmax(220px,1fr) auto;gap:8px;align-items:end}
.backup-primary-form.compact-four{grid-template-columns:minmax(180px,220px) minmax(220px,1fr) minmax(150px,180px) auto}
.backup-primary-form .fg{min-width:0}
.backup-empty{font-size:12px;color:var(--txd);padding:10px;border:1px dashed var(--brd);border-radius:8px;background:var(--bg)}
.backup-diagnostics{margin-top:10px}
.auto-backup-panel{margin-top:10px}
.auto-backup-status{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:10px}
.auto-backup-card{border:1px solid var(--brd);border-radius:8px;background:var(--bg);padding:10px}
.auto-backup-card strong{display:block;font-size:17px;color:var(--tx);margin-bottom:4px}
.auto-backup-card span{font-size:11px;color:var(--txd)}
.auto-backup-meta{font-size:11px;color:var(--txd);line-height:1.55;margin-top:8px}
.config-backup-layout{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(300px,.9fr);gap:10px}
.config-backup-side{display:flex;flex-direction:column;gap:10px}
.config-backup-card{border:1px solid var(--brd);border-radius:8px;background:var(--bg);padding:10px}
.config-backup-card h4{font-size:12px;margin-bottom:6px;color:var(--tx)}
.config-backup-card p{font-size:11px;color:var(--txd);margin-bottom:8px;line-height:1.45}
.beheer-users-head{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.beheer-users-wrap,.beheer-rrd-wrap{width:100%;max-width:100%;min-width:0;overflow:auto;border:1px solid var(--brd);border-radius:8px;background:var(--bg)}
.beheer-users-table,.beheer-rrd-table{width:100%;border-collapse:collapse}
@media(max-width:1220px){.backup-grid{grid-template-columns:1fr}.backup-overview{grid-template-columns:repeat(2,minmax(0,1fr))}.auto-backup-status{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:980px){.backup-primary-form,.backup-primary-form.compact-four{grid-template-columns:1fr}}
@media(max-width:900px){.config-backup-layout{grid-template-columns:1fr}.auto-backup-status{grid-template-columns:1fr}}
@media(max-width:800px){.backup-overview{grid-template-columns:1fr}.backup-table{font-size:10px}.backup-actions{justify-content:flex-start}.backup-menu-panel{right:auto;left:0}}
@media(max-width:1100px){.settings-pref-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:640px){
    .subtabs{grid-template-columns:1fr;gap:6px}
    .subtabs,.settings-pref-grid,.backup-grid,.backup-panel,.backup-scroll,.config-backup-layout,.config-backup-side,.config-backup-card,.auto-backup-status,.log-top-grid,.log-source-table-wrap,.log-full-wrap,.admin-scroll-pane{width:100%;max-width:100%;min-width:0}
    .settings-pref-grid,.backup-grid,.config-backup-layout,.auto-backup-status{grid-template-columns:1fr!important}
    .backup-overview{display:none}
    .backup-action-row,.backup-action-row form,.backup-primary-form,.backup-primary-form.compact-four{width:100%;max-width:100%;min-width:0;grid-template-columns:1fr!important}
    .backup-action-row .fg,.backup-primary-form .fg{min-width:0!important}
    .backup-scroll,.log-source-table-wrap,.log-full-wrap,.admin-scroll-pane{overflow:auto;overscroll-behavior-x:contain}
    .beheer-users-wrap,.beheer-rrd-wrap{overflow:auto;overscroll-behavior-x:contain}
    .beheer-users-head .bt{width:100%;justify-content:center}
    .cd>table{display:block;max-width:100%;overflow:auto;white-space:nowrap}
    .log-actions{width:100%}
    .subtab{display:block;padding:10px 10px;font-size:calc(12px + var(--font-adjust))}
    .subtab .subtab-title,.subtab .subtab-hint{display:inline;font-size:inherit;line-height:1.35}
    .subtab .subtab-hint::before{content:' - ';opacity:.72}
    .mobile-backup-accordion .cd-t{display:flex;align-items:center;justify-content:space-between;cursor:pointer;margin:0;padding:7px 10px;border-bottom:1px solid var(--brd)}
    .mobile-backup-accordion .cd-t::after{content:'▾';font-size:13px;color:var(--txd)}
    .mobile-backup-accordion.is-collapsed .cd-t::after{content:'▸'}
    .mobile-backup-accordion.is-collapsed>:not(.cd-t){display:none}
}
</style>
<div class="subtabs">
<a href="?p=settings&stab=instellingen" class="subtab <?=$stab==='instellingen'?'active':''?>"><span class="subtab-title">⚙️ Instellingen</span><span class="subtab-hint">Thema, sessie, voorkeuren</span></a>
<?php if($canOpenConfigUi): ?><a href="?p=settings&stab=configuratie" class="subtab <?=$stab==='configuratie'?'active':''?>"><span class="subtab-title">🧩 Configuratie</span><span class="subtab-hint">Service en configfiles</span></a>
<?php endif; ?><?php if($canOpenBackupsUi): ?><a href="?p=settings&stab=backups" class="subtab <?=$stab==='backups'?'active':''?>"><span class="subtab-title">💾 Backups</span><span class="subtab-hint">Herstel en retentie</span></a><?php endif; ?>
<?php if(isAdmin($db)): ?>
<a href="?p=settings&stab=logging" class="subtab <?=$stab==='logging'?'active':''?>"><span class="subtab-title">📋 Logging</span><span class="subtab-hint">Historie en onderhoud</span></a>
<a href="?p=settings&stab=performance" class="subtab <?=$stab==='performance'?'active':''?>"><span class="subtab-title">⚡ Performance</span><span class="subtab-hint">Snelheid en cache</span></a>
<?php endif; ?>
<?php if($canOpenBeheerUi): ?><a href="?p=settings&stab=beheer" class="subtab <?=$stab==='beheer'?'active':''?>"><span class="subtab-title">🛡️ Beheer<?php if($isAdminUi && $pendingApprovalCount>0): ?><span class="subtab-badge"><?=$pendingApprovalCount?></span><?php endif; ?></span><span class="subtab-hint">Gebruikers, goedkeuringen en alerts</span></a><?php endif; ?>
</div>

<?php if($stab==='instellingen'): ?>
<div class="settings-pref-grid">
<div class="cd settings-pref-card"><div class="cd-t">🎨 Thema, sessie & lettertype</div>
<form method="POST"><input type="hidden" name="action" value="set_theme"><?=csrfField()?>
<div class="settings-inline-stack">
<div class="fg"><label>Thema voorkeur</label><select name="theme"><option value="auto" <?=$theme==='auto'?'selected':''?>>Automatisch</option><option value="light" <?=$theme==='light'?'selected':''?>>Licht</option><option value="dark" <?=$theme==='dark'?'selected':''?>>Donker</option></select></div>
<div class="fg"><label>Sessieduur voorkeur</label><select name="ui_session_timeout_hours"><option value="24" <?=$uiSessionTimeoutHours==='24'?'selected':''?>>1 dag</option><option value="168" <?=$uiSessionTimeoutHours==='168'?'selected':''?>>1 week</option><option value="720" <?=$uiSessionTimeoutHours==='720'?'selected':''?>>1 maand</option></select></div>
<div class="fg"><label>Lettergrootte voorkeur</label><select name="fontsize"><option value="10" <?=$fontsize==='10'?'selected':''?>>10px</option><option value="12" <?=$fontsize==='12'?'selected':''?>>12px</option><option value="14" <?=$fontsize==='14'?'selected':''?>>14px (Standaard)</option><option value="16" <?=$fontsize==='16'?'selected':''?>>16px</option><option value="18" <?=$fontsize==='18'?'selected':''?>>18px</option><option value="20" <?=$fontsize==='20'?'selected':''?>>20px</option><option value="22" <?=$fontsize==='22'?'selected':''?>>22px</option><option value="24" <?=$fontsize==='24'?'selected':''?>>24px</option></select></div>
</div>
<button type="submit" class="bt bp">Opslaan</button></form></div>

<div class="cd settings-pref-card"><div class="cd-t">👤 Profielbeheer</div>
<form method="POST"><input type="hidden" name="action" value="chpw"><?=csrfField()?>
<div class="fg"><label>Nieuwe gebruikersnaam (leeg = behouden)</label><input type="text" name="newuser" value="<?=e($_SESSION['uname']??'')?>"></div>
<div class="fg"><label>Huidig wachtwoord</label><input type="password" name="cur" required></div>
<div class="fg"><label>Nieuw wachtwoord (leeg = behouden)</label><input type="password" name="new" minlength="6"></div>
<div class="fg"><label>Bevestig nieuw wachtwoord</label><input type="password" name="con" minlength="6"></div>
<button type="submit" class="bt bp">Opslaan</button></form></div>

<?php if(isAdmin($db)): ?>
<div class="cd settings-pref-card"><div class="cd-t">🔐 Google Auth</div>
<form method="POST"><input type="hidden" name="action" value="save_google_auth_settings"><?=csrfField()?>
<div class="fg"><label><input type="checkbox" name="google_auth_enabled" value="1" <?=getSetting($db, 'google_auth_enabled', '0') === '1' ? 'checked' : ''?>> Google aanmelding inschakelen</label></div>
<div class="fg"><label>Google Client ID</label><input type="text" name="google_client_id" value="<?=e((string)getSetting($db, 'google_client_id', ''))?>" placeholder="xxxxx.apps.googleusercontent.com"></div>
<div class="fg"><label>Google Client Secret</label><input type="password" name="google_client_secret" placeholder="Laat leeg om bestaand geheim te behouden"></div>
<div class="fg"><label>Redirect URI</label><input type="text" name="google_redirect_uri" value="<?=e((string)getSetting($db, 'google_redirect_uri', buildGoogleRedirectUri($db)))?>" placeholder="<?=e(buildGoogleRedirectUri($db))?>"></div>
<p style="font-size:12px;color:var(--txd);margin:8px 0 0">Nieuwe Google registraties komen eerst in de goedkeuringswachtrij. De notificatie gaat naar de standaard e-mailontvangers.</p>
<button type="submit" class="bt bp">Google Instellingen Opslaan</button></form></div>

<div class="cd settings-pref-card"><div class="cd-t">🚀 Stappenplan</div>
<p style="font-size:12px;color:var(--txd);margin-bottom:12px">Reset alle categorieën en targets, en start het stappenplan opnieuw.</p>
<?php if($uiCanConfigManage): ?><form method="POST" onsubmit="return confirm('WAARSCHUWING: Dit verwijdert alle categorieën en targets! Weet je zeker dat je het stappenplan wilt resetten?')"><input type="hidden" name="action" value="reset_setup"><?=csrfField()?><button type="submit" class="bt bd">Stappenplan Resetten</button></form><?php else: ?><p style="color:var(--txd);font-size:13px">Je hebt geen rechten om het stappenplan te resetten.</p><?php endif; ?>
</div>
</div>
<?php endif; ?>

<?php elseif($stab==='configuratie'): ?>
<div class="cd"><div class="cd-t">🔄 Configuratie & Service</div>
<?php if($uiCanConfigManage): ?><div style="display:flex;gap:8px;margin-bottom:16px"><form method="POST"><input type="hidden" name="action" value="reload"><?=csrfField()?><button class="bt bo" style="flex:1;justify-content:center">Rebuild & Restart SmokePing</button></form><form method="POST"><input type="hidden" name="action" value="restart"><?=csrfField()?><button class="bt bo" style="flex:1;justify-content:center">Alleen Restart</button></form></div><?php endif; ?>
<table style="width:100%;font-size:13px;line-height:1.8"><tr><td style="color:var(--txd);padding:5px 0;width:200px">Targets Config</td><td><code style="font-size:11px"><?=SMOKEPING_TARGETS_FILE?></code><?php if(file_exists(SMOKEPING_TARGETS_FILE)) echo ' ✅'; ?></td></tr><tr><td style="color:var(--txd);padding:5px 0">Probes Config</td><td><code style="font-size:11px"><?=SMOKEPING_PROBES_FILE?></code><?php if(file_exists(SMOKEPING_PROBES_FILE)) echo ' ✅'; ?></td></tr><tr><td style="color:var(--txd);padding:5px 0">Database</td><td><code style="font-size:11px"><?=DB_PATH?></code><?php if(file_exists(DB_PATH)) echo ' ✅'; ?></td></tr><tr><td style="color:var(--txd);padding:5px 0">RRD Data Dir</td><td><code style="font-size:11px"><?=SMOKEPING_DATA_DIR?></code><?php if(is_dir(SMOKEPING_DATA_DIR)) echo ' ✅'; ?></td></tr><tr><td style="color:var(--txd);padding:5px 0">PHP Versie</td><td><?=phpversion()?></td></tr><tr><td style="color:var(--txd);padding:5px 0">SmokePing CGI</td><td><code style="font-size:11px"><?=SMOKEPING_CGI_URL?></code></td></tr></table>
</div>

<div class="cd"><div class="cd-t">🧾 Configuratiebestanden</div><div class="fr"><div class="fg"><label>Bestand</label><select onchange="location='?p=settings&stab=configuratie&file='+this.value"><?php foreach($files as $f):?><option value="<?=e($f)?>" <?=$f===$selFile?'selected':''?>><?=e($f)?></option><?php endforeach;?></select></div></div>
<?php if($selFile):?>
<?php if($uiCanConfigManage): ?>
<form method="POST">
<input type="hidden" name="action" value="save_config_file"><?=csrfField()?>
<input type="hidden" name="config_file" value="<?=e($selFile)?>">
<textarea name="content" rows="20" style="width:100%;min-height:300px"><?=e($content)?></textarea>
<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap">
<button type="submit" class="bt bp">Opslaan & Restart</button>
</div>
</form>

<?php else: ?>
<div class="pre" style="min-height:300px"><?=e($content)?></div>
<?php endif; ?>
<?php endif;?>
</div>

<?php elseif($stab==='backups'): ?>
<div class="backup-overview">
    <div class="backup-kpi"><strong><?=count($fullBackups)?></strong><span>Volledige backups</span></div>
    <div class="backup-kpi"><strong><?=count($targetsBackups)?></strong><span>Targets backups</span></div>
    <div class="backup-kpi"><strong><?=$autoBackupCfg['enabled'] ? '<span style="color:var(--ok)">Actief</span>' : 'Uit'?></strong><span>Auto backup</span></div>
    <div class="backup-kpi"><strong><?=e($autoBackupCfg['frequency'])?></strong><span>Frequentie</span></div>
</div>

<div class="backup-grid">

<section class="backup-panel" style="grid-column:1/-1">
<div class="cd-t">📦 Volledige Backups</div>
<div class="backup-hint">Volledige backups bevatten alle config bestanden, database en RRD-data. Handmatige en automatische backups staan samen in één overzicht.</div>
<?php if($uiCanBackupsManage): ?>
<div class="backup-action-row">
    <form method="POST" style="margin:0"><input type="hidden" name="action" value="backup"><?=csrfField()?><button type="submit" class="bt bp">📦 Nieuwe Backup Maken</button></form>
    <form method="POST" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:center;margin:0;flex-wrap:wrap">
        <input type="hidden" name="action" value="upload_backup"><?=csrfField()?>
        <input type="file" class="file-input" name="backup_tar" accept=".tar.gz,.tgz" required style="font-size:12px;min-width:0;flex:1 1 200px">
        <button type="submit" class="bt bg" style="white-space:nowrap">⬆ Upload Backup</button>
    </form>
</div>
<?php endif; ?>

<?php if(empty($fullBackups)): ?>
<div class="backup-empty">Nog geen volledige backups beschikbaar.</div>
<?php else: ?>
<div class="backup-scroll">
<table class="backup-table">
<thead><tr><th>Naam</th><th>Type</th><th>Datum</th><th>Grootte</th><th style="text-align:right">Acties</th></tr></thead>
<tbody>
<?php foreach($fullBackups as $b):
    $bDir = BACKUP_DIR.'/'.$b;
    $isAuto = strpos($b, '_auto_') !== false;
    $approxSize = 0;
    foreach (glob($bDir.'/*') ?: [] as $bf) { if (is_file($bf)) $approxSize += (int)@filesize($bf); }
?>
<tr>
<td class="backup-filecell"><code><?=e($b)?></code></td>
<td><?=$isAuto ? '<span class="btype-auto">Auto</span>' : '<span class="btype-manual">Handmatig</span>'?></td>
<td><?=is_dir($bDir) ? date('d-m-Y H:i', (int)@filemtime($bDir)) : '-'?></td>
<td><?=$approxSize > 0 ? number_format($approxSize/1024/1024, 2, ',', '.') . ' MB' : '-'?></td>
<td><div class="backup-actions">
<?php if($uiCanBackupsManage): ?>
<details class="backup-menu"><summary>Acties ▾</summary><div class="backup-menu-panel">
<form method="POST" onsubmit="return confirm('Backup terugzetten? Dit overschrijft huidige config!')"><input type="hidden" name="action" value="restore"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button class="bt bo bsm">Terugzetten</button></form>
<form method="POST"><input type="hidden" name="action" value="download_backup"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button type="submit" class="bt bg bsm">⬇ Download</button></form>
<form method="POST" onsubmit="return confirm('Backup verwijderen?')"><input type="hidden" name="action" value="del_backup"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button class="bt bd bsm">Wissen</button></form>
</div></details>
<?php else: ?>
<form method="POST"><input type="hidden" name="action" value="download_backup"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button type="submit" class="bt bg bsm">⬇ Download</button></form>
<?php endif; ?>
</div></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
<?php endif; ?>

<div class="cd-t" style="margin-top:18px">⏱ Automatische Backups</div>
<div class="auto-backup-status">
    <div class="auto-backup-card"><strong><?=$autoBackupCfg['enabled'] ? '<span style="color:var(--ok)">Actief</span>' : 'Uit'?></strong><span>Status</span></div>
    <div class="auto-backup-card"><strong><?=e($autoBackupCfg['frequency'])?></strong><span>Nieuw backupmoment</span></div>
    <div class="auto-backup-card"><strong><?=count($autoBackupDirs)?></strong><span>Auto backups aanwezig</span></div>
    <div class="auto-backup-card"><strong><?=e((string)$autoBackupCfg['keep_latest'])?></strong><span>Altijd bewaren</span></div>
</div>
<div class="auto-backup-meta">
Laatste run: <?=!empty($autoBackupCfg['last_run_at']) ? e(formatDbDateLocal($autoBackupCfg['last_run_at'])) : 'Nog niet uitgevoerd'?><br>
Laatste resultaat: <?=!empty($autoBackupCfg['last_result']) ? e($autoBackupCfg['last_result']) : 'Nog geen automatische backup uitgevoerd.'?>
</div>
<?php if($uiCanBackupsManage): ?>
<div class="config-backup-card" style="margin-top:10px">
<form method="POST" class="backup-primary-form compact-four" style="grid-template-columns:repeat(3,minmax(0,1fr)) repeat(3,minmax(110px,150px)) auto;margin:0">
    <input type="hidden" name="action" value="save_auto_backup_settings"><?=csrfField()?>
    <div class="fg" style="min-width:0"><label><input type="checkbox" name="auto_backup_enabled" value="1" <?=$autoBackupCfg['enabled']?'checked':''?>> Automatische backups inschakelen</label></div>
    <div class="fg"><label>Frequentie</label><select name="auto_backup_frequency"><option value="daily" <?=$autoBackupCfg['frequency']==='daily'?'selected':''?>>Elke dag</option><option value="weekly" <?=$autoBackupCfg['frequency']==='weekly'?'selected':''?>>Elke week</option><option value="monthly" <?=$autoBackupCfg['frequency']==='monthly'?'selected':''?>>Elke maand</option></select></div>
    <div class="fg"><label>Behoud laatste x</label><input type="number" name="auto_backup_keep_latest" value="<?=e((string)$autoBackupCfg['keep_latest'])?>" min="1" max="100"></div>
    <div class="fg"><label>Dagelijks bewaren</label><input type="number" name="auto_backup_retain_daily" value="<?=e((string)$autoBackupCfg['retain_daily'])?>" min="0" max="365"></div>
    <div class="fg"><label>Wekelijks bewaren</label><input type="number" name="auto_backup_retain_weekly" value="<?=e((string)$autoBackupCfg['retain_weekly'])?>" min="0" max="104"></div>
    <div class="fg"><label>Maandelijks bewaren</label><input type="number" name="auto_backup_retain_monthly" value="<?=e((string)$autoBackupCfg['retain_monthly'])?>" min="0" max="36"></div>
    <button type="submit" class="bt bp">Opslaan</button>
</form>
<form method="POST" style="margin-top:8px;display:flex;justify-content:flex-end">
    <input type="hidden" name="action" value="run_auto_backup_now"><?=csrfField()?>
    <button type="submit" class="bt bg">Nu uitvoeren</button>
</form>
</div>
<?php endif; ?>
</section>

<section class="backup-panel" style="grid-column:1/-1">
<div class="cd-t">🎯 Targets Backup</div>
<div class="backup-hint">Backup van het Targets configuratiebestand. Handig om alleen targets-wijzigingen veilig te stellen of terug te zetten zonder de rest van de configuratie te raken.</div>
<?php if($uiCanBackupsManage): ?>
<div class="backup-action-row">
    <form method="POST" style="margin:0"><input type="hidden" name="action" value="backup_targets_file"><?=csrfField()?><button type="submit" class="bt bp">📦 Backup Targets</button></form>
    <form method="POST" enctype="multipart/form-data" style="display:flex;gap:8px;align-items:center;margin:0;flex-wrap:wrap">
        <input type="hidden" name="action" value="upload_targets_file_backup"><?=csrfField()?>
        <input type="file" class="file-input" name="targets_backup_upload" accept=".conf,.txt,.backup,.cfg" required style="font-size:12px;min-width:0;flex:1 1 200px">
        <label style="font-size:12px;display:flex;align-items:center;gap:5px;white-space:nowrap"><input type="checkbox" name="restore_after_upload" value="1"> Direct herstellen</label>
        <button type="submit" class="bt bg" style="white-space:nowrap">⬆ Upload Targets</button>
    </form>
</div>
<?php endif; ?>

<?php if(empty($targetsBackups)): ?>
<div class="backup-empty">Nog geen Targets backups beschikbaar.</div>
<?php else: ?>
<div class="backup-scroll">
<table class="backup-table">
<thead><tr><th>Bestand</th><th>Datum</th><th>Grootte</th><th style="text-align:right">Acties</th></tr></thead>
<tbody>
<?php foreach($targetsBackups as $tb): $tbPath = targetsBackupDir().'/'.$tb; ?>
<tr>
<td class="backup-filecell"><code><?=e($tb)?></code></td>
<td><?=is_file($tbPath) ? date('d-m-Y H:i', (int)@filemtime($tbPath)) : '-'?></td>
<td><?=is_file($tbPath) ? number_format(((int)@filesize($tbPath))/1024, 1, ',', '.') . ' KB' : '-'?></td>
<td><div class="backup-actions">
<details class="backup-menu"><summary>Acties ▾</summary><div class="backup-menu-panel">
<?php if($uiCanBackupsManage): ?>
<form method="POST" onsubmit="return confirm('Targets backup terugzetten en alles opnieuw inladen?')"><input type="hidden" name="action" value="restore_targets_file"><?=csrfField()?><input type="hidden" name="backup_file" value="<?=e($tb)?>"><button type="submit" class="bt bo bsm">Terugzetten</button></form>
<?php endif; ?>
<form method="POST"><input type="hidden" name="action" value="download_targets_file_backup"><?=csrfField()?><input type="hidden" name="backup_file" value="<?=e($tb)?>"><button type="submit" class="bt bg bsm">⬇ Download</button></form>
<?php if($uiCanBackupsManage): ?>
<form method="POST" onsubmit="return confirm('Targets backup verwijderen?')"><input type="hidden" name="action" value="delete_targets_file_backup"><?=csrfField()?><input type="hidden" name="backup_file" value="<?=e($tb)?>"><button type="submit" class="bt bd bsm">Wissen</button></form>
<?php endif; ?>
</div></details>
</div></td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
<?php endif; ?>
</section>

</div>

<?php elseif($stab==='logging'): ?>
<?php if(isAdmin($db)): ?>
<?php
$logRetentionDays = (int)getSetting($db, 'log_retention_days', '90');
if ($logRetentionDays < 1) $logRetentionDays = 90;
if ($logRetentionDays > 3650) $logRetentionDays = 3650;

$logDefs = [
    'activity_log' => ['label' => 'Activity log', 'dateExpr' => 'created_at', 'description' => 'Gebruikersacties en systeemacties'],
    'mail_log' => ['label' => 'Mail log', 'dateExpr' => 'created_at', 'description' => 'SMTP verzendpogingen en debug-resultaten'],
    'target_outages' => ['label' => 'Outage events', 'dateExpr' => 'COALESCE(updated_at, ended_at, started_at)', 'description' => 'Uitval/herstel historie per target'],
    'target_ping_loss_events' => ['label' => 'Ping loss events', 'dateExpr' => 'created_at', 'description' => 'Packet-loss events per target'],
    'rrd_reset_logs' => ['label' => 'RRD reset logs', 'dateExpr' => 'created_at', 'description' => 'Historie van RRD reset acties'],
];

$logStats = [];
foreach ($logDefs as $key => $def) {
    $q = $db->query('SELECT COUNT(*) AS cnt, MIN('.$def['dateExpr'].') AS oldest, MAX('.$def['dateExpr'].') AS newest FROM '.$key);
    $row = $q ? $q->fetchArray(SQLITE3_ASSOC) : null;
    $logStats[$key] = [
        'count' => (int)($row['cnt'] ?? 0),
        'oldest' => (string)($row['oldest'] ?? ''),
        'newest' => (string)($row['newest'] ?? ''),
    ];
}

$totalLogRows = 0;
foreach ($logStats as $st) $totalLogRows += (int)$st['count'];

$logViewKey = (string)($_GET['log_view'] ?? '');
if (!isset($logDefs[$logViewKey])) $logViewKey = '';
$logPerPage = 100;
$logPage = max(1, (int)($_GET['log_page'] ?? 1));
$logTotalRows = $logViewKey !== '' ? (int)($logStats[$logViewKey]['count'] ?? 0) : 0;
$logTotalPages = $logViewKey !== '' ? max(1, (int)ceil($logTotalRows / $logPerPage)) : 1;
if ($logPage > $logTotalPages) $logPage = $logTotalPages;
$logOffset = ($logPage - 1) * $logPerPage;
?>

<style>
.log-top-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:10px;align-items:stretch}
.log-top-grid > .cd{display:flex;flex-direction:column;height:100%}
.log-top-grid > .cd > form.log-form-grid{display:flex;flex-direction:column;flex:1}
.log-top-grid > .cd > form.log-form-grid .log-clean-actions{margin-top:auto}
.log-form-grid{display:grid;grid-template-columns:minmax(0,1fr);gap:8px}
.log-inline-field{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px;align-items:center}
.log-inline-field label{font-size:11px;color:var(--txd);font-weight:600;margin:0}
.log-inline-field input,.log-inline-field select{height:30px;padding:4px 8px;font-size:12px}
.log-check-row{display:flex;flex-wrap:wrap;gap:10px 14px;font-size:12px}
.log-check-row label{display:flex;align-items:center;gap:6px}
.log-source-table-wrap,.log-full-wrap{overflow:auto;border:1px solid var(--brd);border-radius:8px;background:var(--bg)}
.log-source-table,.log-full-table{width:100%;border-collapse:collapse;font-size:11px}
.log-source-table th,.log-source-table td,.log-full-table th,.log-full-table td{padding:7px 8px;border-bottom:1px solid var(--brd);text-align:left;vertical-align:top}
.log-source-table th,.log-full-table th{position:sticky;top:0;background:var(--s1);color:var(--txd);font-weight:600;z-index:1}
.log-source-table tbody tr:nth-child(even),.log-full-table tbody tr:nth-child(even){background:color-mix(in srgb, var(--s1) 55%, transparent)}
.log-source-table td:last-child,.log-full-table td:last-child{white-space:normal}
.log-actions{display:grid;grid-template-columns:repeat(3,minmax(78px,1fr));gap:6px;justify-content:end;min-width:0}
.log-actions form{margin:0!important;display:block!important}
.log-actions .bt{width:100%;justify-content:center;white-space:nowrap}
.log-actions-mobile{display:none;position:relative}
.log-actions-mobile summary{list-style:none;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:88px;min-height:32px;padding:6px 10px;border:1px solid var(--brd);border-radius:8px;background:var(--s1);color:var(--tx);font-size:11px;font-weight:700;cursor:pointer}
.log-actions-mobile summary::-webkit-details-marker{display:none}
.log-actions-mobile[open] summary{background:var(--s2);border-color:var(--ac)}
.log-actions-mobile-panel{position:absolute;right:0;top:calc(100% + 6px);min-width:150px;padding:6px;background:var(--s1);border:1px solid var(--brd);border-radius:8px;box-shadow:0 10px 24px rgba(0,0,0,.18);z-index:6;display:flex;flex-direction:column;gap:5px}
.log-actions-mobile.open-up .log-actions-mobile-panel{top:auto;bottom:calc(100% + 6px)}
.log-actions-mobile-panel form{display:flex;margin:0}
.log-actions-mobile-panel .bt{width:100%;min-height:30px;justify-content:flex-start}
.log-clean-actions{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-top:8px}
.log-clean-actions form{margin:0;display:block}
.log-clean-actions .bt{width:100%;justify-content:center}
.log-full{margin-top:10px}
.log-full .cd{padding:10px 12px}
.log-pager{display:flex;gap:6px;align-items:center;justify-content:flex-end;flex-wrap:wrap;margin-top:8px}
@media(max-width:1180px){.log-top-grid{grid-template-columns:1fr}.log-inline-field{grid-template-columns:130px minmax(0,1fr)}}
@media(max-width:760px){.log-inline-field{grid-template-columns:1fr}.log-actions{display:none}.log-actions-mobile{display:inline-block}.log-clean-actions{grid-template-columns:1fr 1fr}.log-source-table th:nth-child(4),.log-source-table th:nth-child(5),.log-source-table td:nth-child(4),.log-source-table td:nth-child(5){display:none}}
</style>

<div class="log-top-grid">
<div class="cd" style="padding:10px 12px">
<div class="cd-t" style="margin-bottom:8px">⚙️ Logging instellingen</div>
<form method="POST" class="log-form-grid">
<input type="hidden" name="action" value="save_log_settings"><?=csrfField()?>
<div class="log-inline-field"><label>Bewaartermijn</label><input type="number" name="log_retention_days" min="1" max="3650" value="<?=$logRetentionDays?>"></div>
<div class="log-inline-field"><label>Log e-mail</label><input type="text" name="log_email_address" value="<?=e(getSetting($db,'log_email_address',''))?>" placeholder="admin@example.com"></div>
<div class="log-check-row">
    <label><input type="checkbox" name="log_email_enabled" value="1" <?=getSetting($db,'log_email_enabled','0')==='1'?'checked':''?>>Logmail</label>
    <label><input type="checkbox" name="log_auto_100" value="1" <?=getSetting($db,'log_auto_100','0')==='1'?'checked':''?>>Auto mail @100</label>
    <label><input type="checkbox" name="log_auto_daily" value="1" <?=getSetting($db,'log_auto_daily','0')==='1'?'checked':''?>>Dagelijks mailen</label>
</div>
<div style="display:flex;justify-content:flex-end"><button type="submit" class="bt bp bsm">Opslaan</button></div>
</form>
</div>

<div class="cd" style="padding:10px 12px">
<div class="cd-t" style="margin-bottom:8px">🧹 Opschonen</div>
<form method="POST" class="log-form-grid">
<input type="hidden" name="action" value="cleanup_logs_by_days"><?=csrfField()?>
<input type="hidden" name="scope" value="all">
<div class="log-inline-field"><label>Verwijder ouder dan</label><input type="number" name="retention_days" min="1" max="3650" value="<?=$logRetentionDays?>"></div>
<div class="log-clean-actions">
    <button type="submit" class="bt bw bsm" onclick="return confirm('Alle logtabellen opschonen op basis van bewaartermijn?')">Alles opschonen</button>
</form>
<form method="POST" onsubmit="return confirm('Activiteitenlog nu per e-mail verzenden?')"><input type="hidden" name="action" value="send_log_email"><?=csrfField()?><button type="submit" class="bt bg bsm">Log mailen</button></form>
</div>
</div>

</div>

<div class="cd" style="padding:10px 12px">
<div class="cd-t" style="margin-bottom:8px">📋 Logbronnen</div>
<div class="log-source-table-wrap">
<table class="log-source-table">
<thead><tr><th>Logtype</th><th>Omschrijving</th><th>Aantal</th><th>Oudste</th><th>Nieuwste</th><th style="text-align:right">Acties</th></tr></thead>
<tbody>
<?php foreach($logDefs as $key => $def): $st = $logStats[$key]; ?>
<tr>
    <td><strong><?=e($def['label'])?></strong></td>
    <td><?=e($def['description'])?></td>
    <td><strong><?=$st['count']?></strong></td>
    <td><?=$st['oldest']!==''?e(formatDbDateLocal($st['oldest'], 'd-m-Y H:i')):'-'?></td>
    <td><?=$st['newest']!==''?e(formatDbDateLocal($st['newest'], 'd-m-Y H:i')):'-'?></td>
    <td>
        <div class="log-actions">
            <form method="GET" style="display:inline">
                <input type="hidden" name="p" value="settings">
                <input type="hidden" name="stab" value="logging">
                <input type="hidden" name="log_view" value="<?=e($key)?>">
                <input type="hidden" name="log_page" value="1">
                <button type="submit" class="bt bw bsm">Bekijken</button>
            </form>
            <form method="POST" style="display:inline" onsubmit="return confirm('Opschonen op bewaartermijn voor <?=e($def['label'])?>?')">
                <input type="hidden" name="action" value="cleanup_logs_by_days"><?=csrfField()?>
                <input type="hidden" name="scope" value="<?=e($key)?>">
                <input type="hidden" name="retention_days" value="<?=$logRetentionDays?>">
                <button type="submit" class="bt bg bsm">Opschonen</button>
            </form>
            <form method="POST" style="display:inline" onsubmit="return confirm('ALLES legen van <?=e($def['label'])?>? Dit kan niet ongedaan worden gemaakt.')">
                <input type="hidden" name="action" value="clear_log_scope"><?=csrfField()?>
                <input type="hidden" name="scope" value="<?=e($key)?>">
                <button type="submit" class="bt bd bsm">Legen</button>
            </form>
        </div>
        <details class="log-actions-mobile"><summary>Acties ▾</summary><div class="log-actions-mobile-panel">
            <form method="GET">
                <input type="hidden" name="p" value="settings">
                <input type="hidden" name="stab" value="logging">
                <input type="hidden" name="log_view" value="<?=e($key)?>">
                <input type="hidden" name="log_page" value="1">
                <button type="submit" class="bt bw bsm">Bekijken</button>
            </form>
            <form method="POST" onsubmit="return confirm('Opschonen op bewaartermijn voor <?=e($def['label'])?>?')">
                <input type="hidden" name="action" value="cleanup_logs_by_days"><?=csrfField()?>
                <input type="hidden" name="scope" value="<?=e($key)?>">
                <input type="hidden" name="retention_days" value="<?=$logRetentionDays?>">
                <button type="submit" class="bt bg bsm">Opschonen</button>
            </form>
            <form method="POST" onsubmit="return confirm('ALLES legen van <?=e($def['label'])?>? Dit kan niet ongedaan worden gemaakt.')">
                <input type="hidden" name="action" value="clear_log_scope"><?=csrfField()?>
                <input type="hidden" name="scope" value="<?=e($key)?>">
                <button type="submit" class="bt bd bsm">Legen</button>
            </form>
        </div></details>
    </td>
</tr>
<?php endforeach; ?>
</tbody>
</table>
</div>
</div>

<?php if($logViewKey !== ''): ?>
<div class="log-full">
<div class="cd">
<div class="cd-t">📄 <?=e($logDefs[$logViewKey]['label'])?> - alle regels</div>
<div style="font-size:12px;color:var(--txd);margin-bottom:8px">Pagina <?=$logPage?> van <?=$logTotalPages?> (<?=$logTotalRows?> totaal, <?=$logPerPage?> per pagina)</div>
<div class="log-full-wrap">
<?php if($logViewKey==='activity_log'): ?>
    <?php $rows=[]; $q=$db->query('SELECT created_at, username, action_type, description, ip_address FROM activity_log ORDER BY created_at DESC LIMIT '.$logPerPage.' OFFSET '.$logOffset); while($q && ($rw=$q->fetchArray(SQLITE3_ASSOC))) $rows[]=$rw; ?>
    <table class="log-full-table"><thead><tr><th>Tijd</th><th>Gebruiker</th><th>Actie</th><th>Omschrijving</th><th>IP</th></tr></thead><tbody>
    <?php foreach($rows as $rw): ?><tr><td><?=e(formatDbDateLocal($rw['created_at'] ?? ''))?></td><td><?=e($rw['username'])?></td><td><?=e($rw['action_type'])?></td><td><?=e($rw['description'])?></td><td><?=e($rw['ip_address'])?></td></tr><?php endforeach; ?>
    </tbody></table>
<?php elseif($logViewKey==='mail_log'): ?>
    <?php $rows=[]; $q=$db->query('SELECT created_at, type, target_name, email_to, status, message FROM mail_log ORDER BY created_at DESC LIMIT '.$logPerPage.' OFFSET '.$logOffset); while($q && ($rw=$q->fetchArray(SQLITE3_ASSOC))) $rows[]=$rw; ?>
    <table class="log-full-table"><thead><tr><th>Tijd</th><th>Type</th><th>Target</th><th>Ontvanger</th><th>Status</th><th>Bericht</th></tr></thead><tbody>
    <?php foreach($rows as $rw): ?><tr><td><?=e(formatDbDateLocal($rw['created_at'] ?? ''))?></td><td><?=e($rw['type'])?></td><td><?=e($rw['target_name'])?></td><td><?=e($rw['email_to'])?></td><td><?=e($rw['status'])?></td><td><?=e($rw['message'])?></td></tr><?php endforeach; ?>
    </tbody></table>
<?php elseif($logViewKey==='target_outages'): ?>
    <?php $rows=[]; $q=$db->query('SELECT o.started_at, o.ended_at, o.is_open, o.duration_seconds, t.display_name AS target_name FROM target_outages o LEFT JOIN targets t ON o.target_id=t.id ORDER BY COALESCE(o.updated_at, o.ended_at, o.started_at) DESC LIMIT '.$logPerPage.' OFFSET '.$logOffset); while($q && ($rw=$q->fetchArray(SQLITE3_ASSOC))) $rows[]=$rw; ?>
    <table class="log-full-table"><thead><tr><th>Start</th><th>Einde</th><th>Target</th><th>Status</th><th>Duur (s)</th></tr></thead><tbody>
    <?php foreach($rows as $rw): ?><tr><td><?=e(formatDbDateLocal($rw['started_at'] ?? ''))?></td><td><?=e(formatDbDateLocal($rw['ended_at'] ?? ''))?></td><td><?=e($rw['target_name'] ?? '')?></td><td><?=((int)($rw['is_open']??0)===1)?'open':'gesloten'?></td><td><?=(int)($rw['duration_seconds']??0)?></td></tr><?php endforeach; ?>
    </tbody></table>
<?php elseif($logViewKey==='target_ping_loss_events'): ?>
    <?php $rows=[]; $q=$db->query('SELECT e.created_at, t.display_name AS target_name, e.loss_fraction, e.is_full_loss, e.notified FROM target_ping_loss_events e LEFT JOIN targets t ON e.target_id=t.id ORDER BY e.created_at DESC LIMIT '.$logPerPage.' OFFSET '.$logOffset); while($q && ($rw=$q->fetchArray(SQLITE3_ASSOC))) $rows[]=$rw; ?>
    <table class="log-full-table"><thead><tr><th>Tijd</th><th>Target</th><th>Loss</th><th>Full loss</th><th>Notified</th></tr></thead><tbody>
    <?php foreach($rows as $rw): ?><tr><td><?=e(formatDbDateLocal($rw['created_at'] ?? ''))?></td><td><?=e($rw['target_name'] ?? '')?></td><td><?=round(((float)($rw['loss_fraction']??0))*100,1)?>%</td><td><?=((int)($rw['is_full_loss']??0)===1)?'ja':'nee'?></td><td><?=((int)($rw['notified']??0)===1)?'ja':'nee'?></td></tr><?php endforeach; ?>
    </tbody></table>
<?php else: ?>
    <?php $rows=[]; $q=$db->query('SELECT created_at, username, category_name, target_name, result, details FROM rrd_reset_logs ORDER BY created_at DESC LIMIT '.$logPerPage.' OFFSET '.$logOffset); while($q && ($rw=$q->fetchArray(SQLITE3_ASSOC))) $rows[]=$rw; ?>
    <table class="log-full-table"><thead><tr><th>Tijd</th><th>Gebruiker</th><th>Categorie</th><th>Target</th><th>Status</th><th>Details</th></tr></thead><tbody>
    <?php foreach($rows as $rw): ?><tr><td><?=e(formatDbDateLocal($rw['created_at'] ?? ''))?></td><td><?=e($rw['username'])?></td><td><?=e($rw['category_name'])?></td><td><?=e($rw['target_name'])?></td><td><?=e($rw['result'])?></td><td><?=e($rw['details'])?></td></tr><?php endforeach; ?>
    </tbody></table>
<?php endif; ?>
</div>

<div class="log-pager">
    <?php if($logPage > 1): ?><a class="bt bg bsm" href="?p=settings&amp;stab=logging&amp;log_view=<?=e($logViewKey)?>&amp;log_page=<?=($logPage-1)?>">Vorige</a><?php endif; ?>
    <span style="font-size:12px;color:var(--txd)">Pagina <?=$logPage?> / <?=$logTotalPages?></span>
    <?php if($logPage < $logTotalPages): ?><a class="bt bg bsm" href="?p=settings&amp;stab=logging&amp;log_view=<?=e($logViewKey)?>&amp;log_page=<?=($logPage+1)?>">Volgende</a><?php endif; ?>
    <a class="bt bw bsm" href="?p=settings&amp;stab=logging">Sluiten</a>
</div>
</div>
</div>
<?php endif; ?>
<?php else: ?>
<div class="cd"><div class="cd-t">Logging</div><p style="color:var(--txd)">Alleen admins hebben toegang tot loggingbeheer.</p></div>
<?php endif; ?>

<?php elseif($stab==='performance'): ?>
<?php if(isAdmin($db)): ?>
<?php
$cacheHits = (int)($perfStats['cache']['hits'] ?? 0);
$cacheMisses = (int)($perfStats['cache']['misses'] ?? 0);
$cacheTotal = max(1, $cacheHits + $cacheMisses);
$cacheHitRate = round(($cacheHits / $cacheTotal) * 100, 2);
?>
<style>
.perf-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin-bottom:12px}
.perf-kpi{border:1px solid var(--brd);border-radius:8px;background:var(--bg);padding:10px}
.perf-kpi strong{display:block;font-size:20px;color:var(--tx)}
.perf-kpi span{font-size:11px;color:var(--txd)}
.perf-table-wrap{overflow:auto;border:1px solid var(--brd);border-radius:8px;background:var(--bg)}
.perf-table{width:100%;border-collapse:collapse;font-size:12px}
.perf-table th,.perf-table td{padding:7px 8px;border-bottom:1px solid var(--brd);text-align:left}
.perf-table th{background:var(--s1);color:var(--txd)}
.perf-setting-row{display:flex;gap:8px;align-items:center;justify-content:flex-start;flex-wrap:wrap}
.perf-help-btn{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;border:1px solid var(--brd);background:var(--s1);color:var(--tx);font-size:12px;cursor:pointer}
.perf-help-btn:hover{border-color:var(--ac);background:var(--s2)}
@media(max-width:1100px){.perf-grid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:700px){.perf-grid{grid-template-columns:1fr}}
</style>

<div class="perf-grid">
    <div class="perf-kpi"><strong><?=round((float)($perfStats['avg_ms'] ?? 0), 1)?> ms</strong><span>Gemiddelde request (24u)</span></div>
    <div class="perf-kpi"><strong><?=round((float)($perfStats['p95_ms'] ?? 0), 1)?> ms</strong><span>P95 request (24u)</span></div>
    <div class="perf-kpi"><strong><?=round((float)($perfStats['p99_ms'] ?? 0), 1)?> ms</strong><span>P99 request (24u)</span></div>
    <div class="perf-kpi"><strong><?=(int)($perfStats['total'] ?? 0)?></strong><span>Gemeten requests (24u)</span></div>
</div>

<div class="cd" style="margin-bottom:12px"><div class="cd-t">⚙️ Performance instellingen</div>
<form method="POST" style="display:grid;gap:8px;max-width:760px">
<input type="hidden" name="action" value="save_performance_settings"><?=csrfField()?>
<div class="perf-setting-row">
<label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="perf_monitor_enabled" value="1" <?=getSetting($db,'perf_monitor_enabled','1')==='1'?'checked':''?>> Performance logging inschakelen</label>
<button type="button" class="perf-help-btn" onclick="showPerformanceSettingInfo('monitor')" title="Uitleg over performance logging">i</button>
</div>
<div class="perf-setting-row">
<label style="display:flex;gap:8px;align-items:center"><input type="checkbox" name="perf_debug_headers" value="1" <?=getSetting($db,'perf_debug_headers','0')==='1'?'checked':''?>> Debug headers tonen voor admin</label>
<button type="button" class="perf-help-btn" onclick="showPerformanceSettingInfo('headers')" title="Uitleg over debug headers">i</button>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap">
<button type="submit" class="bt bp bsm">Opslaan</button>
</form>
<form method="POST" onsubmit="return confirm('Alle performance statistieken resetten?')">
<input type="hidden" name="action" value="reset_performance_metrics"><?=csrfField()?>
<button type="submit" class="bt bd bsm">Reset statistieken</button>
</form>
<form method="POST">
<input type="hidden" name="action" value="export_performance_metrics"><?=csrfField()?>
<button type="submit" class="bt bw bsm">Export CSV (24u)</button>
</form>
</div>
<div style="font-size:12px;color:var(--txd)">Cache hit ratio: <?=$cacheHitRate?>% (hits: <?=$cacheHits?>, misses: <?=$cacheMisses?>)</div>
<div style="font-size:12px;color:var(--txd)">SQL totaal (24u): <?=(int)($perfStats['sql']['count'] ?? 0)?> queries, <?=round((float)($perfStats['sql']['ms'] ?? 0), 1)?> ms querytijd</div>
<div style="font-size:12px;color:var(--txd)">Server piekbelasting (24u): load1 <?=round((float)($perfStats['server']['max_load1'] ?? 0),2)?>, piek geheugen <?=round((float)($perfStats['server']['max_mem_mb'] ?? 0),1)?> MB</div>
</div>
<script>
function showPerformanceSettingInfo(kind){
    var message = '';
    if(kind === 'monitor'){
        message = 'Performance logging registreert per request responstijd, cache hits/misses, SQL-aantallen en piekgeheugen. Dit helpt bij analyse van traagheid, met een kleine extra overhead.';
    } else if(kind === 'headers'){
        message = 'Debug headers voegen extra HTTP headers toe voor admin-requests, zoals totale requesttijd en cache/SQL statistieken. Dit is vooral voor troubleshooting via browser devtools of curl -I.';
    } else {
        message = 'Geen extra informatie beschikbaar.';
    }
    alert(message);
}
</script>

<div class="cd" style="margin-bottom:12px"><div class="cd-t">⏱ Bloktijden (24u)</div>
<div class="perf-table-wrap"><table class="perf-table">
<thead><tr><th>Blok</th><th>Requests</th><th>Gemiddelde</th><th>Piek</th></tr></thead>
<tbody>
<?php foreach(($perfStats['blocks'] ?? []) as $blockKey => $blockInfo): ?>
<tr>
<td><?=e((string)$blockKey)?></td>
<td><?=(int)($blockInfo['count'] ?? 0)?></td>
<td><?=round((float)($blockInfo['avg_ms'] ?? 0), 1)?> ms</td>
<td><?=round((float)($blockInfo['max_ms'] ?? 0), 1)?> ms</td>
</tr>
<?php endforeach; ?>
<?php if(empty($perfStats['blocks'])): ?><tr><td colspan="4" style="color:var(--txd)">Nog geen blokmetingen beschikbaar.</td></tr><?php endif; ?>
</tbody>
</table></div>
</div>

<div class="cd" style="margin-bottom:12px"><div class="cd-t">📊 Per pagina</div>
<div class="perf-table-wrap"><table class="perf-table">
<thead><tr><th>Pagina</th><th>Aantal</th><th>Gemiddelde</th><th>P95</th><th>P99</th></tr></thead>
<tbody>
<?php foreach(($perfStats['by_page'] ?? []) as $k => $v): ?>
<tr>
<td><?=e((string)$k)?></td>
<td><?=(int)($v['count'] ?? 0)?></td>
<td><?=round((float)($v['avg_ms'] ?? 0),1)?> ms</td>
<td><?=round((float)($v['p95_ms'] ?? 0),1)?> ms</td>
<td><?=round((float)($v['p99_ms'] ?? 0),1)?> ms</td>
</tr>
<?php endforeach; ?>
<?php if(empty($perfStats['by_page'])): ?><tr><td colspan="5" style="color:var(--txd)">Nog geen data beschikbaar.</td></tr><?php endif; ?>
</tbody>
</table></div>
</div>

<div class="cd"><div class="cd-t">🐌 Top 10 traagste requests</div>
<div class="perf-table-wrap"><table class="perf-table">
<thead><tr><th>Tijd</th><th>Pagina</th><th>Duur</th><th>Melding/achtergrond</th><th>Cache H/M</th><th>SQL</th></tr></thead>
<tbody>
<?php foreach(($perfStats['top_slowest'] ?? []) as $row): ?>
<tr>
<td><?=!empty($row['ts']) ? e(date('d-m-Y H:i:s', (int)$row['ts'])) : '-'?></td>
<td><?=e((string)($row['page'] ?? '-'))?></td>
<td><?=round((float)($row['total_ms'] ?? 0),1)?> ms</td>
<td><?=round((float)($row['notif_ms'] ?? 0),1)?> ms</td>
<td><?=(int)($row['cache_hits'] ?? 0)?> / <?=(int)($row['cache_misses'] ?? 0)?></td>
<td><?=(int)($row['sql_count'] ?? 0)?> / <?=round((float)($row['sql_ms'] ?? 0),1)?>ms</td>
</tr>
<?php endforeach; ?>
<?php if(empty($perfStats['top_slowest'])): ?><tr><td colspan="6" style="color:var(--txd)">Nog geen trage requests geregistreerd.</td></tr><?php endif; ?>
</tbody>
</table></div>
</div>
<script>
(function(){
    if(document.visibilityState === 'visible'){
        setTimeout(function(){
            if(document.visibilityState === 'visible') location.reload();
        }, 10000);
    }
})();
</script>
<?php else: ?>
<div class="cd"><div class="cd-t">Performance</div><p style="color:var(--txd)">Alleen admins hebben toegang tot performancestatistieken.</p></div>
<?php endif; ?>

<?php elseif($stab==='beheer'): ?>
<?php if($canOpenBeheerUi): ?>
<?php
$beheerTab = trim((string)($_GET['btab'] ?? 'users'));
$allowedBeheerTabs = [];
if ($isAdminUi) $allowedBeheerTabs[] = 'users';
if ($uiCanMailUse || $uiCanMailSettings || $isAdminUi) $allowedBeheerTabs[] = 'email';
if ($isAdminUi) $allowedBeheerTabs[] = 'permissions';
if ($uiCanAlertsManage || $isAdminUi) $allowedBeheerTabs[] = 'alerts';
if ($isAdminUi) $allowedBeheerTabs[] = 'rrd';
if (empty($allowedBeheerTabs)) $allowedBeheerTabs = ['email'];
if (!in_array($beheerTab, $allowedBeheerTabs, true)) $beheerTab = $allowedBeheerTabs[0];
?>
<div class="subtabs" style="margin-bottom:10px">
<?php if($isAdminUi): ?>
<a href="?p=settings&stab=beheer&btab=users" class="subtab <?=$beheerTab==='users'?'active':''?>"><span class="subtab-title">👥 Gebruikersbeheer<?php if($pendingApprovalCount>0): ?><span class="subtab-badge"><?=$pendingApprovalCount?></span><?php endif; ?></span><span class="subtab-hint">Accounts en rollen</span></a>
<?php endif; ?>
<?php if($uiCanMailUse || $uiCanMailSettings || $isAdminUi): ?>
<a href="?p=settings&stab=beheer&btab=email" class="subtab <?=$beheerTab==='email'?'active':''?>"><span class="subtab-title">📧 E-mail & Notificaties</span><span class="subtab-hint">SMTP en meldingen</span></a>
<?php endif; ?>
<?php if($isAdminUi): ?>
<a href="?p=settings&stab=beheer&btab=permissions" class="subtab <?=$beheerTab==='permissions'?'active':''?>"><span class="subtab-title">🔐 Paginarechten</span><span class="subtab-hint">Zichtbaarheid user-pagina's</span></a>
<?php endif; ?>
<?php if($uiCanAlertsManage || $isAdminUi): ?>
<a href="?p=settings&stab=beheer&btab=alerts" class="subtab <?=$beheerTab==='alerts'?'active':''?>"><span class="subtab-title">🔔 Alerts</span><span class="subtab-hint">Alertprofielen beheren</span></a>
<?php endif; ?>
<?php if($isAdminUi): ?>
<a href="?p=settings&stab=beheer&btab=rrd" class="subtab <?=$beheerTab==='rrd'?'active':''?>"><span class="subtab-title">📋 RRD Logs</span><span class="subtab-hint">Reset geschiedenis</span></a>
<?php endif; ?>
</div>

<?php if($beheerTab==='users' && $isAdminUi): ?>
<?php if($pendingApprovalCount>0): ?>
<div class="cd" style="margin-bottom:10px"><div class="cd-t">⏳ Goedkeuringswachtrij</div><p style="font-size:13px;color:var(--txd)">Er <?=($pendingApprovalCount===1?'staat':'staan')?> <strong><?=$pendingApprovalCount?></strong> gebruiker<?=($pendingApprovalCount===1?'':'s')?> te wachten op goedkeuring. Gebruik hieronder de knoppen <strong>Goedkeuren</strong> of <strong>Afwijzen</strong>.</p></div>
<?php endif; ?>
<div class="cd"><div class="beheer-users-head"><div class="cd-t" style="margin-bottom:0">👥 Gebruikersbeheer</div><button type="button" class="bt bp bsm" onclick="openM('addUserM')">+ Nieuwe Gebruiker</button></div>
<?php
$pendingRows=[];
$pendingSelect = ['id','username'];
if (userColumnExists($db, 'google_email')) $pendingSelect[] = 'google_email';
if (userColumnExists($db, 'requested_at')) $pendingSelect[] = 'requested_at';
$pendingOrder = userColumnExists($db, 'requested_at') ? 'requested_at ASC, id ASC' : 'id ASC';
$pendingSql = 'SELECT ' . implode(',', $pendingSelect) . ' FROM users WHERE approval_status="pending" ORDER BY ' . $pendingOrder;
$pendingQuery = $db->query($pendingSql);
if ($pendingQuery instanceof SQLite3Result) {
    while($pendingRow=$pendingQuery->fetchArray(SQLITE3_ASSOC)) $pendingRows[]=$pendingRow;
}
?>
<?php if(!empty($pendingRows)): ?>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px;margin-bottom:12px">
<?php foreach($pendingRows as $pending): ?>
<div style="border:1px solid var(--warn);background:var(--warnbg);border-radius:10px;padding:10px">
<div style="font-weight:800;color:var(--warnfg);font-size:13px;margin-bottom:4px"><?=e((string)($pending['username'] ?? 'onbekend'))?></div>
<?php if(!empty($pending['google_email'])): ?><div style="font-size:12px;color:var(--txd);margin-bottom:3px"><?=e((string)$pending['google_email'])?></div><?php endif; ?>
<?php if(!empty($pending['requested_at'])): ?><div style="font-size:11px;color:var(--txd);margin-bottom:8px">Aangevraagd: <?=e((string)$pending['requested_at'])?></div><?php endif; ?>
<div style="display:flex;gap:6px;flex-wrap:wrap"><form method="POST" style="display:inline"><input type="hidden" name="action" value="approve_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$pending['id']?>"><button type="submit" class="bt bp bsm">✓ Goedkeuren</button></form><form method="POST" style="display:inline" onsubmit="return confirm('Deze registratie afwijzen?')"><input type="hidden" name="action" value="reject_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$pending['id']?>"><button type="submit" class="bt bd bsm">✕ Afwijzen</button></form></div>
</div>
<?php endforeach; ?>
</div>
<div class="beheer-users-wrap" style="margin-bottom:12px">
<table class="beheer-users-table" style="font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)"><th style="text-align:left;padding:10px">Aanvraag</th><th style="text-align:left;padding:10px">Google e-mail</th><th style="text-align:left;padding:10px">Aangevraagd</th><th style="text-align:center;padding:10px">Acties</th></tr></thead><tbody>
<?php foreach($pendingRows as $pending): ?>
<tr style="border-bottom:1px solid var(--brd)"><td style="padding:10px"><?=e($pending['username'])?></td><td style="padding:10px"><?=e((string)($pending['google_email'] ?? ''))?></td><td style="padding:10px"><?=e((string)($pending['requested_at'] ?? ''))?></td><td style="padding:10px;text-align:center"><div style="display:flex;gap:6px;justify-content:center;flex-wrap:wrap"><form method="POST" style="display:inline"><input type="hidden" name="action" value="approve_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$pending['id']?>"><button type="submit" class="bt bp bsm">✓ Goedkeuren</button></form><form method="POST" style="display:inline" onsubmit="return confirm('Deze registratie afwijzen?')"><input type="hidden" name="action" value="reject_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$pending['id']?>"><button type="submit" class="bt bd bsm">✕ Afwijzen</button></form></div></td></tr>
<?php endforeach; ?></tbody></table></div>
<?php elseif($pendingApprovalCount>0): ?>
<div class="cd" style="margin-bottom:12px"><p style="font-size:13px;color:var(--warnfg)">Er zijn wachtende registraties geteld, maar de lijst kon niet volledig worden geladen. Vernieuw de pagina of controleer of de database is gemigreerd.</p></div>
<?php endif; ?>
<?php
$activeUsers=[];
$activeUsersQuery = $db->query('SELECT id,username,email,role,auth_provider,google_email,last_login_at FROM users WHERE approval_status="active" ORDER BY role DESC, username ASC');
if ($activeUsersQuery instanceof SQLite3Result) {
    while($ar=$activeUsersQuery->fetchArray(SQLITE3_ASSOC)) $activeUsers[]=$ar;
}
$roleDisplay=['admin'=>'👑 Admin','manager'=>'⚙️ Manager','user'=>'👤 User','readonly'=>'👁️ Alleen lezen'];
?>
<div class="cd" style="margin-bottom:12px">
<div class="cd-t">✅ Toegangsoverzicht (actieve gebruikers)</div>
<div class="beheer-users-wrap">
<table class="beheer-users-table" style="font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)"><th style="text-align:left;padding:10px">Gebruiker</th><th style="text-align:left;padding:10px">Rol</th><th style="text-align:left;padding:10px">Provider</th><th style="text-align:left;padding:10px">Laatste login</th></tr></thead><tbody>
<?php foreach($activeUsers as $au): ?>
<tr style="border-bottom:1px solid var(--brd)"><td style="padding:10px"><?=e((string)$au['username'])?><?=((int)$au['id']===(int)($_SESSION['uid']??0))?' <span style="color:var(--ok);font-weight:600">(jij)</span>':''?></td><td style="padding:10px"><?=$roleDisplay[$au['role']]??e((string)$au['role'])?></td><td style="padding:10px"><?=e((string)($au['auth_provider'] ?? 'local'))?><?=!empty($au['google_email'])?' <span style="color:var(--txd);font-size:11px">'.e((string)$au['google_email']).'</span>':''?></td><td style="padding:10px"><?=!empty($au['last_login_at'])?e(formatDbDateLocal((string)$au['last_login_at'])):'-'?></td></tr>
<?php endforeach; ?>
<?php if(empty($activeUsers)): ?><tr><td colspan="4" style="padding:12px;color:var(--txd)">Geen actieve gebruikers gevonden.</td></tr><?php endif; ?>
</tbody></table>
</div>
</div>
<div class="beheer-users-wrap"><table class="beheer-users-table" style="font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)"><th style="text-align:left;padding:10px">Gebruiker</th><th style="text-align:left;padding:10px">Rol</th><th style="text-align:left;padding:10px">Status</th><th style="text-align:center;padding:10px">Acties</th></tr></thead><tbody>
<?php $users=$db->query('SELECT id,username,email,role,approval_status,google_email,auth_provider,requested_at,approved_at FROM users ORDER BY CASE WHEN approval_status="pending" THEN 0 ELSE 1 END, id'); while($u=$users->fetchArray(SQLITE3_ASSOC)): $statusDisplay=['active'=>'Actief','pending'=>'Wacht op goedkeuring','rejected'=>'Afgewezen']; $statusKey=strtolower((string)($u['approval_status'] ?? 'active')); $isCurrentUser=$u['id']==$_SESSION['uid'];?>
<tr style="border-bottom:1px solid var(--brd)"><td style="padding:10px"><?=e($u['username'])?><?=$isCurrentUser?' <span style="color:var(--ok);font-weight:600">(jij)</span>':''?></td><td style="padding:10px"><?=$roleDisplay[$u['role']]??$u['role']?></td><td style="padding:10px"><span class="bge" style="<?=e($statusKey==='active' ? 'background:var(--okbg);color:var(--okfg);border:1px solid var(--ok)' : ($statusKey==='pending' ? 'background:var(--warnbg);color:var(--warnfg);border:1px solid var(--warn)' : 'background:var(--errbg);color:var(--errfg);border:1px solid var(--err)'))?>"><?=e($statusDisplay[$statusKey]??$statusKey)?></span><?=!empty($u['email'])?' <span style="color:var(--txd);font-size:11px">'.e((string)$u['email']).'</span>':''?><?=!empty($u['google_email'])?' <span style="color:var(--txd);font-size:11px">'.e((string)$u['google_email']).'</span>':''?></td><td style="padding:10px;text-align:center"><?php if($statusKey!=='active'): ?><form method="POST" style="display:inline"><input type="hidden" name="action" value="approve_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$u['id']?>"><button type="submit" class="bt bp bsm">✓ Goedkeuren</button></form><form method="POST" style="display:inline" onsubmit="return confirm('Deze registratie afwijzen?')"><input type="hidden" name="action" value="reject_user"><?=csrfField()?><input type="hidden" name="user_id" value="<?=(int)$u['id']?>"><button type="submit" class="bt bd bsm">✕ Afwijzen</button></form><?php elseif(!$isCurrentUser): ?><form method="POST" style="display:inline"><input type="hidden" name="action" value="edit_user"><input type="hidden" name="user_id" value="<?=(int)$u['id']?>"><?=csrfField()?><button type="button" class="bt bg bsm" onclick="showEditUser(<?=(int)$u['id']?>, '<?=e($u['username'])?>', '<?=$u['role']?>', '<?=e((string)($u['email'] ?? ''))?>')">✎ Bewerken</button></form><form method="POST" style="display:inline" onsubmit="return confirm('Gebruiker verwijderen?')"><input type="hidden" name="action" value="del_user"><input type="hidden" name="user_id" value="<?=(int)$u['id']?>"><?=csrfField()?><button type="submit" class="bt bd bsm">🗑 Verwijderen</button></form><?php else: ?><span style="color:var(--txd);font-size:11px">Kan jezelf niet wijzigen</span><?php endif; ?></td></tr>
<?php endwhile; ?></tbody></table></div></div>

<?php endif; ?>

<?php if($beheerTab==='email' && ($uiCanMailUse || $uiCanMailSettings || $isAdminUi)): ?>
<div class="cd"><div class="cd-t">📧 E-mail & Alert Instellingen</div>
<style>
.beheer-mail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:12px}
.beheer-card-compact{border:1px solid var(--brd);border-radius:8px;background:var(--bg);padding:10px}
.beheer-card-compact .cd-t{margin-bottom:8px}
.beheer-inline-fields{display:grid;gap:6px}
.beheer-inline-row{display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px;align-items:center}
.beheer-inline-row label{font-size:11px;color:var(--txd);font-weight:600;margin:0}
.beheer-inline-row input,.beheer-inline-row select{height:28px;padding:2px 8px;font-size:12px;line-height:1.2}
.beheer-inline-row small{grid-column:2;font-size:10px;color:var(--txd);line-height:1.35}
.beheer-toggle{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;margin-bottom:8px}
.beheer-stack-card{border:1px solid var(--brd);border-radius:8px;background:var(--bg);padding:10px;margin-bottom:10px}
.beheer-notify-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
@media(max-width:1080px){.beheer-mail-grid{grid-template-columns:1fr}}
@media(max-width:1080px){.beheer-notify-grid{grid-template-columns:1fr}}
@media(max-width:760px){.beheer-inline-row{grid-template-columns:1fr}.beheer-inline-row small{grid-column:1}}
</style>
<form method="POST"><input type="hidden" name="action" value="save_email_settings"><?=csrfField()?>
<div class="beheer-mail-grid">
<div class="beheer-card-compact">
<div class="cd-t">SMTP Instellingen</div>
<label class="beheer-toggle">
<input type="checkbox" name="smtp_enabled" value="1" <?=$emailSettings['smtp_enabled']? 'checked':''?>>
<span>SMTP E-mail verzenden inschakelen</span>
 </label>
<div class="beheer-inline-fields">
<div class="beheer-inline-row"><label>SMTP Host</label><input type="text" name="smtp_host" value="<?=e($emailSettings['smtp_host']??'smtp.gmail.com')?>" placeholder="smtp.gmail.com"></div>
<div class="beheer-inline-row"><label>Poort</label><input type="number" name="smtp_port" value="<?=$emailSettings['smtp_port']??587?>" placeholder="587"></div>
<div class="beheer-inline-row"><label>Encryptie</label><select name="smtp_encryption">
<option value="tls" <?=($emailSettings['smtp_encryption']??'tls')==='tls'?'selected':''?>>TLS</option>
<option value="ssl" <?=($emailSettings['smtp_encryption']??'')==='ssl'?'selected':''?>>SSL</option>
</select></div>
<div class="beheer-inline-row"><label>SMTP Username</label><input type="email" name="smtp_username" value="<?=e($emailSettings['smtp_username']??'')?>" placeholder="jouw.naam@gmail.com"></div>
<div class="beheer-inline-row"><label>App Password</label><input type="password" name="smtp_password" placeholder="<?=!empty($emailSettings['smtp_password'])?'••••••••••••••••':'16-cijferig App Password'?>"></div>
<div class="beheer-inline-row"><label>Afzender E-mail</label><input type="email" name="smtp_from_email" value="<?=e($emailSettings['smtp_from_email']??$emailSettings['smtp_username']??'')?>" placeholder="jouw.naam@gmail.com"></div>
<div class="beheer-inline-row"><label>Afzender Naam</label><input type="text" name="smtp_from_name" value="<?=e($emailSettings['smtp_from_name']??'SmokePing Manager')?>" placeholder="SmokePing Manager"></div>
</div>
</div>

<div class="beheer-card-compact">
<div class="cd-t">Alert Configuratie</div>
<label class="beheer-toggle">
<input type="checkbox" name="alert_enabled" value="1" <?=$emailSettings['alert_enabled']?'checked':''?>>
<span>Automatische alerts inschakelen bij target uitval</span>
</label>
<div class="beheer-inline-fields">
<div class="beheer-inline-row"><label>Uptime Drempel</label><input type="number" name="alert_threshold" value="<?=$emailSettings['alert_threshold']??95?>" min="0" max="100" placeholder="95"></div>
<small>Alert versturen als uptime onder dit percentage komt.</small>
<div class="beheer-inline-row"><label>Packet loss</label><input type="number" step="0.1" name="mail_threshold" value="<?=e((string)($emailSettings['mail_threshold']??5.0))?>" min="0" max="100" placeholder="5.0"></div>
<small>Mail alleen bij minimaal dit packet-loss percentage.</small>
<div class="beheer-inline-row"><label>Mail interval</label><input type="number" name="alert_interval_minutes" value="<?=$emailSettings['alert_interval_minutes']??15?>" min="1" max="1440" placeholder="15"></div>
<small>Minimale tijd tussen twee waarschuwingmails.</small>
<div class="beheer-inline-row"><label>Verzendlijst</label><input type="text" name="alert_recipients" value="<?=e($emailSettings['alert_recipients']??'')?>" placeholder="admin@example.com, monitor@example.com"></div>
<small>Default voor targets met notificatie en fallback voor sessie- en uitvalmails.</small>
</div>
</div>
</div>

<div class="beheer-notify-grid">
<div class="beheer-stack-card">
<div class="cd-t">⚠️ Uitval Notificaties</div>
<div class="fg">
<label style="display:flex;align-items:center;gap:8px;cursor:pointer">
<input type="checkbox" name="batch_outage_notifications" value="1" <?=((int)($emailSettings['batch_outage_notifications']??1)===1)?'checked':''?>>
<span>Batch uitval notificaties (verzamel alle uitvallen in 1 e-mail)</span>
</label>
<small style="color:var(--txd);font-size:11px;margin-left:28px">Aangeraden om e-mail spamming te voorkomen bij massale uitval. Uitgeschakeld = afzonderlijke e-mail per uitval.</small>
</div>
<div class="fg"><label>Uitval Mail Interval</label>
<select name="outage_mail_interval">
<option value="5" <?=((int)($emailSettings['outage_mail_interval']??5)===5)?'selected':''?>>5 minuten</option>
<option value="10" <?=((int)($emailSettings['outage_mail_interval']??5)===10)?'selected':''?>>10 minuten</option>
<option value="15" <?=((int)($emailSettings['outage_mail_interval']??5)===15)?'selected':''?>>15 minuten</option>
<option value="30" <?=((int)($emailSettings['outage_mail_interval']??5)===30)?'selected':''?>>30 minuten</option>
<option value="240" <?=((int)($emailSettings['outage_mail_interval']??5)===240)?'selected':''?>>4 uren</option>
<option value="480" <?=((int)($emailSettings['outage_mail_interval']??5)===480)?'selected':''?>>8 uren</option>
<option value="1440" <?=((int)($emailSettings['outage_mail_interval']??5)===1440)?'selected':''?>>1 dag</option>
<option value="2880" <?=((int)($emailSettings['outage_mail_interval']??5)===2880)?'selected':''?>>2 dagen</option>
<option value="10080" <?=((int)($emailSettings['outage_mail_interval']??5)===10080)?'selected':''?>>7 dagen</option>
</select>
<small style="color:var(--txd);font-size:11px">Bij batch worden uitval en herstel in 1 gecombineerde mail verstuurd volgens dit interval. Start/einde sessie-mails blijven direct.</small>
</div>
</div>

<div class="beheer-stack-card">
<div class="cd-t">📉 Pingverlies Notificaties</div>
<div class="fg">
<label style="display:flex;align-items:center;gap:8px;cursor:pointer">
<input type="checkbox" name="ping_loss_notifications" value="1" <?=((int)($emailSettings['ping_loss_notifications']??0)===1)?'checked':''?>>
<span>Aparte e-mail sturen bij pingverlies (per target)</span>
</label>
<small style="color:var(--txd);font-size:11px;margin-left:28px">Verwerkt pingverlies per target. Enkele verliesmomenten tonen datum+tijd, langere verliesreeksen tonen begin- en eindtijd.</small>
</div>
</div>
</div>

<div style="display:flex;gap:8px;justify-content:space-between;align-items:center">
<?php if($uiCanMailSettings || $isAdminUi): ?>
<button type="submit" class="bt bp">💾 Instellingen Opslaan</button>
<?php endif; ?>
<?php if($uiCanMailUse || $isAdminUi): ?>
<button type="button" class="bt bg" onclick="testEmail(event)">📤 Test E-mail Verzenden</button>
<?php endif; ?>
</div>
</form>

<div id="testEmailResult" style="margin-top:12px;display:none;padding:12px;border-radius:var(--r);"></div>
</div>
<?php endif; ?>

<?php if($beheerTab==='permissions' && $isAdminUi): ?>
<div class="cd" style="margin-top:12px">
<div class="cd-t">🔐 Pagina Zichtbaarheid voor niet-admin gebruikers</div>
<p style="font-size:12px;color:var(--txd);margin-bottom:12px">Beheer welke pagina's niet-admin gebruikers kunnen zien en openen. Voor gebruikers met rol <strong>user</strong> en <strong>readonly</strong> blijven Database en Logging altijd geblokkeerd voor veiligheid.</p>
<form method="POST" style="margin-bottom:12px">
<input type="hidden" name="action" value="set_user_page_permissions"><?=csrfField()?>
<?php
$pageKeys = ['targets','dashboard','database','settings','logging'];
$actionDefs = getActionPermissionDefinitions();
$actionGroups = [];
foreach ($actionDefs as $actionKey => $meta) {
    $group = (string)($meta['group'] ?? 'Overig');
    if (!isset($actionGroups[$group])) $actionGroups[$group] = [];
    $actionGroups[$group][$actionKey] = $meta;
}
?>
<div class="beheer-users-wrap">
<table class="beheer-users-table" style="font-size:13px">
<thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)">
<th style="text-align:left;padding:10px">Gebruiker</th>
<th style="text-align:center;padding:10px">Targets</th>
<th style="text-align:center;padding:10px">Dashboard</th>
<th style="text-align:center;padding:10px">Database</th>
<th style="text-align:center;padding:10px">Settings</th>
<th style="text-align:center;padding:10px">Logging</th>
</tr></thead>
<tbody>
<?php 
$userRows = [];
$usersQuery = $db->query('SELECT id,username,role FROM users WHERE approval_status="active" AND role!="admin" ORDER BY role ASC, username ASC');
if ($usersQuery instanceof SQLite3Result) {
    while($userRow = $usersQuery->fetchArray(SQLITE3_ASSOC)) $userRows[] = $userRow;
}
if (empty($userRows)): 
?>
<tr><td colspan="6" style="padding:12px;color:var(--txd);text-align:center">Geen niet-admin gebruikers gevonden.</td></tr>
<?php else: foreach($userRows as $user): 
    $perms = getPageVisibility($db, (int)$user['id']);
?>
<tr style="border-bottom:1px solid var(--brd)">
<td style="padding:10px"><input type="hidden" name="present_user_ids[]" value="<?=(int)$user['id']?>"><?=e((string)$user['username'])?> <span style="color:var(--txd);font-size:11px">(<?=e((string)$user['role'])?>)</span></td>
<?php foreach($pageKeys as $page): ?>
<td style="text-align:center;padding:10px">
<label style="display:inline-flex;align-items:center;cursor:pointer">
<input type="checkbox" name="user_<?=(int)$user['id']?>_<?=$page?>" value="1" <?=(int)($perms[$page] ?? 0) === 1 ? 'checked' : ''?> style="cursor:pointer">
</label>
</td>
<?php endforeach; ?>
</tr>
<?php endforeach; endif; ?>
</tbody>
</table>
</div>

<div class="cd-t" style="margin-top:16px">🧩 Actierechten per gebruiker</div>
<p style="font-size:12px;color:var(--txd);margin-bottom:12px">Hier bepaal je wat gebruikers exact mogen doen: toevoegen, bewerken, verplaatsen, verwijderen, mailfunctie, backups, configuratie en meer.</p>
<?php if (!empty($userRows)): ?>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px">
<?php foreach($userRows as $user):
    $actionPerms = getActionPermissions($db, (int)$user['id'], (string)$user['role']);
?>
<div class="beheer-card-compact" style="padding:12px">
<div class="cd-t" style="font-size:14px;margin-bottom:8px"><?=e((string)$user['username'])?> <span style="color:var(--txd);font-size:11px">(<?=e((string)$user['role'])?>)</span></div>
<?php foreach ($actionGroups as $groupName => $groupItems): ?>
<div style="margin-bottom:8px">
<div style="font-size:11px;color:var(--txd);text-transform:uppercase;letter-spacing:.04em;margin:6px 0"><?=e($groupName)?></div>
<?php foreach ($groupItems as $actionKey => $meta): ?>
<label style="display:flex;align-items:flex-start;gap:8px;margin:4px 0;cursor:pointer;font-size:12px">
<input type="checkbox" name="user_<?=(int)$user['id']?>_<?=$actionKey?>" value="1" <?=(int)($actionPerms[$actionKey] ?? 0) === 1 ? 'checked' : ''?>>
<span><?=e((string)($meta['label'] ?? $actionKey))?></span>
</label>
<?php endforeach; ?>
</div>
<?php endforeach; ?>
</div>
<?php endforeach; ?>
</div>
<?php endif; ?>

<button type="submit" class="bt bp" style="margin-top:12px">💾 Rechten Opslaan</button>
</form>
</div>
<?php endif; ?>

<?php if($beheerTab==='email'): ?>
<script>
function testEmail(ev) {
    var email = prompt('Voer een e-mailadres in om een testmail naartoe te sturen:', <?=json_encode($defaultTestEmail)?>);
    if(!email) return;
    var btn = ev.target;
    btn.disabled = true;
    btn.textContent = '⏳ Bezig met verzenden...';
    
    fetch('', {
        method: 'POST',
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
        body: 'action=test_email&test_email='+encodeURIComponent(email)+'&<?=csrfField(true)?>'
    })
    .then(r => r.json())
    .then(data => {
        var resultDiv = document.getElementById('testEmailResult');
        resultDiv.style.display = 'block';
        resultDiv.style.background = data.success ? 'var(--ok)' : 'var(--err)';
        resultDiv.style.color = '#fff';
        resultDiv.style.padding = '12px';
        resultDiv.style.marginTop = '12px';
        resultDiv.style.borderRadius = '6px';
        
        var html = '<strong>' + (data.success ? '✅' : '❌') + ' ' + data.message + '</strong>';
        
        // Add debug output in a collapsible section
        if(data.debug) {
            html += '<br><br>';
            html += '<details style="margin-top:8px;background:rgba(0,0,0,0.2);padding:8px;border-radius:4px;">';
            html += '<summary style="cursor:pointer;font-weight:bold;">🔍 Debug Log (klik om te openen)</summary>';
            html += '<pre style="margin-top:8px;font-size:11px;white-space:pre-wrap;word-wrap:break-word;max-height:300px;overflow-y:auto;">' + data.debug + '</pre>';
            html += '</details>';
        }
        
        resultDiv.innerHTML = html;
        btn.disabled = false;
        btn.textContent = '📤 Test E-mail Verzenden';
        
        // Auto-hide after 15 seconds (longer for debug info)
        setTimeout(() => resultDiv.style.display = 'none', 15000);
    })
    .catch(err => {
        var resultDiv = document.getElementById('testEmailResult');
        resultDiv.style.display = 'block';
        resultDiv.style.background = 'var(--err)';
        resultDiv.style.color = '#fff';
        resultDiv.style.padding = '12px';
        resultDiv.textContent = '❌ Fout: ' + err;
        btn.disabled = false;
        btn.textContent = '📤 Test E-mail Verzenden';
    });
}
</script>
<?php endif; ?>
<?php if($beheerTab==='alerts' && ($uiCanAlertsManage || $isAdminUi)): ?>
<div class="cd">
<div class="cd-t">🔔 Alert Configuraties Beheer</div>
<p style="font-size:13px;color:var(--txd);margin-bottom:16px">
    Configureer hier de alerts die je kunt toewijzen aan targets. Elke alert definieert wanneer er een notificatie moet worden verstuurd.
</p>

<?php if($uiCanAlertsManage || $isAdminUi): ?>
<button class="bt bp" onclick="openM('alertM');document.getElementById('alA').value='add_alert';document.getElementById('alTitle').textContent='Nieuwe Alert';document.getElementById('alBtn').textContent='Toevoegen';document.getElementById('alertForm').reset();document.getElementById('alER').style.display='none'">+ Nieuwe Alert</button>
<?php endif; ?>

<?php if(empty($allAlerts)):?><div style="padding:20px;text-align:center;color:var(--txd)"><p>Geen alerts geconfigureerd.</p></div>
<?php else:?><div style="padding:0;overflow-x:auto;margin-top:16px"><table class="tb">
<thead><tr><th>Naam</th><th>Weergave</th><th>Type</th><th>Drempel</th><th>Duur</th><th>Ontvangers</th><th>Status</th><?php if($uiCanAlertsManage || $isAdminUi):?><th style="text-align:right">Acties</th><?php endif;?></tr></thead><tbody>
<?php foreach($allAlerts as $al):?><tr>
<td><code style="font-size:12px"><?=e($al['name'])?></code></td>
<td><strong><?=e($al['display_name'])?></strong></td>
<td><span class="bge bge-on"><?=e(ucfirst($al['type']))?></span></td>
<td><?=round($al['threshold_loss']*100,1)?>% loss</td>
<td><?=$al['threshold_duration']?>s</td>
<td><?php if(!empty($al['recipients'])):?><code style="font-size:11px"><?=e(substr($al['recipients'],0,30))?><?=strlen($al['recipients'])>30?'...':''?></code><?php else:?><span style="color:var(--txd)">Via email settings</span><?php endif;?></td>
<td><span class="bge <?=$al['enabled']?'bge-on':'bge-off'?>"><?=$al['enabled']?'Actief':'Uit'?></span></td>
<?php if($uiCanAlertsManage || $isAdminUi):?><td><div style="display:flex;gap:4px;justify-content:flex-end">
<button class="bt bg bsm" onclick='var d=<?=json_encode($al)?>;document.getElementById("alA").value="edit_alert";document.getElementById("alTitle").textContent="Alert Bewerken";document.getElementById("alBtn").textContent="Opslaan";document.getElementById("alId").value=d.id;document.getElementById("alN").value=d.name;document.getElementById("alD").value=d.display_name;document.getElementById("alT").value=d.type;document.getElementById("alTL").value=(d.threshold_loss*100).toFixed(1);document.getElementById("alTD").value=d.threshold_duration;document.getElementById("alNM").value=d.notification_method;document.getElementById("alR").value=d.recipients||"";document.getElementById("alEn").checked=d.enabled==1;document.getElementById("alER").style.display="flex";openM("alertM")'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Alert verwijderen?')"><input type="hidden" name="action" value="del_alert"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$al['id']?>"><button class="bt bd bsm">×</button></form>
</div></td><?php endif;?>
</tr><?php endforeach;?></tbody></table></div><?php endif;?>
</div>
<?php endif; ?>

<?php else: ?>
<div class="cd"><div class="cd-t">Beheer</div><p style="color:var(--txd)">Je hebt momenteel geen beheerrechten om deze onderdelen te openen. Jouw rol is: <strong><?=e($currentRoleForUi ?: 'onbekend')?></strong>.</p></div>
<?php endif; ?>

<?php if(isAdmin($db) && $beheerTab==='rrd'): ?>
<div class="cd"><div class="cd-t">📋 RRD Reset Logs</div>
<div class="beheer-rrd-wrap"><table class="beheer-rrd-table" style="font-size:12px">
<thead><tr style="background:var(--s2);border-bottom:1px solid var(--brd)"><th style="text-align:left;padding:8px">Datum</th><th style="text-align:left;padding:8px">Gebruiker</th><th style="text-align:left;padding:8px">Target</th><th style="text-align:left;padding:8px">Status</th><th style="text-align:left;padding:8px">Details</th></tr></thead>
<tbody>
<?php $logs = $db->query('SELECT * FROM rrd_reset_logs ORDER BY created_at DESC LIMIT 50'); $hasLogs = false; while($log = $logs->fetchArray(SQLITE3_ASSOC)): $hasLogs = true; $statusBg = $log['result'] === 'success' ? 'var(--ok)' : 'var(--err)'; $statusText = $log['result'] === 'success' ? 'OK' : 'FAILED'; ?>
<tr style="border-bottom:1px solid var(--brd);font-family:monospace;font-size:11px"><td style="padding:8px;color:var(--txd)"><?=e(formatDbDateLocal($log['created_at'] ?? ''))?></td><td style="padding:8px"><?=e($log['username'])?></td><td style="padding:8px"><strong><?=e($log['category_name'])?>/<?=e($log['target_name'])?></strong></td><td style="padding:8px"><span style="background:<?=$statusBg?>;color:#fff;padding:2px 6px;border-radius:3px;font-size:10px"><?=$statusText?></span></td><td style="padding:8px;word-break:break-word;max-width:400px;color:var(--txd)"><?=e(substr($log['details'],0,200))?><?=strlen($log['details'])>200?'...':''?></td></tr>
<?php endwhile; if(!$hasLogs): ?><tr><td colspan="5" style="padding:16px;text-align:center;color:var(--txd)">Geen logs beschikbaar</td></tr><?php endif; ?>
</tbody>
</table></div></div>
<?php endif; ?>

<div class="mo" id="addUserM" onclick="if(event.target===this)closeM('addUserM')"><div class="md">
<h3>Nieuwe Gebruiker</h3>
<form method="POST"><input type="hidden" name="action" value="add_user"><?=csrfField()?>
<div class="fg"><label>Gebruikersnaam</label><input type="text" name="username" required minlength="3" placeholder="bijv. john"></div>
<div class="fg"><label>E-mailadres</label><input type="email" name="email" required placeholder="bijv. john@example.com"></div>
<div class="fg"><label>Rol</label><select name="role" required>
<option value="manager">⚙️ Manager - kan config bewerken</option>
<option value="user">👤 User - eigen targets beheren</option>
<option value="readonly">👁️ Alleen lezen - kan alles zien maar niet wijzigen</option>
<option value="admin">👑 Admin - volledige toegang (incl. gebruikersbeheer)</option>
</select></div>
<p style="margin:8px 0 0;font-size:12px;color:var(--txd)">Na toevoegen ontvangt de gebruiker een e-mail met een link om zelf een eerste wachtwoord in te stellen.</p>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px"><button type="button" class="bt bg" onclick="closeM('addUserM')">Annuleren</button><button type="submit" class="bt bp">Toevoegen</button></div>
</form></div></div>

<div class="mo" id="editUserM" onclick="if(event.target===this)closeM('editUserM')"><div class="md">
<h3>Gebruiker Bewerken</h3>
<form method="POST"><input type="hidden" name="action" value="edit_user"><?=csrfField()?>
<input type="hidden" name="user_id" id="euUserId">
<div class="fg"><label>Gebruikersnaam</label><input type="text" name="username" id="euUsername" required minlength="3"></div>
<div class="fg"><label>E-mailadres</label><input type="email" name="email" id="euEmail" required></div>
<div class="fg"><label>Rol</label><select name="role" id="euRole" required>
<option value="manager">⚙️ Manager - kan config bewerken</option>
<option value="user">👤 User - eigen targets beheren</option>
<option value="readonly">👁️ Alleen lezen - kan alles zien maar niet wijzigen</option>
<option value="admin">👑 Admin - volledige toegang</option>
</select></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px"><button type="button" class="bt bw" onclick="document.getElementById('rpwUserId').value=document.getElementById('euUserId').value;closeM('editUserM');openM('resetUserPwdM')">Reset wachtwoord…</button><button type="button" class="bt bg" onclick="closeM('editUserM')">Annuleren</button><button type="submit" class="bt bp">Opslaan</button></div>
</form></div></div>

<div class="mo" id="resetUserPwdM" onclick="if(event.target===this)closeM('resetUserPwdM')"><div class="md">
<h3>Wachtwoord resetten</h3>
<form method="POST" onsubmit="return confirm('Wachtwoord resetten?')"><input type="hidden" name="action" value="user_change_password"><?=csrfField()?>
<input type="hidden" name="user_id" id="rpwUserId">
<div class="fg"><label>Nieuw wachtwoord</label><input type="password" name="new_password" required minlength="6" placeholder="Minimaal 6 tekens"></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px"><button type="button" class="bt bg" onclick="closeM('resetUserPwdM')">Annuleren</button><button type="submit" class="bt bp">Resetten</button></div>
</form></div></div>

<div class="mo" id="alertM" onclick="if(event.target===this)closeM('alertM')"><div class="md">
<h3 id="alTitle">Nieuwe Alert</h3>
<form method="POST" id="alertForm"><input type="hidden" name="action" id="alA" value="add_alert"><?=csrfField()?>
<input type="hidden" name="id" id="alId">
<div class="fr">
<div class="fg"><label>Naam (intern)</label><input type="text" name="name" id="alN" required pattern="[a-zA-Z0-9_]+" placeholder="bijv. high_priority"></div>
<div class="fg"><label>Weergavenaam</label><input type="text" name="display_name" id="alD" required placeholder="bijv. Hoge Prioriteit Alert"></div>
</div>
<div class="fr">
<div class="fg"><label>Type</label><select name="type" id="alT">
<option value="email">E-mail</option>
<option value="sms">SMS (nog niet ondersteund)</option>
<option value="webhook">Webhook (nog niet ondersteund)</option>
</select></div>
<div class="fg"><label>Notificatie Methode</label><select name="notification_method" id="alNM">
<option value="email">E-mail</option>
</select></div>
</div>
<div class="fr">
<div class="fg"><label>Drempel (% packet loss)</label><input type="number" name="threshold_loss" id="alTL" min="0" max="100" step="0.1" value="5" required><small style="color:var(--txd);font-size:11px">Bijv. 5 = 5% packet loss</small></div>
<div class="fg"><label>Duur (seconden)</label><input type="number" name="threshold_duration" id="alTD" min="60" max="3600" value="300" required><small style="color:var(--txd);font-size:11px">Hoe lang probleem moet bestaan voordat alert</small></div>
</div>
<div class="fg"><label>E-mail Ontvangers (optioneel)</label><input type="text" name="recipients" id="alR" placeholder="mail1@example.com, mail2@example.com"><small style="color:var(--txd);font-size:11px">Laat leeg om de ontvangers uit E-mail Alerts settings te gebruiken</small></div>
<div class="fg ck" id="alER" style="display:none"><input type="checkbox" name="enabled" id="alEn" checked><label for="alEn">Alert Actief</label></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('alertM')">Annuleren</button>
<button type="submit" class="bt bp" id="alBtn">Toevoegen</button></div></form></div></div>
<?php endif; ?>

<?php elseif($stab==='email'): ?>
<?php
$typeLabels = ['session_start'=>'Sessie start','session_end'=>'Sessie einde','session_end_manual'=>'Sessie handmatig einde','session_summary'=>'Sessie tussenstand','outage_start'=>'Uitval','outage_end'=>'Uitval opgelost','outage_batch'=>'Uitval/herstel batch','ping_loss'=>'Pingverlies','test'=>'Test','notification'=>'Notificatie'];
$mailStatusMeta = [
    'pending' => ['label' => 'In wachtrij', 'bg' => 'var(--warnbg)', 'fg' => 'var(--warnfg)', 'border' => 'var(--warn)'],
    'sending' => ['label' => 'Bezig', 'bg' => 'var(--s2)', 'fg' => 'var(--tx)', 'border' => 'var(--ac)'],
    'success' => ['label' => 'Verzonden', 'bg' => 'var(--okbg)', 'fg' => 'var(--okfg)', 'border' => 'var(--ok)'],
    'failed' => ['label' => 'Mislukt', 'bg' => 'var(--errbg)', 'fg' => 'var(--errfg)', 'border' => 'var(--err)'],
    'cancelled' => ['label' => 'Geannuleerd', 'bg' => 'var(--s2)', 'fg' => 'var(--txd)', 'border' => 'var(--brd)'],
];
$queuedMailLogs = [];
$queuedRes = $db->query('SELECT id,type,target_name,email_to,subject,status,message,created_at,datetime(created_at, \'localtime\') AS created_at_local FROM mail_log WHERE status="pending" ORDER BY id ASC LIMIT 100');
if ($queuedRes) { while ($queuedRow = $queuedRes->fetchArray(SQLITE3_ASSOC)) { $queuedMailLogs[] = $queuedRow; } }
$mailLogs = [];
$mlRes = $db->query('SELECT id,type,target_name,email_to,subject,status,message,debug_output,created_at,datetime(created_at, \'localtime\') AS created_at_local FROM mail_log WHERE status <> "pending" ORDER BY id DESC LIMIT 100');
if ($mlRes) { while ($mlRow = $mlRes->fetchArray(SQLITE3_ASSOC)) { $mailLogs[] = $mlRow; } }
// Targets met notificatie ingeschakeld
$notifyTargets = [];
$ntRes = $db->query('SELECT id,display_name,session_duration,session_started_at,session_start_notified,session_end_notified,enabled FROM targets WHERE session_notify_enabled=1 ORDER BY display_name');
if ($ntRes) { while ($ntRow = $ntRes->fetchArray(SQLITE3_ASSOC)) { $notifyTargets[] = $ntRow; } }
$notifyEmail = getDefaultTestEmail($db);
?>
<div class="cd"><div class="cd-t">📧 Test E-mail Versturen</div>
<div class="fg"><label>E-mailadres</label><input type="text" id="testEmailAddr" value="<?=e($notifyEmail)?>" placeholder="ontvanger@voorbeeld.nl" style="max-width:320px"></div>
<?php if($uiCanMailUse || $isAdminUi): ?>
<button type="button" class="bt bp" onclick="sendTestEmail()">Verstuur test</button>
<?php endif; ?>
<div id="testEmailResult" style="margin-top:10px;font-size:13px"></div>
<script>
function sendTestEmail(){
  var el=document.getElementById('testEmailResult');
  el.textContent='Bezig...';
  var addr=document.getElementById('testEmailAddr').value.trim();
    fetch('',{
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'action=test_email&test_email='+encodeURIComponent(addr)+'&<?=csrfField(true)?>'
    }).then(r=>r.json()).then(d=>{
    el.innerHTML='<strong style="color:'+(d.success?'var(--ok)':'var(--err)')+'">'+
      (d.success?'✓ Mail verstuurd':'✗ Mislukt')+': '+escHtml(d.message)+'</strong>'+
      (d.debug?'<details style="margin-top:6px"><summary style="cursor:pointer;font-size:11px;color:var(--txd)">Debug output</summary><pre style="font-size:10px;overflow:auto;max-height:200px;background:var(--s2);padding:8px;border-radius:4px;margin-top:4px">'+escHtml(d.debug)+'</pre></details>':'');
  }).catch(e=>{el.textContent='Fout: '+e.message;});
}
function escHtml(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
</script>
</div>

<?php if(!empty($notifyTargets)): ?>
<div class="cd"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px"><div class="cd-t" style="margin-bottom:0">🎯 Notificatiestatus per target</div></div>
<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)">
<th style="text-align:left;padding:10px">Target</th>
<th style="text-align:left;padding:10px">Sessieduur</th>
<th style="text-align:center;padding:10px">Start verzonden</th>
<th style="text-align:center;padding:10px">Einde verzonden</th>
<th style="text-align:center;padding:10px">Actie</th>
</tr></thead><tbody>
<?php foreach($notifyTargets as $nt):
  $snLabels=['0'=>'Nee','1'=>'Ja'];
  $durLabel = $nt['session_duration'] === 'unlimited' ? 'Onbeperkt' : sessionDurationLabel($nt['session_duration']);
  $startNotified = (int)($nt['session_start_notified']??0);
  $endNotified = (int)($nt['session_end_notified']??0);
?>
<tr style="border-bottom:1px solid var(--brd)">
<td style="padding:10px"><?=e($nt['display_name'])?><?=$nt['enabled']?'':' <span style="color:var(--txd);font-size:11px">(uitgeschakeld)</span>'?></td>
<td style="padding:10px"><?=e($durLabel)?></td>
<td style="padding:10px;text-align:center"><span style="color:<?=$startNotified?'var(--ok)':'var(--txd)'?>"><?=$startNotified?'✓ Ja':'— Nee'?></span></td>
<td style="padding:10px;text-align:center"><span style="color:<?=$endNotified?'var(--ok)':'var(--txd)'?>"><?=$endNotified?'✓ Ja':'— Nee'?></span></td>
<td style="padding:10px;text-align:center">
<?php if(($uiCanMailUse || $isAdminUi) && $startNotified): ?>
<form method="POST" style="display:inline"><input type="hidden" name="action" value="reset_notify_flag"><input type="hidden" name="target_id" value="<?=(int)$nt['id']?>"><?=csrfField()?><button type="submit" class="bt bg bsm" title="Reset start-notificatie zodat bij volgende sessie opnieuw een start-mail wordt gestuurd">↺ Reset start</button></form>
<?php else: ?>
<span style="color:var(--txd);font-size:11px">—</span>
<?php endif; ?>
<?php if(($uiCanMailUse || $isAdminUi) && (int)($nt['enabled']??0)===1): ?>
<form method="POST" style="display:inline;margin-left:6px" onsubmit="return confirm('Tussenstand van deze sessie nu per e-mail versturen?')"><input type="hidden" name="action" value="session_summary_now"><input type="hidden" name="target_id" value="<?=(int)$nt['id']?>"><?=csrfField()?><button type="submit" class="bt bg bsm" title="Mail tussenstand van lopende sessie">📨 Tussenstand</button></form>
<form method="POST" style="display:inline;margin-left:6px" onsubmit="return confirm('Sessie nu handmatig beëindigen en samenvatting mailen?')"><input type="hidden" name="action" value="manual_end_session"><input type="hidden" name="target_id" value="<?=(int)$nt['id']?>"><?=csrfField()?><button type="submit" class="bt bw bsm" title="Beeindig sessie handmatig en mail samenvatting">⏹ Beëindig sessie</button></form>
<?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</tbody></table></div>
<?php endif; ?>

<div class="cd"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
<div class="cd-t" style="margin-bottom:0">📋 Mail Log <span style="font-size:12px;font-weight:400;color:var(--txd)">(laatste 100)</span></div>
<?php if(($uiCanMailUse || $isAdminUi) && !empty($mailLogs)): ?>
<form method="POST" onsubmit="return confirm('Mail log wissen?')"><input type="hidden" name="action" value="clear_mail_log"><?=csrfField()?><button type="submit" class="bt bd bsm">🗑 Log wissen</button></form>
<?php endif; ?>
</div>
<?php if(!empty($queuedMailLogs)): ?>
<div style="margin-bottom:12px;border:1px solid var(--brd);border-radius:10px;background:var(--bg);overflow:auto">
<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 12px;border-bottom:1px solid var(--brd);background:var(--s1)">
        <div style="font-weight:700">Wachtrij voor verzending <span style="font-size:12px;font-weight:400;color:var(--txd)">(<?=count($queuedMailLogs)?>)</span></div>
        <div style="font-size:12px;color:var(--txd)">Deze mails worden door deferred maintenance verstuurd.</div>
</div>
<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)">
<th style="text-align:left;padding:10px">Geplaatst</th>
<th style="text-align:left;padding:10px">Type</th>
<th style="text-align:left;padding:10px">Target</th>
<th style="text-align:left;padding:10px">Ontvanger</th>
<th style="text-align:left;padding:10px">Onderwerp</th>
<th style="text-align:center;padding:10px">Status</th>
<th style="text-align:right;padding:10px">Actie</th>
</tr></thead><tbody>
<?php foreach($queuedMailLogs as $ml):
    $tlabel = $typeLabels[$ml['type']] ?? $ml['type'];
    $statusMeta = $mailStatusMeta[$ml['status']] ?? $mailStatusMeta['pending'];
?>
<tr style="border-bottom:1px solid var(--brd);vertical-align:top">
<td style="padding:10px;white-space:nowrap;color:var(--txd);font-size:11px"><?=e($ml['created_at_local'] ?? $ml['created_at'])?></td>
<td style="padding:10px;white-space:nowrap"><?=e($tlabel)?></td>
<td style="padding:10px"><?=e($ml['target_name'])?></td>
<td style="padding:10px;font-size:11px;color:var(--txd)"><?=e($ml['email_to'])?></td>
<td style="padding:10px"><?=e($ml['subject'])?></td>
<td style="padding:10px;text-align:center"><span style="display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;background:<?=$statusMeta['bg']?>;color:<?=$statusMeta['fg']?>;border:1px solid <?=$statusMeta['border']?>"><?=e($statusMeta['label'])?></span></td>
<td style="padding:10px;text-align:right">
<?php if($uiCanMailUse || $isAdminUi): ?>
<form method="POST" onsubmit="return confirm('Deze mail uit de wachtrij halen en niet meer versturen?')" style="display:inline">
        <input type="hidden" name="action" value="cancel_queued_mail"><?=csrfField()?>
        <input type="hidden" name="mail_log_id" value="<?=(int)$ml['id']?>">
        <button type="submit" class="bt bd bsm">Annuleren</button>
</form>
<?php else: ?>
<span style="color:var(--txd);font-size:11px">-</span>
<?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</tbody></table>
</div>
<?php endif; ?>
<?php if(empty($mailLogs)): ?>
<p style="color:var(--txd);font-size:13px">Nog geen mail-pogingen geregistreerd.</p>
<?php else: ?>
<table style="width:100%;border-collapse:collapse;font-size:13px"><thead><tr style="background:var(--s2);border-bottom:2px solid var(--brd)">
<th style="text-align:left;padding:10px">Datum/tijd</th>
<th style="text-align:left;padding:10px">Type</th>
<th style="text-align:left;padding:10px">Target</th>
<th style="text-align:left;padding:10px">Ontvanger</th>
<th style="text-align:center;padding:10px">Status</th>
<th style="text-align:left;padding:10px">Bericht</th>
</tr></thead><tbody>
<?php foreach($mailLogs as $ml):
  $tlabel = $typeLabels[$ml['type']] ?? $ml['type'];
    $statusMeta = $mailStatusMeta[$ml['status']] ?? $mailStatusMeta['failed'];
?>
<tr style="border-bottom:1px solid var(--brd);vertical-align:top">
<td style="padding:10px;white-space:nowrap;color:var(--txd);font-size:11px"><?=e($ml['created_at_local'] ?? $ml['created_at'])?></td>
<td style="padding:10px;white-space:nowrap"><?=e($tlabel)?></td>
<td style="padding:10px"><?=e($ml['target_name'])?></td>
<td style="padding:10px;font-size:11px;color:var(--txd)"><?=e($ml['email_to'])?></td>
<td style="padding:10px;text-align:center"><span style="display:inline-block;padding:2px 8px;border-radius:99px;font-size:11px;font-weight:600;background:<?=$statusMeta['bg']?>;color:<?=$statusMeta['fg']?>;border:1px solid <?=$statusMeta['border']?>"><?=e($statusMeta['label'])?></span></td>
<td style="padding:10px;font-size:12px">
<?=e($ml['message'])?>
<?php if(!empty($ml['debug_output'])): ?><details style="margin-top:4px"><summary style="cursor:pointer;font-size:11px;color:var(--txd)">Debug</summary><pre style="font-size:10px;overflow:auto;max-height:200px;background:var(--s2);padding:6px;border-radius:4px;margin-top:4px;white-space:pre-wrap"><?=e($ml['debug_output'])?></pre></details><?php endif; ?>
</td>
</tr>
<?php endforeach; ?>
</tbody></table>
<?php endif; ?>
</div>

<?php endif;?>
</div>
</div><?php endif;?>

<!-- Notification Help Modal -->
<div class="mo" id="notifHelpModal" onclick="if(event.target===this)closeM('notifHelpModal')">
<div class="md">
<h3>🔔 Notificaties Activeren</h3>
<p style="color:var(--txd);margin-bottom:16px;font-size:13px">Je browser heeft notificaties geblokkeerd. Volg de onderstaande stappen om dit te wijzigen:</p>

<div class="notif-help-step">
<strong style="display:block;margin-bottom:6px">Microsoft Edge:</strong>
<ol style="margin-left:20px;font-size:13px;line-height:1.6">
<li>Klik op het slotje (🔒) in de adresbalk</li>
<li>Klik op "Machtigingen voor deze site"</li>
<li>Zoek "Meldingen" en wijzig naar "Toestaan"</li>
<li>Ververs deze pagina en klik opnieuw op de bel-icon</li>
</ol>
</div>

<div class="notif-help-step">
<strong style="display:block;margin-bottom:6px">Google Chrome:</strong>
<ol style="margin-left:20px;font-size:13px;line-height:1.6">
<li>Klik op het slotje (🔒) of info-icon (ⓘ) in de adresbalk</li>
<li>Zoek "Meldingen" in het menu</li>
<li>Wijzig naar "Toestaan"</li>
<li>Ververs deze pagina</li>
</ol>
</div>

<div class="notif-help-step">
<strong style="display:block;margin-bottom:6px">Mozilla Firefox:</strong>
<ol style="margin-left:20px;font-size:13px;line-height:1.6">
<li>Klik op het slotje (🔒) in de adresbalk</li>
<li>Klik op de pijl naast "Geblokkeerde verbinding"</li>
<li>Klik op "Meer informatie"</li>
<li>Ga naar het tabblad "Machtigingen"</li>
<li>Zoek "Meldingen" en verwijder de blokkering</li>
<li>Ververs deze pagina</li>
</ol>
</div>

<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:16px">
<button type="button" class="bt bp" onclick="closeM('notifHelpModal')">Begrepen</button>
</div>
</div>
</div>

<?php if(isLoggedIn()): ?>
<!-- Floating Action Button (Mobile Quick Add) -->
<button class="fab" onclick="openM('tgtM')" title="Snel nieuwe target toevoegen" style="display:none">+</button>
<?php endif; ?>

<script>
// Show FAB only on targets/categories page on mobile
(function(){
    var fab = document.querySelector('.fab');
    var page = '<?=$page?>';
    if(fab && (page === 'targets' || page === 'categories') && window.innerWidth <= 640) {
        fab.style.display = 'flex';
    }
    window.addEventListener('resize', function(){
        if(fab && (page === 'targets' || page === 'categories')) {
            fab.style.display = window.innerWidth <= 640 ? 'flex' : 'none';
        }
    });
})();

// Swipe gesture handler for target/category items
(function(){
    if(window.innerWidth > 640) return; // Mobile only

    var startX = 0, startY = 0, currentX = 0, isSwiping = false;
    var activeItem = null;

    document.addEventListener('touchstart', function(e){
        var item = e.target.closest('.tg, .cat-item');
        if(!item) return;
        
        activeItem = item;
        startX = e.touches[0].clientX;
        startY = e.touches[0].clientY;
        isSwiping = false;
    }, {passive: true});

    document.addEventListener('touchmove', function(e){
        if(!activeItem) return;
        
        currentX = e.touches[0].clientX;
        var deltaX = currentX - startX;
        var deltaY = e.touches[0].clientY - startY;
        
        // Detect horizontal swipe (not vertical scroll)
        if(Math.abs(deltaX) > Math.abs(deltaY) && Math.abs(deltaX) > 10) {
            isSwiping = true;
            // Optional: add visual feedback
            if(Math.abs(deltaX) > 50) {
                activeItem.style.transform = 'translateX(' + (deltaX * 0.3) + 'px)';
                activeItem.style.transition = 'none';
            }
        }
    }, {passive: true});

    document.addEventListener('touchend', function(e){
        if(!activeItem || !isSwiping) {
            if(activeItem) {
                activeItem.style.transform = '';
                activeItem.style.transition = '';
            }
            activeItem = null;
            return;
        }
        
        var deltaX = currentX - startX;
        
        // Reset transform
        activeItem.style.transform = '';
        activeItem.style.transition = 'transform 0.3s ease';
        
        // Swipe left = delete action
        if(deltaX < -80) {
            var deleteBtn = activeItem.querySelector('button[title*="Verwijder"], button[onclick*="confirm"]');
            if(deleteBtn) {
                if(confirm('Weet je zeker dat je dit wilt verwijderen?')) {
                    deleteBtn.click();
                }
            }
        }
        // Swipe right = edit action
        else if(deltaX > 80) {
            var editBtn = activeItem.querySelector('button[title*="Bewerk"], button[onclick*="edit"]');
            if(editBtn) {
                editBtn.click();
            }
        }
        
        setTimeout(function(){
            if(activeItem) activeItem.style.transition = '';
        }, 300);
        
        activeItem = null;
        isSwiping = false;
    }, {passive: true});
})();

// Mobile backups accordion: default collapsed for the 3 backup categories.
(function(){
    var currentPage = '<?=$page?>';
    var currentSettingsTab = <?=json_encode(isset($stab) ? $stab : '')?>;
    if(window.innerWidth > 640) return;
    if(currentPage !== 'settings' || currentSettingsTab !== 'backups') return;
    var cards = Array.from(document.querySelectorAll('.mobile-backup-accordion'));
    cards.forEach(function(card){
        card.classList.add('is-collapsed');
        var head = card.querySelector('.cd-t');
        if(!head) return;
        head.setAttribute('role','button');
        head.setAttribute('tabindex','0');
        var toggle = function(){
            var willOpen = card.classList.contains('is-collapsed');
            cards.forEach(function(other){
                if(other !== card) other.classList.add('is-collapsed');
            });
            if(willOpen) card.classList.remove('is-collapsed');
            else card.classList.add('is-collapsed');
        };
        head.addEventListener('click', toggle);
        head.addEventListener('keydown', function(e){
            if(e.key === 'Enter' || e.key === ' '){
                e.preventDefault();
                toggle();
            }
        });
    });
})();

<?php if(isLoggedIn()): ?>
// Run maintenance outside the main page request.
(function(){
    var fd = new FormData();
    fd.append('action', 'run_web_maintenance');
    fetch('?p=maintenance', {
        method: 'POST',
        body: fd,
        credentials: 'same-origin',
        keepalive: true
    }).catch(function(){});
})();
<?php endif; ?>
</script>

<?php
finalizePerformanceMetric($db, (string)($page ?? 'unknown'));
?>
</body></html>
ENDOFPHP
}

# If script called with --deploy-only, write web files and exit
if [ "$1" = "--deploy-only" ]; then
    set +e
    echo "Deploying web application files..."
    mkdir -p "$WEBDIR"
    deploy_php
    deploy_notify_php
    install_cli_launcher "$0" >/dev/null 2>&1 || true
    chown -R www-data:www-data "$WEBDIR" >/dev/null 2>&1 || true
    chmod 755 "$WEBDIR" >/dev/null 2>&1 || true
    [ -f "$WEBDIR/index.php" ] && chmod 644 "$WEBDIR/index.php" >/dev/null 2>&1 || true
    [ -f "$WEBDIR/smokeping-notify.php" ] && chmod 640 "$WEBDIR/smokeping-notify.php" >/dev/null 2>&1 || true
    setup_notify_cron >/dev/null 2>&1 || true
    ensure_smokeping_paths_and_permissions >/dev/null 2>&1 || true
    apply_php_upload_limits "50M" "64M" >/dev/null 2>&1 || true
    systemctl restart apache2 >/dev/null 2>&1 || true
    mkdir -p "$DBDIR" "$BACKUPDIR" >/dev/null 2>&1 || true
    chown -R www-data:www-data "$DBDIR" "$BACKUPDIR" >/dev/null 2>&1 || true
    echo "Done."
    exit 0
fi

install_cli_launcher "$0" >/dev/null 2>&1 || true

# ============================================================
# MAIN MENU LOOP
# ============================================================
while true; do
    show_menu
    case "$choice" in
        1) do_install "fresh"; pause_for_enter ;;
        2) do_update ;;
        3) do_uninstall; pause_for_enter ;;
        4) do_clear_targets; pause_for_enter ;;
        5) do_clear_rrd; pause_for_enter ;;
        6) do_wipe_all_targets; pause_for_enter ;;
        7) do_download_targets; pause_for_enter ;;
        8) do_backup; pause_for_enter ;;
        9) do_restore; pause_for_enter ;;
        10) do_change_creds; pause_for_enter ;;
        11) do_manage_users; pause_for_enter ;;
        12) do_restart_smokeping; pause_for_enter ;;
        13) do_reload_smokeping; pause_for_enter ;;
        14) do_status_smokeping; pause_for_enter ;;
        15) do_check_smokeping; pause_for_enter ;;
        0) echo "Tot ziens!"; exit 0 ;;
        *) echo "Ongeldige keuze." ; sleep 1 ;;
    esac
done