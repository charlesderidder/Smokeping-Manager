#!/bin/bash
# ============================================================
# SmokePing Manager v3 - Complete All-in-One Installer
#
# Features:
#   - Interactief installatiemenu
#   - Categorieën + Targets + Presets + IPv6
#   - Probe beheer (Probes config)
#   - MultiHost grafieken (IPv4+IPv6 gecombineerd)
#   - Backup / Restore via CLI en webinterface
#   - Uptime/downtime overzicht per target
#   - Deeplinks naar SmokePing grafieken
#   - Gebruikersbeheer
#   - Volledige SmokePing config editor
#
# Voer uit als root in je LXC-container:
#   chmod +x install_smokeping_manager.sh
#   ./install_smokeping_manager.sh
# ============================================================

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

WEBDIR="/var/www/html/smokeping-manager"
DBDIR="$WEBDIR/data"
BACKUPDIR="$WEBDIR/data/backups"
SMOKEPING_CONF_DIR="/etc/smokeping/config.d"
SMOKEPING_CONF="/etc/smokeping/config"
TARGETS_FILE="$SMOKEPING_CONF_DIR/Targets"
PROBES_FILE="$SMOKEPING_CONF_DIR/Probes"
SUDOERS_FILE="/etc/sudoers.d/smokeping-manager"

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}✗ Dit script moet als root worden uitgevoerd!${NC}"
    exit 1
fi

show_menu() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   ${CYAN}SmokePing Manager v3 - Installer${BLUE}       ║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║${NC}  1) Volledige installatie                ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  2) Alleen updaten (behoud database)     ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  3) Alles verwijderen (clean uninstall)  ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  4) Targets bestand leeghalen            ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  5) Backup maken                         ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  6) Backup terugzetten                   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  7) Gebruikersnaam/wachtwoord wijzigen   ${BLUE}║${NC}"
    echo -e "${BLUE}║${NC}  0) Afsluiten                            ${BLUE}║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
    echo ""
    read -rp "Keuze [0-7]: " choice
}

do_install() {
    local KEEP_DB="$1"
    echo ""
    echo -e "${YELLOW}[1/8]${NC} Pakketten installeren..."
    apt-get update -qq
    apt-get install -y -qq apache2 php php-sqlite3 libapache2-mod-php sqlite3 sudo rrdtool > /dev/null 2>&1
    echo -e "${GREEN}  ✓ Pakketten geïnstalleerd${NC}"

    echo -e "${YELLOW}[2/8]${NC} Apache modules..."
    a2enmod php* > /dev/null 2>&1 || true
    a2enmod rewrite > /dev/null 2>&1 || true
    echo -e "${GREEN}  ✓ Modules actief${NC}"

    echo -e "${YELLOW}[3/8]${NC} Directories..."
    mkdir -p "$WEBDIR" "$DBDIR" "$BACKUPDIR"
    echo -e "${GREEN}  ✓ Directories aangemaakt${NC}"

    echo -e "${YELLOW}[4/8]${NC} PHP Applicatie deployen..."
    deploy_php
    echo -e "${GREEN}  ✓ index.php gedeployd${NC}"

    echo -e "${YELLOW}[5/8]${NC} Rechten instellen..."
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

    # SmokePing config bestanden schrijfbaar maken
    for f in "$TARGETS_FILE" "$PROBES_FILE"; do
        [ -f "$f" ] || touch "$f"
        chown root:www-data "$f"
        chmod 664 "$f"
    done
    # Backup van alle smokeping config bestanden
    for f in "$SMOKEPING_CONF_DIR"/*; do
        [ -f "$f" ] && chown root:www-data "$f" && chmod 664 "$f"
    done
    # Hoofdconfig ook leesbaar
    [ -f "$SMOKEPING_CONF" ] && chmod 644 "$SMOKEPING_CONF"
    echo -e "${GREEN}  ✓ Rechten ingesteld${NC}"

    echo -e "${YELLOW}[6/8]${NC} Sudoers..."
    cat > "$SUDOERS_FILE" << 'EOF'
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/systemctl status smokeping
www-data ALL=(ALL) NOPASSWD: /usr/bin/smokeping --check
EOF
    chmod 440 "$SUDOERS_FILE"
    visudo -cf "$SUDOERS_FILE" > /dev/null 2>&1 && echo -e "${GREEN}  ✓ Sudoers OK${NC}" || echo -e "${RED}  ✗ Sudoers fout${NC}"

    echo -e "${YELLOW}[7/8]${NC} FPing6 probe en /run/smokeping controleren..."
    ensure_fping6_probe
    # Zorg dat /run/smokeping bestaat (wordt gewist bij reboot)
    mkdir -p /run/smokeping
    chown smokeping:smokeping /run/smokeping
    # Maak persistent via tmpfiles.d zodat het na reboot ook bestaat
    echo "d /run/smokeping 0755 smokeping smokeping -" > /etc/tmpfiles.d/smokeping.conf
    echo -e "${GREEN}  ✓ Probes en /run/smokeping gecontroleerd${NC}"

    echo -e "${YELLOW}[8/8]${NC} Apache herstarten..."
    systemctl restart apache2
    echo -e "${GREEN}  ✓ Apache herstart${NC}"

    IP=$(hostname -I | awk '{print $1}')
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e "${GREEN} ✓ SmokePing Manager v3 geïnstalleerd!${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
    echo -e " URL:   ${YELLOW}http://${IP}/smokeping-manager/${NC}"
    echo -e " Login: ${YELLOW}admin${NC} / ${YELLOW}admin${NC}"
    echo -e " ${RED}⚠  Wijzig het wachtwoord direct na eerste login!${NC}"
    echo -e "${BLUE}════════════════════════════════════════════${NC}"
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
        echo -e "${GREEN}✓ SmokePing Manager volledig verwijderd.${NC}"
        echo -e "${YELLOW}  SmokePing zelf en config bestanden zijn NIET verwijderd.${NC}"
    else
        echo "Geannuleerd."
    fi
}

do_clear_targets() {
    echo ""
    read -rp "Targets bestand leeghalen? Dit verwijdert alle targets! (ja/nee): " confirm
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
        [ -f "$bpath/rrd_data.tar.gz" ] && tar xzf "$bpath/rrd_data.tar.gz" -C /var/lib/smokeping/
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

deploy_php() {
cat > "$WEBDIR/index.php" << 'ENDOFPHP'
<?php
session_start();
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);

define('DB_PATH', __DIR__ . '/data/smokeping_manager.db');
define('BACKUP_DIR', __DIR__ . '/data/backups');
define('SMOKEPING_CONF_DIR', '/etc/smokeping/config.d');
define('SMOKEPING_TARGETS_FILE', SMOKEPING_CONF_DIR . '/Targets');
define('SMOKEPING_PROBES_FILE', SMOKEPING_CONF_DIR . '/Probes');
define('SMOKEPING_DATA_DIR', '/var/lib/smokeping');
define('SMOKEPING_CGI_URL', '/smokeping/smokeping.cgi');
define('SMOKEPING_RELOAD', 'sudo /usr/bin/systemctl reload smokeping 2>&1');
define('SMOKEPING_RESTART', 'sudo /usr/bin/systemctl restart smokeping 2>&1');
define('SMOKEPING_STATUS', 'sudo /usr/bin/systemctl status smokeping 2>&1');
define('SMOKEPING_CHECK', 'sudo /usr/bin/smokeping --check 2>&1');
define('SMOKEPING_MAIN_CONF', '/etc/smokeping/config');
define('APP_TITLE', 'SmokePing Manager');
define('APP_VERSION', 'v3.2');

function getDB(): SQLite3 {
    $db = new SQLite3(DB_PATH);
    $db->busyTimeout(5000);
    $db->exec('PRAGMA journal_mode=WAL');
    $db->exec('PRAGMA foreign_keys=ON');
    $db->exec('CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS categories (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, display_name TEXT NOT NULL, probe TEXT DEFAULT "FPing",
        remark TEXT DEFAULT "", sort_order INTEGER DEFAULT 0, enabled INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS targets (
        id INTEGER PRIMARY KEY, category_id INTEGER NOT NULL, name TEXT NOT NULL, display_name TEXT NOT NULL,
        host TEXT NOT NULL, host_ipv6 TEXT DEFAULT "", probe TEXT DEFAULT "", menu_name TEXT DEFAULT "",
        remark TEXT DEFAULT "", alert TEXT DEFAULT "", enabled INTEGER DEFAULT 1, sort_order INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (category_id) REFERENCES categories(id) ON DELETE CASCADE)');
    $db->exec('CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, binary_path TEXT DEFAULT "/usr/bin/fping",
        protocol TEXT DEFAULT "", step INTEGER DEFAULT 300, pings INTEGER DEFAULT 20,
        extra_config TEXT DEFAULT "", enabled INTEGER DEFAULT 1)');
    $db->exec('CREATE TABLE IF NOT EXISTS multigraphs (
        id INTEGER PRIMARY KEY, name TEXT NOT NULL, display_name TEXT NOT NULL,
        sort_order INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)');
    $db->exec('CREATE TABLE IF NOT EXISTS multigraph_targets (
        id INTEGER PRIMARY KEY, multigraph_id INTEGER NOT NULL, target_id INTEGER NOT NULL,
        FOREIGN KEY (multigraph_id) REFERENCES multigraphs(id) ON DELETE CASCADE,
        FOREIGN KEY (target_id) REFERENCES targets(id) ON DELETE CASCADE)');
    $s = $db->prepare('SELECT COUNT(*) c FROM users'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) { $s = $db->prepare('INSERT INTO users (username,password) VALUES(:u,:p)');
        $s->bindValue(':u','admin'); $s->bindValue(':p',password_hash('admin',PASSWORD_BCRYPT)); $s->execute(); }
    $s = $db->prepare('SELECT COUNT(*) c FROM probes'); $r = $s->execute()->fetchArray();
    if ($r['c'] == 0) {
        $db->exec("INSERT INTO probes (name,binary_path,protocol) VALUES ('FPing','/usr/bin/fping','')");
        $db->exec("INSERT INTO probes (name,binary_path,protocol) VALUES ('FPing6','/usr/bin/fping','6')");
        $db->exec("INSERT INTO probes (name,binary_path,protocol) VALUES ('DNS','/usr/bin/dig','')");
    }
    return $db;
}
$db = getDB();

function isLoggedIn(): bool { return isset($_SESSION['uid']); }
function requireLogin() { if (!isLoggedIn()) { header('Location:?p=login'); exit; } }
function redir(string $p, array $q=[]): void { $u='?p='.urlencode($p); foreach($q as $k=>$v) $u.='&'.urlencode($k).'='.urlencode($v); header("Location:$u"); exit; }
function flash(string $m,string $t='success') { $_SESSION['flash']=['msg'=>$m,'type'=>$t]; }
function getFlash(): ?array { if(isset($_SESSION['flash'])){$f=$_SESSION['flash'];unset($_SESSION['flash']);return $f;} return null; }
function e(string $s): string { return htmlspecialchars($s,ENT_QUOTES,'UTF-8'); }
function csrf(): string { if(empty($_SESSION['csrf'])) $_SESSION['csrf']=bin2hex(random_bytes(32)); return $_SESSION['csrf']; }
function csrfField(): string { return '<input type="hidden" name="csrf" value="'.csrf().'">'; }
function verifyCsrf(): bool { return isset($_POST['csrf'],$_SESSION['csrf'])&&hash_equals($_SESSION['csrf'],$_POST['csrf']); }
function safeName(string $s): string { return preg_replace('/[^a-zA-Z0-9_]/','_',$s); }
function safeBackupName(string $s): string { return preg_replace('/[^a-zA-Z0-9_\-]/','',basename($s)); }
function getCats($db) { $r=$db->query('SELECT * FROM categories ORDER BY sort_order,name'); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getTargetsForCat($db,$cid) { $s=$db->prepare('SELECT * FROM targets WHERE category_id=:c ORDER BY sort_order,name'); $s->bindValue(':c',$cid,SQLITE3_INTEGER); $r=$s->execute(); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getAllTargets($db) { $r=$db->query('SELECT t.*,c.name as cat_name,c.display_name as cat_display FROM targets t JOIN categories c ON t.category_id=c.id ORDER BY c.sort_order,c.name,t.sort_order,t.name'); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getProbes($db) { $r=$db->query('SELECT * FROM probes WHERE enabled=1 ORDER BY name'); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getAllProbes($db) { $r=$db->query('SELECT * FROM probes ORDER BY name'); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getMultiGraphs($db) { $r=$db->query('SELECT * FROM multigraphs ORDER BY sort_order,name'); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a; }
function getMultiGraphTargets($db, $mgId) {
    $s=$db->prepare('SELECT t.*,c.name as cat_name,c.display_name as cat_display FROM multigraph_targets mt JOIN targets t ON mt.target_id=t.id JOIN categories c ON t.category_id=c.id WHERE mt.multigraph_id=:m ORDER BY t.name');
    $s->bindValue(':m',$mgId,SQLITE3_INTEGER); $r=$s->execute(); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=$row; return $a;
}
function getMultiGraphTargetIds($db, $mgId) {
    $s=$db->prepare('SELECT target_id FROM multigraph_targets WHERE multigraph_id=:m');
    $s->bindValue(':m',$mgId,SQLITE3_INTEGER); $r=$s->execute(); $a=[]; while($row=$r->fetchArray(SQLITE3_ASSOC)) $a[]=(int)$row['target_id']; return $a;
}

function deepLink(string $catName, string $targetName=''): string {
    $path = safeName($catName);
    if ($targetName) $path .= '.' . safeName($targetName);
    return SMOKEPING_CGI_URL . '?target=' . $path;
}

// RRD data uitlezen voor uptime info
function getTargetStatus(string $catName, string $targetName): array {
    $rrdFile = SMOKEPING_DATA_DIR . '/' . safeName($catName) . '/' . safeName($targetName) . '.rrd';
    $result = ['exists' => false, 'loss' => null, 'median' => null, 'last_down' => null, 'downtime_str' => ''];
    if (!file_exists($rrdFile)) return $result;
    $result['exists'] = true;
    $out = @shell_exec("rrdtool lastupdate " . escapeshellarg($rrdFile) . " 2>/dev/null");
    if ($out) {
        $lines = explode("\n", trim($out));
        $last = end($lines);
        if (preg_match('/^(\d+):\s+(.+)/', $last, $m)) {
            $vals = preg_split('/\s+/', trim($m[2]));
            $loss = $vals[0] ?? null;
            $median = $vals[1] ?? null;
            $result['loss'] = ($loss !== null && $loss !== 'NaN') ? (float)$loss : null;
            $result['median'] = ($median !== null && $median !== 'NaN') ? round((float)$median * 1000, 2) : null;
        }
    }
    // Check recente downtime via rrdtool fetch
    $fetch = @shell_exec("rrdtool fetch " . escapeshellarg($rrdFile) . " AVERAGE -s -3600 2>/dev/null");
    if ($fetch) {
        $downPeriods = [];
        $inDown = false;
        $downStart = 0;
        foreach (explode("\n", $fetch) as $line) {
            if (preg_match('/^(\d+):\s+(.+)/', $line, $m)) {
                $ts = (int)$m[1];
                $vals = preg_split('/\s+/', trim($m[2]));
                $loss = $vals[0] ?? 'NaN';
                if ($loss === 'NaN' || (float)$loss >= 1.0) {
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
        if (!empty($downPeriods)) {
            $result['downtime_str'] = implode("\n", array_slice($downPeriods, -5));
        }
    }
    return $result;
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
        if ($p['step'] && $p['step'] != 300) $c .= "step = {$p['step']}\n";
        if ($p['pings'] && $p['pings'] != 20) $c .= "pings = {$p['pings']}\n";
        if (!empty($p['extra_config'])) $c .= $p['extra_config'] . "\n";
        $c .= "\n";
    }
    return $c;
}

function generateTargetsConfig($db): string {
    $c = "# Auto-generated by SmokePing Manager " . APP_VERSION . "\n# " . date('Y-m-d H:i:s') . "\n\n";
    $c .= "*** Targets ***\n\nprobe = FPing\nmenu = Top\ntitle = Netwerk Latency Monitor\nremark = Beheerd via SmokePing Manager\n\n";
    $cats = $db->query('SELECT * FROM categories WHERE enabled=1 ORDER BY sort_order,name');
    $multiHosts = []; // verzamel voor multihost grafieken
    while ($cat = $cats->fetchArray(SQLITE3_ASSOC)) {
        $cn = safeName($cat['name']);
        $c .= "+ {$cn}\nmenu = {$cat['display_name']}\ntitle = {$cat['display_name']}\n";
        if (!empty($cat['probe']) && $cat['probe'] !== 'FPing') $c .= "probe = {$cat['probe']}\n";
        if (!empty($cat['remark'])) $c .= "remark = {$cat['remark']}\n";
        $c .= "\n";
        $st = $db->prepare('SELECT * FROM targets WHERE category_id=:c AND enabled=1 ORDER BY sort_order,name');
        $st->bindValue(':c', $cat['id'], SQLITE3_INTEGER);
        $tgts = $st->execute();
        while ($t = $tgts->fetchArray(SQLITE3_ASSOC)) {
            $tn = safeName($t['name']);
            $menu = !empty($t['menu_name']) ? $t['menu_name'] : $t['display_name'];
            $c .= "++ {$tn}\nmenu = {$menu}\ntitle = {$t['display_name']}\nhost = {$t['host']}\n";
            if (!empty($t['probe'])) $c .= "probe = {$t['probe']}\n";
            if (!empty($t['remark'])) $c .= "remark = {$t['remark']}\n";
            if (!empty($t['alert'])) $c .= "alerts = {$t['alert']}\n";
            $c .= "\n";
            // IPv6 variant
            if (!empty($t['host_ipv6'])) {
                $c .= "++ {$tn}_v6\nmenu = {$menu} (IPv6)\ntitle = {$t['display_name']} IPv6\nprobe = FPing6\nhost = {$t['host_ipv6']}\n\n";
                $multiHosts[] = ['cat' => $cn, 'name' => $t['display_name'], 'v4' => $tn, 'v6' => $tn . '_v6'];
            }
        }
    }
    // Auto MultiHost grafieken voor IPv4+IPv6 combinaties
    if (!empty($multiHosts)) {
        $c .= "+ MultiHost_IPv4_IPv6\nmenu = IPv4 vs IPv6\ntitle = IPv4 vs IPv6 Vergelijking\n\n";
        foreach ($multiHosts as $mh) {
            $safeName = safeName($mh['name']) . '_combined';
            $c .= "++ {$safeName}\nmenu = {$mh['name']} (v4+v6)\ntitle = {$mh['name']} IPv4 vs IPv6\n";
            $c .= "host = /{$mh['cat']}/{$mh['v4']} /{$mh['cat']}/{$mh['v6']}\n\n";
        }
    }
    // Custom gecombineerde grafieken
    $mgs = getMultiGraphs($db);
    if (!empty($mgs)) {
        $c .= "+ Gecombineerd\nmenu = Gecombineerde Grafieken\ntitle = Gecombineerde Grafieken\n\n";
        foreach ($mgs as $mg) {
            $mgTargets = getMultiGraphTargets($db, $mg['id']);
            if (empty($mgTargets)) continue;
            $hosts = [];
            foreach ($mgTargets as $mgt) {
                $hosts[] = '/' . safeName($mgt['cat_name']) . '/' . safeName($mgt['name']);
                if (!empty($mgt['host_ipv6'])) {
                    $hosts[] = '/' . safeName($mgt['cat_name']) . '/' . safeName($mgt['name']) . '_v6';
                }
            }
            $c .= "++ " . safeName($mg['name']) . "\nmenu = {$mg['display_name']}\ntitle = {$mg['display_name']}\n";
            $c .= "host = " . implode(' ', $hosts) . "\n\n";
        }
    }
    return $c;
}

function ensureRunDir(): void {
    if (!is_dir('/run/smokeping')) { @mkdir('/run/smokeping', 0755, true); @chown('/run/smokeping', 'smokeping'); @chgrp('/run/smokeping', 'smokeping'); }
}

function writeAllConfig($db): array {
    // Probes
    $pc = generateProbesConfig($db);
    if (@file_put_contents(SMOKEPING_PROBES_FILE, $pc) === false)
        return ['success'=>false,'msg'=>'Kan Probes niet schrijven'];
    // Targets
    $tc = generateTargetsConfig($db);
    if (@file_put_contents(SMOKEPING_TARGETS_FILE, $tc) === false)
        return ['success'=>false,'msg'=>'Kan Targets niet schrijven'];
    ensureRunDir();
    $out = shell_exec(SMOKEPING_RESTART);
    return ['success'=>true,'msg'=>'Config geschreven & SmokePing herstart uitgevoerd.','output'=>$out];
}

function doRestart(): array {
    ensureRunDir();
    $out = shell_exec(SMOKEPING_RESTART);
    return ['success'=>true,'msg'=>'SmokePing herstart uitgevoerd.','output'=>$out];
}

// Presets
function getPresets(): array {
    return [
        'dns'=>['label'=>'DNS Servers','cat'=>['name'=>'DNS','display_name'=>'DNS','probe'=>'DNS'],'targets'=>[
            ['name'=>'CloudflareDNS1','dn'=>'Cloudflare DNS 1','t'=>'Cloudflare DNS 1.1.1.1','h'=>'1.1.1.1','h6'=>'2606:4700:4700::1111'],
            ['name'=>'CloudflareDNS2','dn'=>'Cloudflare DNS 2','t'=>'Cloudflare DNS 1.0.0.1','h'=>'1.0.0.1','h6'=>'2606:4700:4700::1001'],
            ['name'=>'GoogleDNS1','dn'=>'Google DNS 1','t'=>'Google DNS 8.8.8.8','h'=>'8.8.8.8','h6'=>'2001:4860:4860::8888'],
            ['name'=>'GoogleDNS2','dn'=>'Google DNS 2','t'=>'Google DNS 8.8.4.4','h'=>'8.8.4.4','h6'=>'2001:4860:4860::8844'],
            ['name'=>'L3_1','dn'=>'Level3 DNS 1','t'=>'Level3 DNS 4.2.2.1','h'=>'4.2.2.1','h6'=>''],
            ['name'=>'L3_2','dn'=>'Level3 DNS 2','t'=>'Level3 DNS 4.2.2.2','h'=>'4.2.2.2','h6'=>''],
            ['name'=>'OpenDNS1','dn'=>'OpenDNS 1','t'=>'OpenDNS 208.67.222.222','h'=>'208.67.222.222','h6'=>'2620:119:35::35'],
            ['name'=>'OpenDNS2','dn'=>'OpenDNS 2','t'=>'OpenDNS 208.67.220.220','h'=>'208.67.220.220','h6'=>'2620:119:53::53'],
            ['name'=>'Quad9','dn'=>'Quad9','t'=>'Quad9 DNS 9.9.9.9','h'=>'9.9.9.9','h6'=>'2620:fe::fe'],
        ]],
        'ipv6'=>['label'=>'IPv6 Websites','cat'=>['name'=>'IPv6','display_name'=>'IPv6 websites','probe'=>'FPing6'],'targets'=>[
            ['name'=>'GoogleIPv6','dn'=>'Google IPv6','t'=>'ipv6.google.com','h'=>'ipv6.google.com','h6'=>''],
            ['name'=>'TestMyIPv6','dn'=>'TestMyIPv6','t'=>'v6.testmyipv6.com','h'=>'v6.testmyipv6.com','h6'=>''],
            ['name'=>'FacebookIPv6','dn'=>'Facebook IPv6','t'=>'www.v6.facebook.com','h'=>'www.v6.facebook.com','h6'=>''],
        ]],
        'nl'=>['label'=>'NL Providers','cat'=>['name'=>'NL_Providers','display_name'=>'NL Providers','probe'=>'FPing'],'targets'=>[
            ['name'=>'ZiggoDNS1','dn'=>'Ziggo DNS 1','t'=>'Ziggo DNS 62.179.104.196','h'=>'62.179.104.196','h6'=>''],
            ['name'=>'ZiggoDNS2','dn'=>'Ziggo DNS 2','t'=>'Ziggo DNS 213.46.228.196','h'=>'213.46.228.196','h6'=>''],
        ]],
        'cdn'=>['label'=>'Websites / CDN','cat'=>['name'=>'WebCDN','display_name'=>'Websites en CDN','probe'=>'FPing'],'targets'=>[
            ['name'=>'Google','dn'=>'Google','t'=>'google.com','h'=>'google.com','h6'=>''],
            ['name'=>'Cloudflare','dn'=>'Cloudflare','t'=>'cloudflare.com','h'=>'cloudflare.com','h6'=>''],
            ['name'=>'Amazon','dn'=>'Amazon AWS','t'=>'aws.amazon.com','h'=>'aws.amazon.com','h6'=>''],
            ['name'=>'Microsoft','dn'=>'Microsoft','t'=>'microsoft.com','h'=>'microsoft.com','h6'=>''],
        ]],
    ];
}

// ============================================================
// ROUTING
// ============================================================
$page = $_GET['p'] ?? (isLoggedIn() ? 'dash' : 'login');
$act = $_POST['action'] ?? '';
if ($_SERVER['REQUEST_METHOD']==='POST' && $act) {
    if ($act==='login') {
        $s=$db->prepare('SELECT * FROM users WHERE username=:u'); $s->bindValue(':u',trim($_POST['username']??''));
        $row=$s->execute()->fetchArray(SQLITE3_ASSOC);
        if ($row && password_verify($_POST['password']??'',$row['password'])) {
            $_SESSION['uid']=$row['id']; $_SESSION['uname']=$row['username']; flash('Welkom!'); redir('dash');
        }
        flash('Ongeldige login.','error'); redir('login');
    }
    if ($act==='logout') { session_destroy(); header('Location:?p=login'); exit; }
    if (!isLoggedIn()) redir('login');
    if (!verifyCsrf()) { flash('CSRF fout.','error'); redir('dash'); }

    // Categories
    if ($act==='add_cat') {
        $s=$db->prepare('INSERT INTO categories(name,display_name,probe,remark,sort_order) VALUES(:n,:d,:p,:r,:s)');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':p',trim($_POST['probe']??'FPing')); $s->bindValue(':r',trim($_POST['remark']??''));
        $s->bindValue(':s',(int)($_POST['sort_order']??0));
        $s->execute(); $r=writeAllConfig($db); flash('Categorie toegevoegd. '.$r['msg']); redir('dash');
    }
    if ($act==='edit_cat') {
        $s=$db->prepare('UPDATE categories SET name=:n,display_name=:d,probe=:p,remark=:r,sort_order=:s,enabled=:e WHERE id=:id');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':p',trim($_POST['probe']??'FPing')); $s->bindValue(':r',trim($_POST['remark']??''));
        $s->bindValue(':s',(int)($_POST['sort_order']??0)); $s->bindValue(':e',isset($_POST['enabled'])?1:0);
        $s->bindValue(':id',(int)$_POST['id']); $s->execute(); $r=writeAllConfig($db); flash('Bijgewerkt. '.$r['msg']); redir('dash');
    }
    if ($act==='del_cat') {
        $db->exec('DELETE FROM targets WHERE category_id='.(int)$_POST['id']);
        $s=$db->prepare('DELETE FROM categories WHERE id=:id'); $s->bindValue(':id',(int)$_POST['id']); $s->execute();
        $r=writeAllConfig($db); flash('Verwijderd. '.$r['msg']); redir('dash');
    }
    // Targets
    if ($act==='add_tgt') {
        $cid=(int)$_POST['category_id'];
        $s=$db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6,probe,menu_name,remark,alert,sort_order) VALUES(:c,:n,:d,:h,:h6,:p,:m,:r,:a,:s)');
        $s->bindValue(':c',$cid); $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':h',trim($_POST['host'])); $s->bindValue(':h6',trim($_POST['host_ipv6']??''));
        $s->bindValue(':p',trim($_POST['probe']??'')); $s->bindValue(':m',trim($_POST['menu_name']??''));
        $s->bindValue(':r',trim($_POST['remark']??'')); $s->bindValue(':a',trim($_POST['alert']??''));
        $s->bindValue(':s',(int)($_POST['sort_order']??0));
        $s->execute(); $r=writeAllConfig($db); flash('Target toegevoegd. '.$r['msg']); redir('cat',['id'=>$cid]);
    }
    if ($act==='edit_tgt') {
        $cid=(int)$_POST['category_id'];
        $s=$db->prepare('UPDATE targets SET category_id=:c,name=:n,display_name=:d,host=:h,host_ipv6=:h6,probe=:p,menu_name=:m,remark=:r,alert=:a,sort_order=:s,enabled=:e,updated_at=CURRENT_TIMESTAMP WHERE id=:id');
        $s->bindValue(':c',$cid); $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':d',trim($_POST['display_name']));
        $s->bindValue(':h',trim($_POST['host'])); $s->bindValue(':h6',trim($_POST['host_ipv6']??''));
        $s->bindValue(':p',trim($_POST['probe']??'')); $s->bindValue(':m',trim($_POST['menu_name']??''));
        $s->bindValue(':r',trim($_POST['remark']??'')); $s->bindValue(':a',trim($_POST['alert']??''));
        $s->bindValue(':s',(int)($_POST['sort_order']??0)); $s->bindValue(':e',isset($_POST['enabled'])?1:0);
        $s->bindValue(':id',(int)$_POST['id']); $s->execute(); $r=writeAllConfig($db); flash('Bijgewerkt. '.$r['msg']); redir('cat',['id'=>$cid]);
    }
    if ($act==='del_tgt') {
        $cid=(int)$_POST['category_id']; $s=$db->prepare('DELETE FROM targets WHERE id=:id');
        $s->bindValue(':id',(int)$_POST['id']); $s->execute(); $r=writeAllConfig($db); flash('Verwijderd. '.$r['msg']); redir('cat',['id'=>$cid]);
    }
    // Probes
    if ($act==='add_probe') {
        $s=$db->prepare('INSERT INTO probes(name,binary_path,protocol,step,pings,extra_config) VALUES(:n,:b,:pr,:st,:pi,:e)');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':b',trim($_POST['binary_path']??'/usr/bin/fping'));
        $s->bindValue(':pr',trim($_POST['protocol']??'')); $s->bindValue(':st',(int)($_POST['step']??300));
        $s->bindValue(':pi',(int)($_POST['pings']??20)); $s->bindValue(':e',trim($_POST['extra_config']??''));
        $s->execute(); $r=writeAllConfig($db); flash('Probe toegevoegd. '.$r['msg']); redir('probes');
    }
    if ($act==='edit_probe') {
        $s=$db->prepare('UPDATE probes SET name=:n,binary_path=:b,protocol=:pr,step=:st,pings=:pi,extra_config=:e,enabled=:en WHERE id=:id');
        $s->bindValue(':n',trim($_POST['name'])); $s->bindValue(':b',trim($_POST['binary_path']??'/usr/bin/fping'));
        $s->bindValue(':pr',trim($_POST['protocol']??'')); $s->bindValue(':st',(int)($_POST['step']??300));
        $s->bindValue(':pi',(int)($_POST['pings']??20)); $s->bindValue(':e',trim($_POST['extra_config']??''));
        $s->bindValue(':en',isset($_POST['enabled'])?1:0); $s->bindValue(':id',(int)$_POST['id']);
        $s->execute(); $r=writeAllConfig($db); flash('Probe bijgewerkt. '.$r['msg']); redir('probes');
    }
    if ($act==='del_probe') {
        $s=$db->prepare('DELETE FROM probes WHERE id=:id'); $s->bindValue(':id',(int)$_POST['id']);
        $s->execute(); $r=writeAllConfig($db); flash('Probe verwijderd. '.$r['msg']); redir('probes');
    }
    // MultiGraphs
    if ($act==='add_mg') {
        $tids = $_POST['target_ids'] ?? [];
        $mgName = trim($_POST['name'] ?? '');
        $mgDisplay = trim($_POST['display_name'] ?? '');
        if (empty($tids) || empty($mgName)) { flash('Selecteer targets en vul een naam in.','error'); redir('graphs'); }
        $s=$db->prepare('INSERT INTO multigraphs(name,display_name,sort_order) VALUES(:n,:d,:s)');
        $s->bindValue(':n',safeName($mgName)); $s->bindValue(':d',$mgDisplay ?: $mgName); $s->bindValue(':s',(int)($_POST['sort_order']??0));
        $s->execute(); $mgId=$db->lastInsertRowID();
        foreach ($tids as $tid) {
            $s=$db->prepare('INSERT INTO multigraph_targets(multigraph_id,target_id) VALUES(:m,:t)');
            $s->bindValue(':m',$mgId); $s->bindValue(':t',(int)$tid); $s->execute();
        }
        $r=writeAllConfig($db); flash('Gecombineerde grafiek aangemaakt. '.$r['msg']); redir('graphs');
    }
    if ($act==='edit_mg') {
        $mgId=(int)$_POST['id']; $tids=$_POST['target_ids']??[];
        $mgName=trim($_POST['name']??''); $mgDisplay=trim($_POST['display_name']??'');
        if(empty($mgName)){flash('Naam is verplicht.','error');redir('graphs');}
        $s=$db->prepare('UPDATE multigraphs SET name=:n,display_name=:d,sort_order=:s WHERE id=:id');
        $s->bindValue(':n',safeName($mgName));$s->bindValue(':d',$mgDisplay?:$mgName);$s->bindValue(':s',(int)($_POST['sort_order']??0));$s->bindValue(':id',$mgId);$s->execute();
        $db->exec('DELETE FROM multigraph_targets WHERE multigraph_id='.$mgId);
        foreach($tids as $tid){$s=$db->prepare('INSERT INTO multigraph_targets(multigraph_id,target_id) VALUES(:m,:t)');$s->bindValue(':m',$mgId);$s->bindValue(':t',(int)$tid);$s->execute();}
        $r=writeAllConfig($db); flash('Grafiek bijgewerkt. '.$r['msg']); redir('graphs');
    }
    if ($act==='del_mg') {
        $s=$db->prepare('DELETE FROM multigraphs WHERE id=:id'); $s->bindValue(':id',(int)$_POST['id']); $s->execute();
        $r=writeAllConfig($db); flash('Grafiek verwijderd. '.$r['msg']); redir('graphs');
    }
    // Presets
    if ($act==='import_preset') {
        $presets=getPresets(); $sel=$_POST['presets']??[]; $selT=$_POST['preset_targets']??[]; $imp=0;
        foreach($sel as $key) {
            if(!isset($presets[$key])) continue; $p=$presets[$key]; $cat=$p['cat'];
            $ch=$db->prepare('SELECT id FROM categories WHERE name=:n'); $ch->bindValue(':n',$cat['name']);
            $ex=$ch->execute()->fetchArray(SQLITE3_ASSOC);
            if($ex) { $catId=(int)$ex['id']; } else {
                $s=$db->prepare('INSERT INTO categories(name,display_name,probe) VALUES(:n,:d,:p)');
                $s->bindValue(':n',$cat['name']); $s->bindValue(':d',$cat['display_name']); $s->bindValue(':p',$cat['probe']);
                $s->execute(); $catId=(int)$db->lastInsertRowID();
            }
            foreach($p['targets'] as $t) {
                $tk=$key.'__'.$t['name'];
                if(!empty($selT)&&!in_array($tk,$selT)) continue;
                $ch2=$db->prepare('SELECT id FROM targets WHERE category_id=:c AND name=:n');
                $ch2->bindValue(':c',$catId); $ch2->bindValue(':n',$t['name']);
                if($ch2->execute()->fetchArray()) continue;
                $s=$db->prepare('INSERT INTO targets(category_id,name,display_name,host,host_ipv6) VALUES(:c,:n,:d,:h,:h6)');
                $s->bindValue(':c',$catId); $s->bindValue(':n',$t['name']); $s->bindValue(':d',$t['t']??$t['dn']);
                $s->bindValue(':h',$t['h']); $s->bindValue(':h6',$t['h6']??''); $s->execute(); $imp++;
            }
        }
        if($imp>0){$r=writeAllConfig($db);flash("$imp target(s) geïmporteerd. ".$r['msg']);}
        else flash('Geen nieuwe targets.','error');
        redir('dash');
    }
    // Backup web - complete backup
    if ($act==='backup') {
        $stamp=date('Ymd_His'); $bdir=BACKUP_DIR."/backup_$stamp"; mkdir($bdir,0750,true);
        // Alle config.d bestanden
        foreach(glob(SMOKEPING_CONF_DIR.'/*') as $f) if(is_file($f)) copy($f,$bdir.'/'.basename($f));
        // Hoofdconfig
        if(file_exists(SMOKEPING_MAIN_CONF)) copy(SMOKEPING_MAIN_CONF,$bdir.'/smokeping_main_config');
        // Smokemail en tmail
        if(file_exists('/etc/smokeping/smokemail')) copy('/etc/smokeping/smokemail',$bdir.'/smokemail');
        if(file_exists('/etc/smokeping/tmail')) copy('/etc/smokeping/tmail',$bdir.'/tmail');
        if(file_exists('/etc/smokeping/smokeping_secrets')) copy('/etc/smokeping/smokeping_secrets',$bdir.'/smokeping_secrets');
        // Manager database
        if(file_exists(DB_PATH)) copy(DB_PATH,$bdir.'/smokeping_manager.db');
        // RRD data
        @exec("tar czf ".escapeshellarg($bdir.'/rrd_data.tar.gz')." -C ".SMOKEPING_DATA_DIR." . 2>/dev/null");
        chown($bdir, 'www-data'); @exec("chown -R www-data:www-data ".escapeshellarg($bdir));
        flash("Complete backup gemaakt: backup_$stamp"); redir('backup');
    }
    if ($act==='download_backup') {
        $bname = safeBackupName($_POST['backup_name'] ?? '');
        $bdir = BACKUP_DIR . '/' . $bname;
        if (is_dir($bdir)) {
            $tarfile = BACKUP_DIR . '/' . $bname . '.tar.gz';
            exec("tar czf " . escapeshellarg($tarfile) . " -C " . escapeshellarg(BACKUP_DIR) . " " . escapeshellarg($bname) . " 2>/dev/null");
            if (file_exists($tarfile)) {
                header('Content-Type: application/gzip');
                header('Content-Disposition: attachment; filename="' . $bname . '.tar.gz"');
                header('Content-Length: ' . filesize($tarfile));
                readfile($tarfile);
                @unlink($tarfile);
                exit;
            }
        }
        flash('Backup niet gevonden.','error'); redir('backup');
    }
    if ($act==='restore') {
        $bname = safeBackupName($_POST['backup_name'] ?? '');
        $bdir = BACKUP_DIR . '/' . $bname;
        if(is_dir($bdir)) {
            foreach(glob($bdir.'/*') as $f) {
                $bn=basename($f);
                if($bn==='smokeping_manager.db') copy($f,DB_PATH);
                elseif($bn==='rrd_data.tar.gz') @exec("tar xzf ".escapeshellarg($f)." -C ".SMOKEPING_DATA_DIR);
                elseif($bn==='smokeping_main_config') @copy($f,SMOKEPING_MAIN_CONF);
                elseif($bn==='smokemail') @copy($f,'/etc/smokeping/smokemail');
                elseif($bn==='tmail') @copy($f,'/etc/smokeping/tmail');
                elseif($bn==='smokeping_secrets') @copy($f,'/etc/smokeping/smokeping_secrets');
                elseif($bn!=='.htaccess') copy($f,SMOKEPING_CONF_DIR.'/'.$bn);
            }
            @exec("chown -R smokeping:smokeping ".SMOKEPING_DATA_DIR);
            foreach(glob(SMOKEPING_CONF_DIR.'/*') as $f) { @chown($f, 'root'); @chgrp($f, 'www-data'); @chmod($f, 0664); }
            ensureRunDir();
            shell_exec(SMOKEPING_RESTART);
            flash("Complete backup $bname hersteld en SmokePing herstart.");
        } else flash('Backup niet gevonden.','error');
        redir('backup');
    }
    if ($act==='del_backup') {
        $bname = safeBackupName($_POST['backup_name'] ?? '');
        $bdir = BACKUP_DIR . '/' . $bname;
        if(is_dir($bdir)) { exec("rm -rf ".escapeshellarg($bdir)); flash("Backup $bname verwijderd."); }
        redir('backup');
    }
    // Config bestanden bewerken
    if ($act==='save_config_file') {
        $file=$_POST['config_file']??'';
        $allowed=array_map('basename',glob(SMOKEPING_CONF_DIR.'/*'));
        if(in_array(basename($file),$allowed)) {
            $path=SMOKEPING_CONF_DIR.'/'.basename($file);
            file_put_contents($path,$_POST['content']??'');
            ensureRunDir();
            shell_exec(SMOKEPING_RESTART);
            flash('Bestand opgeslagen en SmokePing herstart.');
        } else flash('Ongeldig bestand.','error');
        redir('config',['file'=>basename($file)]);
    }
    if ($act==='reload') { $r=writeAllConfig($db); flash($r['msg'],$r['success']?'success':'error'); redir('dash'); }
    if ($act==='restart') { $r=doRestart(); flash($r['msg'],$r['success']?'success':'error'); redir('dash'); }
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
            flash('Gegevens bijgewerkt!');
        }
        redir('settings');
    }
}
$flash=getFlash();
?>
<!DOCTYPE html>
<html lang="nl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title><?=APP_TITLE?></title>
<style>
:root{--bg:#1a1d2b;--s1:#22263a;--s2:#2a2f45;--s3:#343a54;--brd:#3d4463;--tx:#e2e5f0;--txd:#8b92b0;--ac:#5a9cf5;--ach:#7bb4ff;--ok:#3dd9a0;--err:#f87171;--warn:#fbbf24;--v6:#a78bfa;--r:10px;--sh:0 4px 16px rgba(0,0,0,.3)}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',-apple-system,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;line-height:1.5}
a{color:var(--ac);text-decoration:none}a:hover{color:var(--ach)}
.hd{background:var(--s1);border-bottom:1px solid var(--brd);padding:0 20px;height:54px;display:flex;align-items:center;justify-content:space-between;box-shadow:0 2px 8px rgba(0,0,0,.25)}
.hd h1{font-size:16px;color:var(--ac);display:flex;align-items:center;gap:6px}.hd h1::before{content:'◉';color:var(--ok);font-size:12px}
.hd .ver{font-size:10px;color:var(--txd);margin-left:4px}
.nv{display:flex;gap:4px;align-items:center;flex-wrap:wrap}
.nv a,.nv button{padding:5px 12px;border-radius:var(--r);font-size:12px;border:none;cursor:pointer;color:var(--txd);background:0;transition:.15s;font-family:inherit}
.nv a:hover,.nv button:hover{background:var(--s2);color:var(--tx)}.nv .on{background:var(--ac);color:#fff}
.ct{max-width:1040px;margin:0 auto;padding:20px}
.fl{padding:10px 14px;border-radius:var(--r);margin-bottom:16px;font-size:13px;border:1px solid}
.fl.success{background:#0d2e1c;border-color:#1a5c38;color:var(--ok)}.fl.error{background:#2e1212;border-color:#6b2020;color:var(--err)}
.cd{background:var(--s1);border:1px solid var(--brd);border-radius:var(--r);padding:20px;margin-bottom:16px;box-shadow:var(--sh)}
.cd-t{font-size:15px;font-weight:600;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--brd)}
.fg{margin-bottom:12px}.fg label{display:block;font-size:12px;color:var(--txd);margin-bottom:3px;font-weight:500}
.fr{display:grid;grid-template-columns:1fr 1fr;gap:12px}.fr3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
input[type=text],input[type=password],input[type=number],select,textarea{width:100%;padding:8px 10px;background:var(--bg);border:1px solid var(--brd);border-radius:var(--r);color:var(--tx);font-size:13px;font-family:inherit}
textarea{resize:vertical;min-height:50px;font-family:'Fira Code',monospace;font-size:12px}
input:focus,select:focus,textarea:focus{outline:0;border-color:var(--ac);box-shadow:0 0 0 2px rgba(90,156,245,.25)}
.bt{display:inline-flex;align-items:center;gap:5px;padding:7px 14px;border-radius:var(--r);font-size:12px;font-weight:500;border:none;cursor:pointer;transition:.15s;font-family:inherit}
.bp{background:var(--ac);color:#fff}.bp:hover{background:var(--ach)}
.bd{background:#b91c1c;color:#fff}.bd:hover{background:#dc2626}
.bg{background:var(--s2);color:var(--txd);border:1px solid var(--brd)}.bg:hover{background:var(--s3);color:var(--tx)}
.bs{background:#15803d;color:#fff}.bs:hover{background:#16a34a}
.bw{background:#b45309;color:#fff}.bw:hover{background:#d97706}
.bsm{padding:4px 9px;font-size:11px}
table.tb{width:100%;border-collapse:collapse}
.tb th{text-align:left;font-size:11px;font-weight:600;color:var(--txd);text-transform:uppercase;letter-spacing:.4px;padding:7px 10px;border-bottom:1px solid var(--brd)}
.tb td{padding:8px 10px;font-size:13px;border-bottom:1px solid var(--brd);vertical-align:middle}
.tb tr:hover td{background:var(--s2)}
.bge{display:inline-block;padding:2px 7px;border-radius:99px;font-size:10px;font-weight:600}
.bge-on{background:#0d2e1c;color:var(--ok)}.bge-off{background:#2e1212;color:var(--err)}
.bge-p{background:#1a2550;color:var(--ac)}.bge-v6{background:#231840;color:var(--v6)}
.bge-down{background:#4a1e03;color:var(--warn)}
.lw{min-height:100vh;display:flex;align-items:center;justify-content:center}
.lb{width:340px;background:var(--s1);border:1px solid var(--brd);border-radius:12px;padding:28px;box-shadow:var(--sh)}
.lb h2{text-align:center;font-size:18px;margin-bottom:6px;color:var(--ac)}.lb .sub{text-align:center;color:var(--txd);font-size:12px;margin-bottom:20px}
.mo{display:none;position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:100;align-items:center;justify-content:center}
.mo.on{display:flex}
.md{background:var(--s1);border:1px solid var(--brd);border-radius:12px;padding:22px;width:560px;max-width:92vw;max-height:90vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,.5)}
.md h3{margin-bottom:14px;font-size:15px}
.tb2{display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;flex-wrap:wrap;gap:6px}
.pre{background:var(--bg);border:1px solid var(--brd);border-radius:var(--r);padding:14px;font-family:'Fira Code',monospace;font-size:11px;line-height:1.6;white-space:pre-wrap;max-height:360px;overflow-y:auto;color:var(--txd)}
.sg{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:16px}
.sc{background:var(--s1);border:1px solid var(--brd);border-radius:var(--r);padding:16px;text-align:center;box-shadow:var(--sh)}
.sc .n{font-size:24px;font-weight:700;color:var(--ac)}.sc .l{font-size:11px;color:var(--txd);margin-top:3px}
.cc{background:var(--s1);border:1px solid var(--brd);border-radius:var(--r);padding:14px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;transition:.15s;box-shadow:var(--sh)}
.cc:hover{border-color:var(--ac)}.cc h3{font-size:14px;margin-bottom:2px}.cc .mt{font-size:11px;color:var(--txd)}
.ca{display:flex;gap:5px;align-items:center}
.ck{display:flex;align-items:center;gap:6px;padding:5px 0}.ck input[type=checkbox]{width:15px;height:15px;accent-color:var(--ac)}
.pg{background:var(--s2);border:1px solid var(--brd);border-radius:var(--r);padding:14px;margin-bottom:10px;box-shadow:var(--sh)}
.pg h4{margin-bottom:8px;font-size:13px;display:flex;align-items:center;gap:6px}
.pt{margin-left:24px}
.bc{font-size:12px;color:var(--txd);margin-bottom:14px}.bc a{color:var(--ac)}
.dl{font-size:11px;color:var(--txd);cursor:pointer;padding:2px 6px;background:var(--s3);border-radius:4px;border:1px solid var(--brd)}
.dl:hover{background:var(--ac);color:#fff;border-color:var(--ac)}
.down-info{font-size:11px;color:var(--warn);background:#1e1600;padding:6px 10px;border-radius:var(--r);margin-top:6px;font-family:monospace;white-space:pre-wrap;border:1px solid #4a3800}
.tsel{max-height:300px;overflow-y:auto;border:1px solid var(--brd);border-radius:var(--r);padding:10px;background:var(--bg)}
.tsel-cat{font-size:11px;font-weight:600;color:var(--txd);text-transform:uppercase;letter-spacing:.4px;margin-top:8px;margin-bottom:4px}
.tsel-cat:first-child{margin-top:0}
@media(max-width:640px){.fr,.fr3{grid-template-columns:1fr}.sg{grid-template-columns:repeat(2,1fr)}}
</style>
<script>
function copyLink(url){navigator.clipboard.writeText(window.location.origin+url);var b=event.target;b.textContent='Gekopieerd!';setTimeout(()=>b.textContent='Link',1500);}
function openM(id){document.getElementById(id).classList.add('on');}
function closeM(id){document.getElementById(id).classList.remove('on');}
function editMG(mgId,mgName,mgDisplay,mgSort,tgtIds){
    document.getElementById('mgA').value='edit_mg';
    document.getElementById('mgId').value=mgId;
    document.getElementById('mgN').value=mgName;
    document.getElementById('mgD').value=mgDisplay;
    document.getElementById('mgS').value=mgSort;
    document.getElementById('mgTitle').textContent='Grafiek Bewerken';
    document.getElementById('mgBtn').textContent='Opslaan';
    // Uncheck all, then check selected
    document.querySelectorAll('#mgTargetList input[type=checkbox]').forEach(function(cb){cb.checked=false;});
    tgtIds.forEach(function(id){var cb=document.getElementById('mgt_'+id);if(cb)cb.checked=true;});
    openM('mgM');
}
function newMG(){
    document.getElementById('mgA').value='add_mg';
    document.getElementById('mgId').value='';
    document.getElementById('mgN').value='';
    document.getElementById('mgD').value='';
    document.getElementById('mgS').value='0';
    document.getElementById('mgTitle').textContent='Nieuwe Gecombineerde Grafiek';
    document.getElementById('mgBtn').textContent='Aanmaken';
    document.querySelectorAll('#mgTargetList input[type=checkbox]').forEach(function(cb){cb.checked=false;});
    openM('mgM');
}
</script>
</head><body>

<?php if($page==='login'):?>
<div class="lw"><div class="lb">
<h2>◉ <?=APP_TITLE?></h2><p class="sub"><?=APP_VERSION?> — Log in om SmokePing te beheren</p>
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>
<form method="POST"><input type="hidden" name="action" value="login">
<div class="fg"><label>Gebruikersnaam</label><input type="text" name="username" required autofocus></div>
<div class="fg"><label>Wachtwoord</label><input type="password" name="password" required></div>
<button type="submit" class="bt bp" style="width:100%;justify-content:center;margin-top:6px">Inloggen</button>
</form></div></div>
<?php else: requireLogin();?>
<div class="hd"><h1><?=APP_TITLE?><span class="ver"><?=APP_VERSION?></span></h1>
<div class="nv">
<a href="?p=dash" class="<?=$page==='dash'?'on':''?>">Dashboard</a>
<a href="?p=overview" class="<?=$page==='overview'?'on':''?>">Overzicht</a>
<a href="?p=graphs" class="<?=$page==='graphs'?'on':''?>">Grafieken</a>
<a href="?p=probes" class="<?=$page==='probes'?'on':''?>">Probes</a>
<a href="?p=presets" class="<?=$page==='presets'?'on':''?>">Presets</a>
<a href="?p=config" class="<?=$page==='config'?'on':''?>">Config</a>
<a href="?p=backup" class="<?=$page==='backup'?'on':''?>">Backup</a>
<a href="?p=settings" class="<?=$page==='settings'?'on':''?>">Instellingen</a>
<form method="POST" style="display:inline"><input type="hidden" name="action" value="logout"><button type="submit">Uitloggen</button></form>
</div></div>
<div class="ct">
<?php if($flash):?><div class="fl <?=$flash['type']?>"><?=e($flash['msg'])?></div><?php endif;?>

<?php
// ========== DASHBOARD ==========
if($page==='dash'):
    $cats=getCats($db); $tc=count($cats);
    $tt=(int)$db->querySingle('SELECT COUNT(*) FROM targets');
    $ta=(int)$db->querySingle('SELECT COUNT(*) FROM targets WHERE enabled=1');
    $t6=(int)$db->querySingle("SELECT COUNT(*) FROM targets WHERE host_ipv6!=''");
    $probeList=getProbes($db);
?>
<div class="sg">
<div class="sc"><div class="n"><?=$tc?></div><div class="l">Categorieën</div></div>
<div class="sc"><div class="n"><?=$tt?></div><div class="l">Targets</div></div>
<div class="sc"><div class="n" style="color:var(--ok)"><?=$ta?></div><div class="l">Actief</div></div>
<div class="sc"><div class="n" style="color:var(--v6)"><?=$t6?></div><div class="l">IPv6</div></div>
</div>
<div class="tb2"><h2 style="font-size:16px">Categorieën</h2>
<div style="display:flex;gap:6px">
<form method="POST" style="display:inline"><input type="hidden" name="action" value="reload"><?=csrfField()?><button class="bt bs bsm">⟳ Rebuild & Restart</button></form>
<form method="POST" style="display:inline"><input type="hidden" name="action" value="restart"><?=csrfField()?><button class="bt bg bsm">↻ Restart SmokePing</button></form>
<a href="?p=presets" class="bt bw bsm">★ Presets</a>
<button class="bt bp bsm" onclick="openM('catM')">+ Categorie</button>
</div></div>
<?php if(empty($cats)):?><div class="cd"><p style="color:var(--txd);text-align:center;padding:20px">Nog geen categorieën.</p></div>
<?php else: foreach($cats as $cat):
    $n1=(int)$db->querySingle('SELECT COUNT(*) FROM targets WHERE category_id='.(int)$cat['id']);
    $n2=(int)$db->querySingle('SELECT COUNT(*) FROM targets WHERE category_id='.(int)$cat['id'].' AND enabled=1');
?><div class="cc"><div><h3><a href="?p=cat&id=<?=(int)$cat['id']?>"><?=e($cat['display_name'])?></a></h3>
<div class="mt"><?=e($cat['name'])?> · <span class="bge bge-p"><?=e($cat['probe'])?></span> · <?=$n2?>/<?=$n1?> actief
<?php if(!$cat['enabled']):?> · <span class="bge bge-off">Uit</span><?php endif;?></div>
</div><div class="ca">
<a href="?p=cat&id=<?=(int)$cat['id']?>" class="bt bg bsm">Bekijk →</a>
<button class="bt bg bsm" onclick='document.getElementById("ecId").value=<?=$cat['id']?>;document.getElementById("ecN").value=<?=e(json_encode($cat['name']))?>;document.getElementById("ecD").value=<?=e(json_encode($cat['display_name']))?>;document.getElementById("ecP").value=<?=e(json_encode($cat['probe']))?>;document.getElementById("ecS").value=<?=$cat['sort_order']?>;document.getElementById("ecR").value=<?=e(json_encode($cat['remark']??''))?>;document.getElementById("ecE").checked=<?=$cat['enabled']?'true':'false'?>;document.getElementById("ecER").style.display="flex";document.getElementById("ecA").value="edit_cat";document.getElementById("ecTitle").textContent="Bewerken";document.getElementById("ecBtn").textContent="Opslaan";openM("catM")'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Categorie + targets verwijderen?')"><input type="hidden" name="action" value="del_cat"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$cat['id']?>"><button class="bt bd bsm">×</button></form>
</div></div><?php endforeach;endif;?>

<div class="mo" id="catM" onclick="if(event.target===this)closeM('catM')"><div class="md">
<h3 id="ecTitle">Nieuwe Categorie</h3>
<form method="POST"><input type="hidden" name="action" id="ecA" value="add_cat"><?=csrfField()?>
<input type="hidden" name="id" id="ecId">
<div class="fr"><div class="fg"><label>Naam (intern)</label><input type="text" name="name" id="ecN" required pattern="[a-zA-Z0-9_]+"></div>
<div class="fg"><label>Weergavenaam</label><input type="text" name="display_name" id="ecD" required></div></div>
<div class="fr"><div class="fg"><label>Probe</label><select name="probe" id="ecP">
<?php foreach($probeList as $pr):?><option value="<?=e($pr['name'])?>"><?=e($pr['name'])?></option><?php endforeach;?>
</select></div><div class="fg"><label>Volgorde</label><input type="number" name="sort_order" id="ecS" value="0"></div></div>
<div class="fg"><label>Opmerking</label><input type="text" name="remark" id="ecR"></div>
<div class="fg ck" id="ecER" style="display:none"><input type="checkbox" name="enabled" id="ecE" checked><label for="ecE">Actief</label></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('catM')">Annuleren</button>
<button type="submit" class="bt bp" id="ecBtn">Toevoegen</button></div>
</form></div></div>

<?php
// ========== CATEGORY DETAIL ==========
elseif($page==='cat'):
    $cid=(int)($_GET['id']??0); $s=$db->prepare('SELECT * FROM categories WHERE id=:id');$s->bindValue(':id',$cid);$cat=$s->execute()->fetchArray(SQLITE3_ASSOC);
    if(!$cat){flash('Niet gevonden.','error');redir('dash');}
    $targets=getTargetsForCat($db,$cid); $allCats=getCats($db); $probeList=getProbes($db);
?>
<div class="bc"><a href="?p=dash">Dashboard</a> → <?=e($cat['display_name'])?></div>
<div class="tb2"><div><h2 style="font-size:16px;display:inline"><?=e($cat['display_name'])?></h2>
<span class="bge bge-p" style="margin-left:6px"><?=e($cat['probe'])?></span></div>
<button class="bt bp bsm" onclick="openM('tgtM');document.getElementById('etA').value='add_tgt';document.getElementById('etTitle').textContent='Nieuw Target';document.getElementById('etBtn').textContent='Toevoegen';document.getElementById('tgtForm').reset();document.getElementById('etCat').value=<?=$cid?>;document.getElementById('etER').style.display='none'">+ Target</button>
</div>
<?php if(empty($targets)):?><div class="cd"><p style="color:var(--txd);text-align:center;padding:20px">Geen targets.</p></div>
<?php else:?><div class="cd" style="padding:0;overflow-x:auto"><table class="tb">
<thead><tr><th>Naam</th><th>Host</th><th>IPv6</th><th>Probe</th><th>Status</th><th style="text-align:right">Acties</th></tr></thead><tbody>
<?php foreach($targets as $t):?><tr>
<td><strong><?=e($t['display_name'])?></strong><div style="font-size:10px;color:var(--txd)"><?=e($t['name'])?><?php if(!empty($t['remark'])):?> — <?=e($t['remark'])?><?php endif;?></div></td>
<td><code style="font-size:12px"><?=e($t['host'])?></code></td>
<td><?php if(!empty($t['host_ipv6'])):?><code style="font-size:10px"><?=e($t['host_ipv6'])?></code> <span class="bge bge-v6">v6</span><?php else:?>—<?php endif;?></td>
<td><?=!empty($t['probe'])?e($t['probe']):'<span style="color:var(--txd)">inherit</span>'?></td>
<td><span class="bge <?=$t['enabled']?'bge-on':'bge-off'?>"><?=$t['enabled']?'Actief':'Uit'?></span></td>
<td><div style="display:flex;gap:4px;justify-content:flex-end">
<span class="dl" onclick="copyLink('<?=deepLink($cat['name'],$t['name'])?>')">Link</span>
<button class="bt bg bsm" onclick='var d=<?=e(json_encode($t))?>;document.getElementById("etA").value="edit_tgt";document.getElementById("etTitle").textContent="Bewerken";document.getElementById("etBtn").textContent="Opslaan";document.getElementById("etId").value=d.id;document.getElementById("etCat").value=d.category_id;document.getElementById("etN").value=d.name;document.getElementById("etD").value=d.display_name;document.getElementById("etH").value=d.host;document.getElementById("etH6").value=d.host_ipv6||"";document.getElementById("etP").value=d.probe||"";document.getElementById("etM").value=d.menu_name||"";document.getElementById("etS").value=d.sort_order||0;document.getElementById("etR").value=d.remark||"";document.getElementById("etAl").value=d.alert||"";document.getElementById("etEn").checked=d.enabled==1;document.getElementById("etER").style.display="flex";openM("tgtM")'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Verwijderen?')"><input type="hidden" name="action" value="del_tgt"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$t['id']?>"><input type="hidden" name="category_id" value="<?=$cid?>"><button class="bt bd bsm">×</button></form>
</div></td></tr><?php endforeach;?></tbody></table></div><?php endif;?>

<div class="mo" id="tgtM" onclick="if(event.target===this)closeM('tgtM')"><div class="md">
<h3 id="etTitle">Nieuw Target</h3>
<form method="POST" id="tgtForm"><input type="hidden" name="action" id="etA" value="add_tgt"><?=csrfField()?>
<input type="hidden" name="id" id="etId">
<div class="fg"><label>Categorie</label><select name="category_id" id="etCat">
<?php foreach($allCats as $c):?><option value="<?=(int)$c['id']?>" <?=$c['id']==$cid?'selected':''?>><?=e($c['display_name'])?></option><?php endforeach;?></select></div>
<div class="fr"><div class="fg"><label>Naam (intern)</label><input type="text" name="name" id="etN" required pattern="[a-zA-Z0-9_]+"></div>
<div class="fg"><label>Weergavenaam</label><input type="text" name="display_name" id="etD" required></div></div>
<div class="fr"><div class="fg"><label>Host (IPv4/hostname)</label><input type="text" name="host" id="etH" required></div>
<div class="fg"><label>Host IPv6 (optioneel)</label><input type="text" name="host_ipv6" id="etH6" placeholder="bijv. 2606:4700::1111"></div></div>
<div class="fr3"><div class="fg"><label>Probe (leeg=inherit)</label><select name="probe" id="etP"><option value="">Inherit</option>
<?php foreach($probeList as $pr):?><option value="<?=e($pr['name'])?>"><?=e($pr['name'])?></option><?php endforeach;?></select></div>
<div class="fg"><label>Menu naam</label><input type="text" name="menu_name" id="etM"></div>
<div class="fg"><label>Volgorde</label><input type="number" name="sort_order" id="etS" value="0"></div></div>
<div class="fr"><div class="fg"><label>Opmerking</label><input type="text" name="remark" id="etR"></div>
<div class="fg"><label>Alert</label><input type="text" name="alert" id="etAl"></div></div>
<div class="fg ck" id="etER" style="display:none"><input type="checkbox" name="enabled" id="etEn" checked><label for="etEn">Actief</label></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('tgtM')">Annuleren</button>
<button type="submit" class="bt bp" id="etBtn">Toevoegen</button></div></form></div></div>

<?php
// ========== OVERZICHT (alle targets met status) ==========
elseif($page==='overview'):
    $allT=getAllTargets($db);
?>
<div class="tb2"><h2 style="font-size:16px">Overzicht — Alle Targets</h2>
<a href="?p=graphs" class="bt bp bsm">+ Gecombineerde Grafiek</a></div>
<div class="cd" style="padding:0;overflow-x:auto"><table class="tb">
<thead><tr><th>Categorie</th><th>Target</th><th>Host</th><th>Latency</th><th>Status</th><th>Deeplink</th></tr></thead><tbody>
<?php foreach($allT as $t):
    $st=getTargetStatus($t['cat_name'],$t['name']);
?><tr>
<td><span class="bge bge-p"><?=e($t['cat_display'])?></span></td>
<td><strong><?=e($t['display_name'])?></strong><?php if(!empty($t['host_ipv6'])):?> <span class="bge bge-v6">v6</span><?php endif;?></td>
<td><code style="font-size:11px"><?=e($t['host'])?></code></td>
<td><?php if($st['exists']&&$st['median']!==null):?><?=$st['median']?> ms<?php else:?>—<?php endif;?></td>
<td><?php if($st['exists']&&$st['loss']!==null):
    if($st['loss']>=1):?><span class="bge bge-off">Down</span>
    <?php elseif($st['loss']>0):?><span class="bge bge-down"><?=round($st['loss']*100)?>% loss</span>
    <?php else:?><span class="bge bge-on">OK</span><?php endif;
    else:?>—<?php endif;?></td>
<td><span class="dl" onclick="copyLink('<?=deepLink($t['cat_name'],$t['name'])?>')">Link</span>
<a href="<?=deepLink($t['cat_name'],$t['name'])?>" target="_blank" class="dl" style="margin-left:3px">Open</a></td>
</tr>
<?php if(!empty($st['downtime_str'])):?><tr><td colspan="6"><div class="down-info"><?=e($st['downtime_str'])?></div></td></tr><?php endif;?>
<?php endforeach;?></tbody></table></div>

<?php
// ========== GRAFIEKEN ==========
elseif($page==='graphs'):
    $mgs=getMultiGraphs($db); $allT=getAllTargets($db);
?>
<div class="tb2"><h2 style="font-size:16px">Gecombineerde Grafieken</h2>
<button class="bt bp bsm" onclick="newMG()">+ Nieuwe Grafiek</button></div>
<p style="font-size:12px;color:var(--txd);margin-bottom:14px">Combineer meerdere targets in één grafiek. IPv6 varianten worden automatisch meegenomen als het target een IPv6 adres heeft.</p>

<?php if(empty($mgs)):?><div class="cd"><p style="color:var(--txd);text-align:center;padding:20px">Nog geen gecombineerde grafieken. Klik + om er een aan te maken.</p></div>
<?php else: foreach($mgs as $mg):
    $mgTgts=getMultiGraphTargets($db,$mg['id']);
    $mgTgtIds=getMultiGraphTargetIds($db,$mg['id']);
?><div class="cc"><div>
<h3><?=e($mg['display_name'])?></h3>
<div class="mt"><?=e($mg['name'])?> · <?=count($mgTgts)?> target(s):
<?php foreach($mgTgts as $i=>$mgt):?><span class="bge bge-p" style="margin-left:2px"><?=e($mgt['display_name'])?></span><?php endforeach;?>
</div></div>
<div class="ca">
<a href="<?=SMOKEPING_CGI_URL?>?target=Gecombineerd.<?=safeName($mg['name'])?>" target="_blank" class="dl">Open ↗</a>
<button class="bt bg bsm" onclick='editMG(<?=$mg['id']?>,<?=e(json_encode($mg['name']))?>,<?=e(json_encode($mg['display_name']))?>,<?=$mg['sort_order']?>,<?=json_encode($mgTgtIds)?>)'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Grafiek verwijderen?')"><input type="hidden" name="action" value="del_mg"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$mg['id']?>"><button class="bt bd bsm">×</button></form>
</div></div>
<?php endforeach; endif;?>

<!-- Auto IPv4+IPv6 multihost grafieken -->
<?php
$autoMH=$db->query("SELECT t.display_name,c.name as cat_name,t.name as tgt_name FROM targets t JOIN categories c ON t.category_id=c.id WHERE t.host_ipv6!='' AND t.enabled=1");
$autoList=[];while($row=$autoMH->fetchArray(SQLITE3_ASSOC))$autoList[]=$row;
if(!empty($autoList)):?>
<div class="cd" style="margin-top:10px"><div class="cd-t">Automatische IPv4 vs IPv6 Grafieken</div>
<p style="font-size:12px;color:var(--txd);margin-bottom:10px">Automatisch gegenereerd voor targets met een IPv6 adres.</p>
<div style="display:flex;flex-wrap:wrap;gap:6px">
<?php foreach($autoList as $a):?>
<a href="<?=SMOKEPING_CGI_URL?>?target=MultiHost_IPv4_IPv6.<?=safeName($a['display_name'])?>_combined" target="_blank" class="dl"><?=e($a['display_name'])?> (v4+v6) ↗</a>
<?php endforeach;?></div></div><?php endif;?>

<!-- MultiGraph modal -->
<div class="mo" id="mgM" onclick="if(event.target===this)closeM('mgM')"><div class="md">
<h3 id="mgTitle">Nieuwe Gecombineerde Grafiek</h3>
<form method="POST"><input type="hidden" name="action" id="mgA" value="add_mg"><?=csrfField()?>
<input type="hidden" name="id" id="mgId">
<div class="fr"><div class="fg"><label>Naam (intern, geen spaties)</label><input type="text" name="name" id="mgN" required pattern="[a-zA-Z0-9_]+"></div>
<div class="fg"><label>Weergavenaam</label><input type="text" name="display_name" id="mgD" required></div></div>
<div class="fg"><label>Volgorde</label><input type="number" name="sort_order" id="mgS" value="0" style="width:100px"></div>
<div class="fg"><label>Selecteer targets:</label></div>
<div class="tsel" id="mgTargetList">
<?php $curCat=''; foreach($allT as $t): if($t['cat_display']!==$curCat):$curCat=$t['cat_display'];?><div class="tsel-cat"><?=e($curCat)?></div><?php endif;?>
<div class="ck"><input type="checkbox" name="target_ids[]" value="<?=(int)$t['id']?>" id="mgt_<?=(int)$t['id']?>"><label for="mgt_<?=(int)$t['id']?>" style="cursor:pointer"><?=e($t['display_name'])?> <code style="font-size:10px;color:var(--txd)"><?=e($t['host'])?></code><?php if(!empty($t['host_ipv6'])):?> <span class="bge bge-v6" style="font-size:9px">+v6</span><?php endif;?></label></div>
<?php endforeach;?></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('mgM')">Annuleren</button>
<button type="submit" class="bt bp" id="mgBtn">Aanmaken</button></div>
</form></div></div>

<?php
// ========== PROBES ==========
elseif($page==='probes'):
    $probes=getAllProbes($db);
?>
<div class="tb2"><h2 style="font-size:16px">Probes</h2>
<button class="bt bp bsm" onclick="openM('probeM');document.getElementById('epA').value='add_probe';document.getElementById('epTitle').textContent='Nieuwe Probe';document.getElementById('epBtn').textContent='Toevoegen';document.getElementById('probeForm').reset()">+ Nieuwe Probe</button>
</div>
<div class="cd" style="padding:0;overflow-x:auto"><table class="tb">
<thead><tr><th>Naam</th><th>Binary</th><th>Protocol</th><th>Step</th><th>Pings</th><th>Status</th><th style="text-align:right">Acties</th></tr></thead><tbody>
<?php foreach($probes as $pr):?><tr>
<td><strong><?=e($pr['name'])?></strong></td><td><code style="font-size:11px"><?=e($pr['binary_path'])?></code></td>
<td><?=!empty($pr['protocol'])?e($pr['protocol']):'auto'?></td><td><?=$pr['step']?>s</td><td><?=$pr['pings']?></td>
<td><span class="bge <?=$pr['enabled']?'bge-on':'bge-off'?>"><?=$pr['enabled']?'Actief':'Uit'?></span></td>
<td><div style="display:flex;gap:4px;justify-content:flex-end">
<button class="bt bg bsm" onclick='var d=<?=e(json_encode($pr))?>;document.getElementById("epA").value="edit_probe";document.getElementById("epTitle").textContent="Probe Bewerken";document.getElementById("epBtn").textContent="Opslaan";document.getElementById("epId").value=d.id;document.getElementById("epN").value=d.name;document.getElementById("epB").value=d.binary_path;document.getElementById("epPr").value=d.protocol||"";document.getElementById("epSt").value=d.step;document.getElementById("epPi").value=d.pings;document.getElementById("epX").value=d.extra_config||"";document.getElementById("epEn").checked=d.enabled==1;document.getElementById("epER").style.display="flex";openM("probeM")'>Bewerken</button>
<form method="POST" style="display:inline" onsubmit="return confirm('Probe verwijderen?')"><input type="hidden" name="action" value="del_probe"><?=csrfField()?><input type="hidden" name="id" value="<?=(int)$pr['id']?>"><button class="bt bd bsm">×</button></form>
</div></td></tr><?php endforeach;?></tbody></table></div>

<div class="cd"><div class="cd-t">Probes Config Preview</div><div class="pre"><?=e(generateProbesConfig($db))?></div></div>

<div class="mo" id="probeM" onclick="if(event.target===this)closeM('probeM')"><div class="md">
<h3 id="epTitle">Nieuwe Probe</h3>
<form method="POST" id="probeForm"><input type="hidden" name="action" id="epA" value="add_probe"><?=csrfField()?>
<input type="hidden" name="id" id="epId">
<div class="fr"><div class="fg"><label>Naam (bijv. FPing6, DNS, TCPPing)</label><input type="text" name="name" id="epN" required></div>
<div class="fg"><label>Binary pad</label><input type="text" name="binary_path" id="epB" value="/usr/bin/fping"></div></div>
<div class="fr3"><div class="fg"><label>Protocol (leeg/4/6)</label><input type="text" name="protocol" id="epPr" placeholder="leeg, 4, of 6"></div>
<div class="fg"><label>Step (sec)</label><input type="number" name="step" id="epSt" value="300"></div>
<div class="fg"><label>Pings</label><input type="number" name="pings" id="epPi" value="20"></div></div>
<div class="fg"><label>Extra config (optioneel, 1 per regel)</label><textarea name="extra_config" id="epX" rows="3" placeholder="bijv. packetsize = 56"></textarea></div>
<div class="fg ck" id="epER" style="display:none"><input type="checkbox" name="enabled" id="epEn" checked><label for="epEn">Actief</label></div>
<div style="display:flex;gap:6px;justify-content:flex-end;margin-top:12px">
<button type="button" class="bt bg" onclick="closeM('probeM')">Annuleren</button>
<button type="submit" class="bt bp" id="epBtn">Toevoegen</button></div></form></div></div>

<?php
// ========== PRESETS ==========
elseif($page==='presets'):
    $presets=getPresets();
?>
<h2 style="font-size:16px;margin-bottom:14px">★ Preset Templates</h2>
<form method="POST"><input type="hidden" name="action" value="import_preset"><?=csrfField()?>
<?php foreach($presets as $k=>$pr):?><div class="pg"><h4>
<input type="checkbox" name="presets[]" value="<?=e($k)?>" id="pr_<?=e($k)?>" onchange="var c=document.getElementById('pt_<?=e($k)?>');c.style.opacity=this.checked?1:.5;c.querySelectorAll('input').forEach(x=>{x.disabled=!this.checked;x.checked=this.checked})">
<label for="pr_<?=e($k)?>" style="cursor:pointer"><?=e($pr['label'])?></label>
<span class="bge bge-p"><?=e($pr['cat']['probe'])?></span><span style="color:var(--txd);font-size:11px;margin-left:6px">(<?=count($pr['targets'])?>)</span></h4>
<div class="pt" id="pt_<?=e($k)?>" style="opacity:.5"><?php foreach($pr['targets'] as $t):?>
<div class="ck"><input type="checkbox" name="preset_targets[]" value="<?=e($k)?>__<?=e($t['name'])?>" disabled>
<label style="cursor:pointer"><strong><?=e($t['dn'])?></strong> <code style="font-size:11px;margin-left:4px"><?=e($t['h'])?></code>
<?php if(!empty($t['h6'])):?><span class="bge bge-v6" style="margin-left:3px">IPv6</span><?php endif;?></label></div>
<?php endforeach;?></div></div><?php endforeach;?>
<div style="margin-top:14px;display:flex;gap:6px">
<button type="submit" class="bt bp">★ Importeren</button><a href="?p=dash" class="bt bg">Terug</a></div></form>

<?php
// ========== CONFIG ==========
elseif($page==='config'):
    $files=array_map('basename',glob(SMOKEPING_CONF_DIR.'/*'));sort($files);
    $selFile=$_GET['file']??($files[0]??'');
    $content=''; if($selFile&&in_array($selFile,$files)) $content=@file_get_contents(SMOKEPING_CONF_DIR.'/'.$selFile);
?>
<h2 style="font-size:16px;margin-bottom:14px">SmokePing Config Bestanden</h2>
<div class="cd"><div class="fr"><div class="fg"><label>Bestand</label><select onchange="location='?p=config&file='+this.value">
<?php foreach($files as $f):?><option value="<?=e($f)?>" <?=$f===$selFile?'selected':''?>><?=e($f)?></option><?php endforeach;?>
</select></div><div class="fg" style="display:flex;align-items:flex-end;gap:6px">
<form method="POST" style="flex:1"><input type="hidden" name="action" value="reload"><?=csrfField()?><button class="bt bs bsm">⟳ Rebuild & Restart</button></form>
<form method="POST" style="flex:0"><input type="hidden" name="action" value="restart"><?=csrfField()?><button class="bt bg bsm">↻ Restart</button></form>
</div></div></div>
<?php if($selFile):?>
<div class="cd"><div class="cd-t"><?=e($selFile)?></div>
<form method="POST"><input type="hidden" name="action" value="save_config_file"><?=csrfField()?>
<input type="hidden" name="config_file" value="<?=e($selFile)?>">
<textarea name="content" rows="20" style="width:100%;min-height:300px"><?=e($content)?></textarea>
<div style="margin-top:10px;display:flex;gap:6px"><button type="submit" class="bt bp">Opslaan & Restart</button></div></form></div>
<?php endif;?>
<div class="cd"><div class="cd-t">SmokePing Status</div><div class="pre"><?=e(shell_exec(SMOKEPING_STATUS)?:'Niet beschikbaar')?></div></div>

<?php
// ========== BACKUP ==========
elseif($page==='backup'):
    $backups=[]; foreach(glob(BACKUP_DIR.'/backup_*') as $d) if(is_dir($d)) $backups[]=basename($d); rsort($backups);
?>
<h2 style="font-size:16px;margin-bottom:14px">Backup & Restore</h2>
<div class="cd"><form method="POST"><input type="hidden" name="action" value="backup"><?=csrfField()?>
<button type="submit" class="bt bp">📦 Nieuwe Complete Backup</button>
<span style="font-size:12px;color:var(--txd);margin-left:10px">Bevat: alle config bestanden (Targets, Probes, Alerts, Database, General, Presentation, Slaves, pathnames), hoofdconfig, smokemail, tmail, secrets, manager database en RRD meetdata</span></form></div>
<?php if(!empty($backups)):?><div class="cd"><div class="cd-t">Beschikbare Backups</div>
<table class="tb"><thead><tr><th>Naam</th><th>Inhoud</th><th style="text-align:right">Acties</th></tr></thead><tbody>
<?php foreach($backups as $b):
    $bfiles = array_map('basename', glob(BACKUP_DIR.'/'.$b.'/*'));
    $fcount = count($bfiles);
?>
<tr><td><strong><?=e($b)?></strong></td>
<td><span style="font-size:11px;color:var(--txd)"><?=$fcount?> bestand(en): <?=e(implode(', ', array_slice($bfiles, 0, 6)))?><?=$fcount>6?'...':''?></span></td>
<td style="text-align:right;white-space:nowrap">
<form method="POST" style="display:inline"><input type="hidden" name="action" value="download_backup"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button class="bt bg bsm">⬇ Download</button></form>
<form method="POST" style="display:inline;margin-left:4px" onsubmit="return confirm('Complete backup terugzetten? Dit overschrijft ALLE huidige configuratie!')"><input type="hidden" name="action" value="restore"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button class="bt bs bsm">⮌ Terugzetten</button></form>
<form method="POST" style="display:inline;margin-left:4px" onsubmit="return confirm('Backup verwijderen?')"><input type="hidden" name="action" value="del_backup"><?=csrfField()?><input type="hidden" name="backup_name" value="<?=e($b)?>"><button class="bt bd bsm">×</button></form>
</td></tr><?php endforeach;?></tbody></table></div><?php endif;?>

<?php
// ========== INSTELLINGEN ==========
elseif($page==='settings'):
?>
<h2 style="font-size:16px;margin-bottom:14px">Instellingen</h2>
<div class="cd"><div class="cd-t">Gebruiker & Wachtwoord</div>
<form method="POST" style="max-width:380px"><input type="hidden" name="action" value="chpw"><?=csrfField()?>
<div class="fg"><label>Nieuwe gebruikersnaam (leeg = behouden)</label><input type="text" name="newuser" value="<?=e($_SESSION['uname']??'')?>"></div>
<div class="fg"><label>Huidig wachtwoord</label><input type="password" name="cur" required></div>
<div class="fg"><label>Nieuw wachtwoord (leeg = behouden)</label><input type="password" name="new" minlength="6"></div>
<div class="fg"><label>Bevestig nieuw wachtwoord</label><input type="password" name="con" minlength="6"></div>
<button type="submit" class="bt bp">Opslaan</button></form></div>
<div class="cd"><div class="cd-t">Systeem</div>
<table style="width:100%;font-size:13px">
<tr><td style="color:var(--txd);padding:5px 0;width:180px">Targets</td><td><code><?=SMOKEPING_TARGETS_FILE?></code></td></tr>
<tr><td style="color:var(--txd);padding:5px 0">Probes</td><td><code><?=SMOKEPING_PROBES_FILE?></code></td></tr>
<tr><td style="color:var(--txd);padding:5px 0">Database</td><td><code><?=DB_PATH?></code></td></tr>
<tr><td style="color:var(--txd);padding:5px 0">RRD Data</td><td><code><?=SMOKEPING_DATA_DIR?></code></td></tr>
<tr><td style="color:var(--txd);padding:5px 0">PHP</td><td><?=phpversion()?></td></tr>
<tr><td style="color:var(--txd);padding:5px 0">SmokePing CGI</td><td><code><?=SMOKEPING_CGI_URL?></code></td></tr>
</table></div>
<?php endif;?>
</div><?php endif;?></body></html>
ENDOFPHP
}

# ============================================================
# MAIN MENU LOOP
# ============================================================
while true; do
    show_menu
    case "$choice" in
        1) do_install "fresh"; read -rp "Druk op Enter..." ;;
        2) do_install "keep"; read -rp "Druk op Enter..." ;;
        3) do_uninstall; read -rp "Druk op Enter..." ;;
        4) do_clear_targets; read -rp "Druk op Enter..." ;;
        5) do_backup; read -rp "Druk op Enter..." ;;
        6) do_restore; read -rp "Druk op Enter..." ;;
        7) do_change_creds; read -rp "Druk op Enter..." ;;
        0) echo "Tot ziens!"; exit 0 ;;
        *) echo "Ongeldige keuze." ; sleep 1 ;;
    esac
done
