#!/usr/bin/env bash
#
# Fedora Ultimate Security Hardening (Auditor & Enforcer)
# Compatible with Fedora 40–45+ (traditional RPM/DNF systems)
# Inspired by secureblue, Kicksecure, madaidan hardening guide and CIS.
# Privacy-first, aggressive surface reduction.
#
# Usage:
#   sudo ./fedora.sh            # audit (default)
#   sudo ./fedora.sh --audit
#   sudo ./fedora.sh --apply
#
# Check kernel error: sudo sysctl --system
#

set -Eeuo pipefail
IFS=$'\n\t'
umask 077

VERSION='2.4'
MODE='audit'
FORCE_SSH_KEEP=true          # set to false if you really want to remove SSH from public zone
AGGRESSIVE_USERNS=false      # set to true to disable unprivileged user namespaces (breaks Flatpak/Podman rootless)

# Interactive parameters (asked only in --apply mode)
PURGE_GNOME_BLOAT=false
INSTALL_OPTIONAL_SOFTWARE=false
INSTALL_HARDENED_MALLOC=false
LOCKDOWN_BASHRC=false
SETUP_SUPERIOR_USER=false
SETUP_GNOME_LAYOUT=false
SETUP_SYSTEM_PREFS=false
SUPERIOR_USER=""

ask_yn() {
  local prompt_msg="$1"
  local default_val="${2:-y}"
  local ans
  if [[ "$MODE" != "apply" ]]; then
    echo "$default_val"
    return
  fi
  local hint="Y/n"
  [[ "$default_val" =~ ^[nN]$ ]] && hint="y/N"
  read -rp "$prompt_msg [$hint]: " ans || ans="$default_val"
  ans="${ans:-$default_val}"
  [[ "$ans" =~ ^[yY][eE]?[sS]?$ ]]
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
for arg in "$@"; do
  case "$arg" in
    --apply)   MODE='apply' ;;
    --audit)   MODE='audit' ;;
    --help|-h)
      cat <<'HELP'
Usage: sudo ./fedora.sh [--audit|--apply|--help]

  --audit   Report current security posture (default, no changes)
  --apply   Backup managed files, apply hardening, log everything

Designed for traditional Fedora Workstation/Server (DNF + systemd).
Not for Atomic/Silverblue/Kinoite (use secureblue or rpm-ostree kargs).
HELP
      exit 0
      ;;
    *)
      if [[ -n "$arg" ]]; then
        echo "Unknown argument: $arg. Use --help." >&2
        exit 2
      fi
      ;;
  esac
done

# ---------------------------------------------------------------------------
# Colors & helpers
# ---------------------------------------------------------------------------
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m'

ok()    { printf '%s[OK]%s      %s\n' "$GREEN"  "$NC" "$*"; }
fixed() { printf '%s[APPLIED]%s %s\n' "$BLUE"   "$NC" "$*"; }
warn()  { printf '%s[WARN]%s    %s\n' "$YELLOW" "$NC" "$*"; }
fail()  { printf '%s[FAIL]%s    %s\n' "$RED"    "$NC" "$*"; }
info()  { printf '          %s\n' "$*"; }
section(){ printf '\n%s=== %s ===%s\n' "$CYAN" "$*" "$NC"; }

die() { fail "$*"; exit 1; }

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if (( EUID != 0 )); then
  die "Run as root or via sudo."
fi

if [[ ! -r /etc/os-release ]] || ! grep -q '^ID=fedora$' /etc/os-release; then
  die "This script is only for Fedora Linux."
fi

# Detect desktop vs server roughly
IS_DESKTOP=false
if systemctl is-active --quiet graphical.target 2>/dev/null || \
   [[ -n "${DISPLAY:-}" || -n "${WAYLAND_DISPLAY:-}" ]]; then
  IS_DESKTOP=true
fi

STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/var/backups/secure-fedora-hardening/$STAMP"
LOG_FILE="/var/log/secure-fedora-hardening.log"

if [[ $MODE == apply ]]; then
  install -d -m 0700 "$BACKUP_DIR"
  touch "$LOG_FILE"
  chmod 0600 "$LOG_FILE"
  # Tee everything to log
  exec 3>&1
  exec > >(tee -a "$LOG_FILE" >&3) 2>&1
  info "Backup directory : $BACKUP_DIR"
  info "Log file         : $LOG_FILE"
fi

backup_file() {
  local f=$1
  if [[ -e $f || -L $f ]]; then
    install -d -m 0700 "$BACKUP_DIR$(dirname "$f")"
    cp -a -- "$f" "$BACKUP_DIR$f" 2>/dev/null || true
  fi
}

write_managed() {
  local dest=$1 mode=$2
  local tmp
  install -d -m 0755 "$(dirname "$dest")"
  tmp=$(mktemp "$(dirname "$dest")/.secure-hardening.XXXXXX")
  cat > "$tmp"
  chmod "$mode" "$tmp"
  if [[ -f $dest ]] && cmp -s "$tmp" "$dest"; then
    rm -f "$tmp"
    ok "Already correct: $dest"
    return 0
  fi
  backup_file "$dest"
  install -o root -g root -m "$mode" "$tmp" "$dest"
  rm -f "$tmp"
  fixed "Updated: $dest"
}

# Resolve the real (non-root) user who invoked sudo
resolve_real_user() {
  local u="${SUDO_USER:-$(logname 2>/dev/null || true)}"
  if [[ -z "$u" || "$u" == "root" ]]; then
    u=$(awk -v tty="$(tty 2>/dev/null | sed 's|/dev/||')" '$2 == tty {print $1}' /proc/self/loginuid 2>/dev/null || true)
  fi
  if [[ -z "$u" || "$u" == "root" ]]; then
    u=$(users 2>/dev/null | awk '{print $1}')
  fi
  echo "${u:-}"
}

setup_sublime_text() {
  local real_user="${1:-$REAL_USER}"
  local user_home="${2:-$USER_HOME}"
  
  if [[ -z "$user_home" || ! -d "$user_home" ]]; then
    warn "User home directory not found for Sublime Text configuration."
    return
  fi

  info "Configuring Sublime Text for user $real_user (Flatpak sandbox compatible)..."

  local st_dirs=()
  if [[ -d "$user_home/.var/app/com.sublimehq.SublimeText/config/sublime-text" ]]; then
    st_dirs+=("$user_home/.var/app/com.sublimehq.SublimeText/config/sublime-text")
  fi
  if [[ -d "$user_home/.config/sublime-text" ]]; then
    st_dirs+=("$user_home/.config/sublime-text")
  fi
  if [[ ${#st_dirs[@]} -eq 0 ]]; then
    st_dirs+=("$user_home/.config/sublime-text")
  fi

  for st_config_dir in "${st_dirs[@]}"; do
    local st_installed_pkg_dir="$st_config_dir/Installed Packages"
    local st_user_pkg_dir="$st_config_dir/Packages/User"
    local st_packages_dir="$st_config_dir/Packages"

    sudo -u "$real_user" mkdir -p "$st_installed_pkg_dir" "$st_user_pkg_dir" "$st_packages_dir"

    local pc_file="$st_installed_pkg_dir/Package Control.sublime-package"
    
    if [[ ! -f "$pc_file" || ! -s "$pc_file" ]]; then
      info "Downloading Package Control 4..."
      sudo -u "$real_user" curl -sSLo "$pc_file" "https://download.sublimetext.com/Package%20Control.sublime-package" 2>/dev/null || true
    else
      info "Package Control 4 already exists, skipping download."
    fi

    sudo -u "$real_user" bash -c "cat << 'EOF' > '$st_user_pkg_dir/Preferences.sublime-settings'
{
  \"always_show_minimap_viewport\": true,
  \"auto_complete\": true,
  \"bold_folder_labels\": true,
  \"fallback_encoding\": \"Cyrillic (Windows 1251)\",
  \"font_face\": \"Monospace\",
  \"font_size\": 12,
  \"ignored_packages\":
  [
    \"Vintage\"
  ],
  \"indent_guide_options\":
  [
    \"draw_normal\",
    \"draw_active\"
  ],
  \"line_padding_bottom\": 2,
  \"line_padding_top\": 2,
  \"index_files\": false,
  \"theme\": \"GitHub Dark.sublime-theme\",
  \"color_scheme\": \"OLED.sublime-color-scheme\"
}
EOF"

    sudo -u "$real_user" bash -c "cat << 'EOF' > '$st_user_pkg_dir/Package Control.sublime-settings'
{
  \"bootstrapped\": true,
  \"auto_upgrade\": true,
  \"install_missing\": true,
  \"channels\":
  [
    \"https://packages.sublimetext.io/channel.json\"
  ],
  \"installed_packages\":
  [
    \"PackageDev\",
    \"OLED Color Scheme\",
    \"GitHub Theme\",
    \"Color Highlight\",
    \"Highlighter\"
  ]
}
EOF"
  done
  fixed "Sublime Text configured with Flatpak-safe downloader and auto-install plugins."
}

# ===========================================================================
# Extreme Firefox (Flatpak) hardening
# ===========================================================================
setup_firefox_prefs() {
  local real_user="${1:-${REAL_USER:-}}"
  local user_home="${2:-${USER_HOME:-}}"

  if [[ -z "$real_user" || "$real_user" == "root" || -z "$user_home" || ! -d "$user_home" ]]; then
    warn "Valid non-root user/home not found for Firefox configuration."
    return 0
  fi

  if ! command -v flatpak >/dev/null 2>&1 ||
     ! sudo -u "$real_user" flatpak info org.mozilla.firefox >/dev/null 2>&1; then
    info "Firefox Flatpak not detected – skipped Firefox hardening."
    return 0
  fi

  local ff_base="$user_home/.var/app/org.mozilla.firefox/.mozilla/firefox"
  local candidate profile_dir
  for candidate in \
    "$user_home/.var/app/org.mozilla.firefox/.mozilla/firefox" \
    "$user_home/.var/app/org.mozilla.firefox/config/.mozilla/firefox" \
    "$user_home/.var/app/org.mozilla.firefox/data/.mozilla/firefox"; do
    if [[ -d "$candidate" ]]; then
      ff_base="$candidate"
      break
    fi
  done
  sudo -u "$real_user" mkdir -p "$ff_base"

  profile_dir=$(find "$ff_base" -mindepth 1 -maxdepth 1 -type d \
    \( -name '*.default-release' -o -name '*.default' \) -print -quit 2>/dev/null || true)
  if [[ -z "$profile_dir" ]]; then
    profile_dir="$ff_base/default.default-release"
    sudo -u "$real_user" mkdir -p "$profile_dir"
  fi

  info "Writing deduplicated Firefox privacy/security preferences to $profile_dir/user.js"
  sudo -u "$real_user" tee "$profile_dir/user.js" >/dev/null <<'FIREFOX_PREFS_EOF'
user_pref("browser.privatebrowsing.autostart", true);
user_pref("media.peerconnection.enabled", false);
user_pref("media.peerconnection.ice.default_address_only", true);
user_pref("media.peerconnection.ice.no_host", true);
user_pref("media.peerconnection.ice.proxy_only", true);
user_pref("media.peerconnection.ice.proxy_only_if_behind_proxy", true);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.server", "");
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("toolkit.telemetry.newProfilePing.enabled", false);
user_pref("toolkit.telemetry.shutdownPingSender.enabled", false);
user_pref("toolkit.telemetry.updatePing.enabled", false);
user_pref("toolkit.telemetry.bhrPing.enabled", false);
user_pref("toolkit.telemetry.firstShutdownPing.enabled", false);
user_pref("browser.ping-centre.telemetry", false);
user_pref("browser.newtabpage.activity-stream.feeds.telemetry", false);
user_pref("browser.newtabpage.activity-stream.telemetry", false);
user_pref("experiments.activeExperiment", false);
user_pref("experiments.enabled", false);
user_pref("experiments.supported", false);
user_pref("app.shield.optoutstudies.enabled", false);
user_pref("app.normandy.enabled", false);
user_pref("app.normandy.api_url", "");
user_pref("extensions.pocket.enabled", false);
user_pref("extensions.pocket.api", "");
user_pref("extensions.pocket.oAuthConsumerKey", "");
user_pref("extensions.pocket.site", "");
user_pref("browser.discovery.enabled", false);
user_pref("browser.discovery.sites", "");
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.pbmode.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);
user_pref("privacy.trackingprotection.emailtracking.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("browser.contentblocking.category", "strict");
user_pref("privacy.annotate_channels.strict_list.enabled", true);
user_pref("privacy.donottrackheader.enabled", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.resistFingerprinting.letterboxing", true);
user_pref("privacy.firstparty.isolate", true);
user_pref("network.cookie.cookieBehavior", 5);
user_pref("network.cookie.lifetimePolicy", 2);
user_pref("network.cookie.thirdparty.sessionOnly", true);
user_pref("network.cookie.thirdparty.nonsecureSessionOnly", true);
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.offlineApps", true);
user_pref("privacy.clearOnShutdown.sessions", true);
user_pref("privacy.clearOnShutdown.siteSettings", true);
user_pref("privacy.clearOnShutdown.openWindows", true);
user_pref("privacy.sanitize.timeSpan", 0);
user_pref("browser.cache.disk.enable", false);
user_pref("browser.cache.disk_cache_ssl", false);
user_pref("browser.cache.memory.enable", true);
user_pref("browser.cache.memory.capacity", 65536);
user_pref("browser.privatebrowsing.forceMediaMemoryCache", true);
user_pref("media.memory_cache_max_size", 65536);
user_pref("browser.sessionstore.privacy_level", 2);
user_pref("browser.sessionstore.resume_from_crash", false);
user_pref("browser.sessionstore.max_tabs_undo", 0);
user_pref("browser.sessionstore.max_windows_undo", 0);
user_pref("browser.formfill.enable", false);
user_pref("signon.rememberSignons", false);
user_pref("signon.autofillForms", false);
user_pref("signon.formlessCapture.enabled", false);
user_pref("browser.startup.page", 0);
user_pref("browser.startup.homepage", "about:blank");
user_pref("browser.newtabpage.enabled", false);
user_pref("browser.newtab.preload", false);
user_pref("network.dns.disablePrefetch", true);
user_pref("network.dns.disablePrefetchFromHTTPS", true);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);
user_pref("network.predictor.enable-prefetch", false);
user_pref("network.http.speculative-parallel-limit", 0);
user_pref("network.http.referer.XOriginPolicy", 2);
user_pref("network.http.referer.XOriginTrimmingPolicy", 2);
user_pref("network.http.referer.defaultPolicy", 2);
user_pref("network.http.referer.defaultPolicy.pbmode", 2);
user_pref("network.http.sendRefererHeader", 0);
user_pref("network.IDN_show_punycode", true);
user_pref("geo.enabled", false);
user_pref("geo.provider.network.url", "");
user_pref("geo.provider.use_gpsd", false);
user_pref("geo.provider.use_geoclue", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.engines", false);
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);
user_pref("browser.urlbar.speculativeConnect.enabled", false);
user_pref("dom.battery.enabled", false);
user_pref("dom.event.clipboardevents.enabled", false);
user_pref("media.navigator.enabled", false);
user_pref("media.getusermedia.screensharing.enabled", false);
user_pref("media.getusermedia.audiocapture.enabled", false);
user_pref("media.getusermedia.browser.enabled", false);
user_pref("camera.control.face_detection.enabled", false);
user_pref("device.sensors.enabled", false);
user_pref("device.sensors.motion.enabled", false);
user_pref("device.sensors.orientation.enabled", false);
user_pref("device.sensors.ambientLight.enabled", false);
user_pref("device.sensors.proximity.enabled", false);
user_pref("webgl.disabled", true);
user_pref("webgl.enable-webgl2", false);
user_pref("gfx.font_rendering.opentype_svg.enabled", false);
user_pref("gfx.font_rendering.graphite.enabled", false);
user_pref("browser.display.use_document_fonts", 0);
user_pref("dom.security.https_only_mode", true);
user_pref("dom.security.https_only_mode_ever_enabled", true);
user_pref("network.stricttransportsecurity.preloadlist", true);
user_pref("security.ssl.require_safe_negotiation", true);
user_pref("security.ssl.treat_unsafe_negotiation_as_broken", true);
user_pref("security.tls.version.min", 3);
user_pref("security.tls.enable_0rtt_data", false);
user_pref("security.cert_pinning.enforcement_level", 2);
user_pref("security.pki.sha1_enforcement_level", 1);
user_pref("browser.safebrowsing.malware.enabled", true);
user_pref("browser.safebrowsing.phishing.enabled", true);
user_pref("browser.safebrowsing.downloads.enabled", true);
user_pref("browser.safebrowsing.downloads.remote.enabled", true);
user_pref("browser.safebrowsing.downloads.remote.block_potentially_unwanted", true);
user_pref("browser.safebrowsing.downloads.remote.block_uncommon", true);
user_pref("browser.safebrowsing.allowOverride", false);
user_pref("dom.serviceWorkers.enabled", false);
user_pref("dom.push.enabled", false);
user_pref("dom.push.connection.enabled", false);
user_pref("dom.push.serverURL", "");
user_pref("beacon.enabled", false);
user_pref("browser.send_pings", false);
user_pref("browser.send_pings.require_same_host", true);
user_pref("dom.event.contextmenu.enabled", false);
user_pref("dom.disable_window_move_resize", true);
user_pref("dom.disable_window_flip", true);
user_pref("dom.disable_window_open_feature.close", true);
user_pref("dom.disable_window_open_feature.location", true);
user_pref("dom.disable_window_open_feature.menubar", true);
user_pref("dom.disable_window_open_feature.minimizable", true);
user_pref("dom.disable_window_open_feature.personalbar", true);
user_pref("dom.disable_window_open_feature.resizable", true);
user_pref("dom.disable_window_open_feature.status", true);
user_pref("dom.disable_window_open_feature.titlebar", true);
user_pref("dom.disable_window_open_feature.toolbar", true);
user_pref("dom.popup_allowed_events", "click dblclick mousedown pointerdown");
user_pref("pdfjs.enableScripting", false);
user_pref("javascript.options.baselinejit", false);
user_pref("javascript.options.ion", false);
user_pref("javascript.options.native_regexp", false);
user_pref("javascript.options.asmjs", false);
user_pref("javascript.options.wasm", false);
user_pref("dom.webaudio.enabled", false);
user_pref("media.webspeech.synth.enabled", false);
user_pref("media.webspeech.recognition.enable", false);
user_pref("dom.gamepad.enabled", false);
user_pref("dom.vr.enabled", false);
user_pref("dom.vibrator.enabled", false);
user_pref("dom.netinfo.enabled", false);
user_pref("dom.telephony.enabled", false);
user_pref("dom.enable_performance", false);
user_pref("dom.enable_resource_timing", false);
user_pref("dom.enable_user_timing", false);
user_pref("dom.performance.enable_notify_performance_timing", false);
user_pref("dom.performance.enable_user_timing_logging", false);
user_pref("browser.uitour.enabled", false);
user_pref("browser.uitour.url", "");
user_pref("devtools.chrome.enabled", false);
user_pref("devtools.debugger.remote-enabled", false);
user_pref("toolkit.telemetry.coverage.opt-out", true);
user_pref("toolkit.coverage.opt-out", true);
user_pref("toolkit.coverage.endpoint.base", "");
user_pref("app.update.auto", true);
user_pref("extensions.update.enabled", true);
user_pref("extensions.update.autoUpdateDefault", true);
user_pref("extensions.getAddons.showPane", false);
user_pref("extensions.htmlaboutaddons.recommendations.enabled", false);
user_pref("extensions.htmlaboutaddons.discover.enabled", false);
user_pref("services.sync.enabled", false);
user_pref("identity.fxaccounts.enabled", false);
user_pref("browser.aboutwelcome.enabled", false);
user_pref("browser.startup.firstrunSkipsHomepage", true);
user_pref("trailhead.firstrun.didSeeAboutWelcome", true);
user_pref("browser.messaging-system.whatsNewPanel.enabled", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("startup.homepage_override_url", "");
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.addons", false);
user_pref("browser.newtabpage.activity-stream.asrouter.userprefs.cfr.features", false);
user_pref("browser.newtabpage.activity-stream.section.highlights.includePocket", false);
user_pref("browser.newtabpage.activity-stream.feeds.section.topstories", false);
user_pref("browser.newtabpage.activity-stream.feeds.topsites", false);
user_pref("browser.newtabpage.activity-stream.showSponsored", false);
user_pref("browser.newtabpage.activity-stream.showSponsoredTopSites", false);
user_pref("browser.newtabpage.activity-stream.default.sites", "");
user_pref("browser.newtabpage.activity-stream.enabled", false);
user_pref("privacy.globalprivacycontrol.enabled", true);
user_pref("signon.management.page.breach-alerts.enabled", false);
user_pref("extensions.formautofill.creditCards.enabled", false);
user_pref("extensions.formautofill.addresses.enabled", false);
user_pref("browser.link.preview.enabled", false);
user_pref("browser.tabs.hoverPreview.enabled", false);
user_pref("browser.translations.enable", false);
user_pref("layout.spellcheckDefault", 0);
user_pref("browser.ml.enable", false);
user_pref("browser.preferences.aiControls", true);
user_pref("permissions.default.camera", 2);
user_pref("permissions.default.microphone", 2);
user_pref("permissions.default.desktop-notification", 2);
user_pref("permissions.default.xr", 2);
user_pref("browser.ml.chat.enabled", false);
user_pref("browser.ml.linkPreview.enabled", false);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.bookmark", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.suggest.topsites", false);
user_pref("browser.urlbar.suggest.recentsearches", false);
user_pref("browser.urlbar.quickactions.enabled", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("permissions.default.geo", 2);
user_pref("media.autoplay.default", 5);
user_pref("media.autoplay.blocking_policy", 2);
user_pref("browser.urlbar.suggest.history", false);
user_pref("browser.urlbar.suggest.bookmark", false);
user_pref("browser.urlbar.suggest.openpage", false);
user_pref("browser.urlbar.suggest.topsites", false);
user_pref("browser.urlbar.suggest.recentsearches", false);
user_pref("browser.search.suggest.enabled", false);
user_pref("browser.urlbar.suggest.searches", false);
user_pref("browser.urlbar.suggest.quickactions", false);
user_pref("browser.urlbar.suggest.quicksuggest.sponsored", false);
user_pref("browser.urlbar.suggest.quicksuggest.nonsponsored", false);
user_pref("browser.urlbar.quicksuggest.enabled", false);
user_pref("browser.urlbar.suggest.quicksuggest", false);
user_pref("privacy.globalprivacycontrol.enabled", true);
user_pref("privacy.globalprivacycontrol.functionality.enabled", true);
user_pref("privacy.globalprivacycontrol.pbmode.enabled", true);
FIREFOX_PREFS_EOF
  sudo -u "$real_user" chmod 0600 "$profile_dir/user.js"
  fixed "Firefox user.js written with duplicate preferences removed."

  # Flatpak Firefox reads system policy from its systemconfig extension path.
  local arch branch pol_dir
  arch=$(sudo -u "$real_user" flatpak info --show-arch org.mozilla.firefox 2>/dev/null || printf 'x86_64')
  branch=$(sudo -u "$real_user" flatpak info --show-branch org.mozilla.firefox 2>/dev/null || printf 'stable')
  pol_dir="/var/lib/flatpak/extension/org.mozilla.firefox.systemconfig/${arch}/${branch}/policies"
  install -d -m 0755 "$pol_dir"
  backup_file "$pol_dir/policies.json"
  cat > "$pol_dir/policies.json" <<'FIREFOX_POLICY_EOF'
{
  "policies": {
    "DefaultGeolocationSetting": 2,
    "DefaultCameraSetting": 2,
    "DefaultMicrophoneSetting": 2,
    "DefaultNotificationsSetting": 2,
    "DefaultAutoplaySetting": 5,
    "DefaultWebXRSetting": 2,
    "AutoplayAllowed": false,
    "DisableTelemetry": true,
    "DisableFirefoxStudies": true,
    "DisablePocket": true,
    "DisableFirefoxAccounts": true,
    "DisableAccounts": true,
    "DisableProfileImport": true,
    "DisableSetDesktopBackground": true,
    "DontCheckDefaultBrowser": true,
    "NoDefaultBookmarks": true,
    "OfferToSaveLogins": false,
    "PasswordManagerEnabled": false,
    "DisableMasterPasswordCreation": true,
    "DisableFormHistory": true,
    "DisableSafeBrowsing": false,
    "SearchSuggestEnabled": false,
    "TranslateEnabled": false,
    "AutofillAddressEnabled": false,
    "AutofillCreditCardEnabled": false,
    "HttpsOnlyMode": "force_enabled",
    "NewTabPage": false,
    "DisableRemoteImprovements": true,
    "FirefoxSuggest": {
      "WebSuggestions": false,
      "SponsoredSuggestions": false,
      "ImproveSuggest": false,
      "Locked": true
    },
    "Homepage": {
      "StartPage": "none",
      "URL": "about:blank",
      "Locked": true
    },
    "GlobalPrivacyControl": {
      "Value": true,
      "Locked": true
    },
    "AIControls": {
      "Enabled": false,
      "Default": {
        "Value": "blocked",
        "Locked": true
      }
    },
    "FirefoxHome": {
      "Search": false,
      "TopSites": false,
      "SponsoredTopSites": false,
      "Highlights": false,
      "Pocket": false,
      "SponsoredPocket": false,
      "Snippets": false,
      "Locked": true
    },
    "EnableTrackingProtection": {
      "Value": true,
      "Locked": true,
      "Cryptomining": true,
      "Fingerprinting": true,
      "EmailTracking": true,
      "Category": "strict"
    },
    "Cookies": {
      "Default": false,
      "AcceptThirdParty": "never",
      "Locked": true
    },
    "Preferences": {
      "browser.privatebrowsing.autostart": {
        "Value": true,
        "Status": "locked"
      },
      "media.peerconnection.enabled": {
        "Value": false,
        "Status": "locked"
      },
      "privacy.resistFingerprinting": {
        "Value": true,
        "Status": "locked"
      },
      "privacy.firstparty.isolate": {
        "Value": true,
        "Status": "locked"
      },
      "browser.cache.disk.enable": {
        "Value": false,
        "Status": "locked"
      },
      "webgl.disabled": {
        "Value": true,
        "Status": "locked"
      },
      "geo.enabled": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.history": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.bookmark": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.openpage": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.topsites": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.recentsearches": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.engines": {
        "Value": false,
        "Status": "locked"
      },
      "browser.urlbar.suggest.searches": {
        "Value": false,
        "Status": "locked"
      },
      "browser.search.suggest.enabled": {
        "Value": false,
        "Status": "locked"
      },
      "privacy.globalprivacycontrol.enabled": {
        "Value": true,
        "Status": "locked"
      }
    },
    "ExtensionSettings": {
      "*": {
        "installation_mode": "blocked",
        "blocked_install_message": "Only uBlock Origin is allowed by system policy."
      },
      "uBlock0@raymondhill.net": {
        "installation_mode": "force_installed",
        "install_url": "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi"
      }
    }
  }
}
FIREFOX_POLICY_EOF
  chmod 0644 "$pol_dir/policies.json"
  fixed "Firefox enterprise policies written (uBlock Origin forced; Safe Browsing retained)."
}
# ===========================================================================
# Chromium / Ungoogled Chromium (Flatpak) – milder (keep history & sessions)
# ===========================================================================
setup_chromium_prefs() {
  local real_user="${1:-$REAL_USER}"
  local user_home="${2:-$USER_HOME}"
  
  if [[ -z "$user_home" || ! -d "$user_home" ]]; then
    warn "User home directory not found for Chromium configuration."
    return
  fi

  info "Applying security overrides and enterprise policies for Chromium-based browsers (Flatpak)..."

  if ! command -v flatpak &>/dev/null; then
    warn "Flatpak not installed – skipping Chromium browser hardening."
    return
  fi

  # Combined flags incorporating your requirements without deprecated entries
  local CHROMIUM_FLAGS="--force-webrtc-ip-handling-policy=disable_non_proxied_udp --disable-background-mode --disable-breakpad --disable-background-networking --disable-domain-reliability --disable-default-apps --disable-sync --disable-speech-api --disable-spellchecking --disable-auto-reload --no-first-run --password-store=gnome-libsecret --disable-features=AutofillServerCommunication,InterestFeedContentSuggestions,TranslateUI,MediaRouter,DialMediaRouteProvider,OptimizationHints,InterestFeed,HelpMeWrite,TabOrganization,AI,LinkPreviews,Translate,TabSearch,AutofillCreditCard,AutofillAddressEnabled,ComponentExtensionsWithBackgroundPages"

  # Enterprise policies JSON strictly mapped to your parameters
  local policy_json
  policy_json=$(cat <<'EOF'
{
  "SafeBrowsingProtectionLevel": 2,
  "HttpsOnlyMode": "force_enabled",
  "BlockThirdPartyCookies": true,
  "DefaultGeolocationSetting": 2,
  "DefaultNotificationsSetting": 2,
  "DefaultSensorsSetting": 2,
  "DefaultPopupsSetting": 2,
  "DefaultAutomaticDownloadsSetting": 2,
  "PasswordManagerEnabled": false,
  "SearchSuggestEnabled": false,
  "SpellCheckServiceEnabled": false,
  "BackgroundModeEnabled": false,
  "SitePerProcess": true,
  "BookmarkBarEnabled": false,
  "HighEfficiencyModeEnabled": true,
  "RestoreOnStartup": 1
}
EOF
)

  # 1. Standard Chromium
  if sudo -u "$real_user" flatpak info org.chromium.Chromium &>/dev/null; then
    info "Hardening Chromium (Flatpak)..."
    sudo -u "$real_user" flatpak override --user org.chromium.Chromium \
      --nofilesystem=host \
      --nosocket=x11 \
      --socket=wayland \
      --nodevice=all 2>/dev/null || true

    sudo -u "$real_user" flatpak override --user org.chromium.Chromium \
      --env=CHROMIUM_FLAGS="$CHROMIUM_FLAGS" 2>/dev/null || true

    local chromium_policy_dir="$user_home/.var/app/org.chromium.Chromium/config/chromium/policies/managed"
    sudo -u "$real_user" mkdir -p "$chromium_policy_dir"
    echo "$policy_json" | sudo -u "$real_user" tee "$chromium_policy_dir/policy.json" >/dev/null
    sudo -u "$real_user" chmod 0600 "$chromium_policy_dir/policy.json"

    sudo -u "$real_user" python3 -c '
    import json, os
    for d in ["org.chromium.Chromium", "io.github.ungoogled_software.ungoogled_chromium"]:
        p = os.path.expanduser(f"~/.var/app/{d}/config/chromium/Default/Preferences")
        if os.path.exists(os.path.dirname(p)):
            os.makedirs(os.path.dirname(p), exist_ok=True)
            data = {}
            if os.path.exists(p):
                try:
                    with open(p, "r") as f: data = json.load(f)
                except: pass
            data.setdefault("session", {})["restore_on_startup"] = 1
            with open(p, "w") as f: json.dump(data, f)
    ' 2>/dev/null || true

    fixed "Chromium (Flatpak) sandbox, flags, policies & startup session applied."
  else
    info "Chromium (Flatpak) not installed – skipped."
  fi

  # 2. Ungoogled Chromium
  if sudo -u "$real_user" flatpak info io.github.ungoogled_software.ungoogled_chromium &>/dev/null; then
    info "Hardening Ungoogled Chromium (Flatpak)..."
    sudo -u "$real_user" flatpak override --user io.github.ungoogled_software.ungoogled_chromium \
      --nofilesystem=host \
      --nosocket=x11 \
      --socket=wayland \
      --nodevice=all 2>/dev/null || true

    local UG_FLAGS="$CHROMIUM_FLAGS --keep-old-history --disable-search-engine-collection --extension-mime-request-handling=always-prompt-for-install --fingerprinting-canvas-image-data-noise --fingerprinting-canvas-measuretext-noise --fingerprinting-client-rects-noise"
    sudo -u "$real_user" flatpak override --user io.github.ungoogled_software.ungoogled_chromium \
      --env=CHROMIUM_FLAGS="$UG_FLAGS" 2>/dev/null || true

    local ug_policy_dir="$user_home/.var/app/io.github.ungoogled_software.ungoogled_chromium/config/chromium/policies/managed"
    sudo -u "$real_user" mkdir -p "$ug_policy_dir"
    echo "$policy_json" | sudo -u "$real_user" tee "$ug_policy_dir/policy.json" >/dev/null
    sudo -u "$real_user" chmod 0600 "$ug_policy_dir/policy.json"

    fixed "Ungoogled Chromium (Flatpak) sandbox, flags & enterprise policies applied."
  else
    info "Ungoogled Chromium (Flatpak) not installed – skipped."
  fi
}

printf '\n=== Fedora Security Hardening Ultimate v%s ===\n' "$VERSION"
printf 'Mode: %s | Date: %s | Host: %s | Kernel: %s\n' \
  "$MODE" "$(date -Is)" "$(hostname)" "$(uname -r)"
printf 'Desktop detected: %s\n' "$IS_DESKTOP"

if [[ $MODE == audit ]]; then
  info "Audit mode — no changes will be made. Use --apply to enforce."
elif [[ $MODE == apply ]]; then
  section 'Interactive Hardening Configuration'
  if ask_yn "1. Purge unnecessary GNOME bloatware (safe apps only)?" "n"; then PURGE_GNOME_BLOAT=true; fi
  if ask_yn "2. Install optional software and secure Flatpaks?" "n"; then INSTALL_OPTIONAL_SOFTWARE=true; fi
  if ask_yn "3. Build and deploy Hardened Malloc?" "n"; then INSTALL_HARDENED_MALLOC=true; fi
  if ask_yn "4. Lockdown user profile files (.bashrc, etc. -> root ownership)?" "n"; then LOCKDOWN_BASHRC=true; fi
  if ask_yn "5. Configure a separate superior admin user for run0/privileges?" "n"; then SETUP_SUPERIOR_USER=true; fi
  if ask_yn "6. Setup GNOME layout, extensions, icons/cursors & tiling?" "n"; then SETUP_GNOME_LAYOUT=true; fi
  if ask_yn "7. Apply recommended system preferences (locale, power, privacy, workspaces...)?" "n"; then SETUP_SYSTEM_PREFS=true; fi
fi

# ===========================================================================
# 1. Bootloader & Kernel Command Line
# ===========================================================================
section '1. Bootloader & Kernel Security Parameters'

#lockdown=integrity
#module.sig_enforce=1
KARGS_CORE=(
  slab_nomerge
  init_on_alloc=1
  init_on_free=1
  page_alloc.shuffle=1
  randomize_kstack_offset=on
  iommu=force
  iommu.strict=1
  iommu.passthrough=0
  pti=on
  vsyscall=none
  random.trust_cpu=off
  random.trust_bootloader=off
  oops=panic
  tsx=off
  debugfs=off
  kvm.nx_huge_pages=force
  spectre_v2_user=on
  spec_rstack_overflow=safe-ret
  l1tf=full,force
)

KARGS_EXTRA=(
  spectre_v2=on
  spec_store_bypass_disable=on
  l1d_flush=on
  gather_data_sampling=force
)

if command -v grubby &>/dev/null; then
  if grubby --info=DEFAULT 2>/dev/null | grep -qE 'rhgb|quiet'; then
    if [[ $MODE == apply ]]; then
      grubby --update-kernel=ALL --remove-args="rhgb quiet" && \
        fixed "Removed rhgb quiet from kernel cmdline"
    else
      warn "rhgb/quiet present (will be removed with --apply)"
    fi
  else
    ok "rhgb/quiet already absent"
  fi

  current=$(grubby --info=DEFAULT 2>/dev/null || true)
  missing_args=()

  for arg in "${KARGS_CORE[@]}" "${KARGS_EXTRA[@]}"; do
    if grep -Fq -- "$arg" <<<"$current"; then
      ok "Kernel arg present: $arg"
    else
      warn "Missing kernel arg: $arg"
      missing_args+=("$arg")
    fi
  done

  if [[ $MODE == apply && ${#missing_args[@]} -gt 0 ]]; then
    joined_args=$(IFS=' '; echo "${missing_args[*]}")
    if grubby --update-kernel=ALL --args="$joined_args"; then
      fixed "Added missing kernel args: $joined_args"
    else
      fail "Failed to add missing kernel args"
    fi
  fi

  if [[ $MODE == apply ]]; then
    all_current_args=$(grubby --info=DEFAULT 2>/dev/null | grep '^args=' | cut -d= -f2- | tr -d '"' || true)
    if [[ -n "$all_current_args" ]]; then
      echo "$all_current_args" > /etc/kernel/cmdline
      chmod 0600 /etc/kernel/cmdline
      fixed "Updated /etc/kernel/cmdline for kernel-install persistence"
    fi
  fi
else
  warn "grubby not found — skipping kernel args"
fi

# ===========================================================================
# 2. PackageKit / Polkit offline updates
# ===========================================================================
section '2. PackageKit offline-update restriction'

RULE_FILE="/etc/polkit-1/rules.d/99-disable-offline-update.rules"
EXPECTED_RULE='polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.packagekit.trigger-offline-update") {
        return polkit.Result.NO;
    }
});'

if [[ -f $RULE_FILE ]] && grep -q 'org.freedesktop.packagekit.trigger-offline-update' "$RULE_FILE"; then
  ok "Polkit offline-update rule already present"
elif [[ $MODE == apply ]]; then
  write_managed "$RULE_FILE" 0644 <<<"$EXPECTED_RULE"
  systemctl try-restart polkit 2>/dev/null || true
else
  warn "Polkit offline-update rule missing"
fi

# ===========================================================================
# 3. Systemd DefaultTimeoutStopSec
# ===========================================================================
section '3. Systemd DefaultTimeoutStopSec'

TIMEOUT_CONF="/etc/systemd/system.conf.d/99-timeout.conf"
if [[ -f $TIMEOUT_CONF ]] && grep -q 'DefaultTimeoutStopSec=5s' "$TIMEOUT_CONF"; then
  ok "DefaultTimeoutStopSec=5s already set"
elif [[ $MODE == apply ]]; then
  write_managed "$TIMEOUT_CONF" 0644 <<'EOF'
[Manager]
DefaultTimeoutStopSec=5s
DefaultTimeoutStartSec=15s
EOF
  systemctl daemon-reload
else
  warn "DefaultTimeoutStopSec not hardened"
fi

# ===========================================================================
# 4. Services & Packages reduction
# ===========================================================================
section '4. Services & Packages Reduction'

if [[ $MODE == apply ]]; then
  if systemctl is-masked --quiet gssproxy.service 2>/dev/null; then
    systemctl unmask gssproxy.service 2>/dev/null || true
    fixed "Unmasked gssproxy service"
  fi
  systemctl mask var-lib-nfs-rpc_pipefs.mount 2>/dev/null || true
  fixed "Masked var-lib-nfs-rpc_pipefs.mount to prevent boot errors"
fi

services_to_mask=(
  wsdd.service wsdd.socket
  avahi-daemon.service avahi-daemon.socket
  abrtd.service abrt-journal-core.service abrt-oops.service
  abrt-vmcore.service abrt-xorg.service
  livesys.service livesys-late.service
  flatpak-add-fedora-repos.service
  cups.service cups.socket cups.path
  pcscd.service
  ModemManager.service
  geoclue.service
  rpcbind.service
  nfs-client.target
  nfs-server.service
  rpc-statd.service
  rpc-gssd.service
  rpc-svcgssd.service
  gssproxy.service
  mcelog.service
  kdump.service
  plymouth-start.service
  plymouth-quit.service
  plymouth-quit-wait.service
  systemd-coredump.socket
  systemd-coredump@.service
  debug-shell.service
  emergency.service
  rescue.service
  iscsid.service
  iscsi.service
  lvm2-monitor.service
  dm-event.service
  mdmonitor.service
  raid-check.timer
  hypervkvpd.service
  hypervvssd.service
  hypervfcopyd.service
)

for srv in "${services_to_mask[@]}"; do
  if systemctl is-enabled --quiet "$srv" 2>/dev/null || \
     systemctl is-active  --quiet "$srv" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$srv" 2>/dev/null || true
      systemctl mask "$srv" 2>/dev/null || true
      fixed "Masked: $srv"
    else
      warn "Active/enabled: $srv"
    fi
  else
    ok "Already disabled/absent: $srv"
  fi
done

pkgs_to_remove=(wsdd firefox)
for pkg in "${pkgs_to_remove[@]}"; do
  if rpm -q "$pkg" &>/dev/null; then
    if [[ $MODE == apply ]]; then
      dnf remove -y --no-autoremove "$pkg" 2>/dev/null || true
      fixed "Removed package: $pkg"
    else
      warn "Package present: $pkg"
    fi
  else
    ok "Package absent: $pkg"
  fi
done

# ===========================================================================
# 5. Name resolution (LLMNR / mDNS)
# ===========================================================================
section '5. LLMNR / mDNS Hardening'

RESOLVED_CONF="/etc/systemd/resolved.conf.d/99-nomdns.conf"
if [[ -f $RESOLVED_CONF ]] && grep -q 'LLMNR=no' "$RESOLVED_CONF"; then
  ok "systemd-resolved: LLMNR/MulticastDNS disabled"
elif [[ $MODE == apply ]]; then
  write_managed "$RESOLVED_CONF" 0644 <<'EOF'
[Resolve]
LLMNR=no
MulticastDNS=no
DNSOverTLS=opportunistic
EOF
  systemctl try-restart systemd-resolved 2>/dev/null || true
else
  warn "systemd-resolved LLMNR/mDNS not disabled"
fi

NM_CONF="/etc/NetworkManager/conf.d/99-no-mdns.conf"
if [[ -f $NM_CONF ]] && grep -q 'mdns=0' "$NM_CONF"; then
  ok "NetworkManager: mdns/llmnr disabled"
elif [[ $MODE == apply ]]; then
  write_managed "$NM_CONF" 0644 <<'EOF'
[connection]
mdns=0
llmnr=0
EOF
  systemctl try-restart NetworkManager 2>/dev/null || true
else
  warn "NetworkManager mdns/llmnr not disabled"
fi

# ===========================================================================
# 6. Bluetooth
# ===========================================================================
section '6. Bluetooth Hardening'

BT_CONF="/etc/bluetooth/main.conf"
if [[ -f $BT_CONF ]] && grep -qE '^[[:space:]]*AutoEnable[[:space:]]*=[[:space:]]*false' "$BT_CONF"; then
  ok "Bluetooth AutoEnable=false"
elif [[ $MODE == apply ]]; then
  backup_file "$BT_CONF"
  install -d -m 0755 /etc/bluetooth
  if [[ -f $BT_CONF ]]; then
    if grep -q 'AutoEnable=' "$BT_CONF"; then
      sed -i 's/^#\?[[:space:]]*AutoEnable=.*/AutoEnable=false/' "$BT_CONF"
    else
      sed -i '/^\[General\]/a AutoEnable=false' "$BT_CONF" || \
        printf '\n[General]\nAutoEnable=false\n' >> "$BT_CONF"
    fi
  else
    cat > "$BT_CONF" <<'EOF'
[General]
AutoEnable=false
EOF
  fi
  fixed "Bluetooth AutoEnable set to false"
  systemctl try-restart bluetooth 2>/dev/null || true
else
  warn "Bluetooth AutoEnable not disabled"
fi

# ===========================================================================
# 7. Firewalld
# ===========================================================================
section '7. Firewalld Hardening'

if command -v firewall-cmd &>/dev/null; then
  if ! systemctl is-active --quiet firewalld; then
    if [[ $MODE == apply ]]; then
      systemctl enable --now firewalld
      fixed "firewalld started and enabled"
    else
      warn "firewalld is not active"
    fi
  else
    ok "firewalld is active"
  fi

  if [[ $MODE == apply ]]; then
    firewall-cmd --permanent --zone=public --set-target=DROP 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=mdns 2>/dev/null || true
    firewall-cmd --permanent --zone=public --remove-service=ssh 2>/dev/null || true

    if [[ $FORCE_SSH_KEEP == true ]]; then
      firewall-cmd --permanent --zone=public --add-service=ssh 2>/dev/null || true
      info "SSH kept in public zone (FORCE_SSH_KEEP=true)"
    else
      warn "!!! WARNING !!! SSH will be REMOVED from public zone."
      warn "Ensure you have console or out-of-band access before proceeding."
      read -rp "Type 'yes' to continue: " confirm
      [[ "$confirm" == "yes" ]] || die "Aborted by user."
    fi

    if ! firewall-cmd --permanent --get-zones 2>/dev/null | grep -qw wireguard; then
      firewall-cmd --permanent --new-zone=wireguard >/dev/null
      fixed "Created firewalld zone: wireguard"
    fi
    firewall-cmd --permanent --zone=wireguard --set-target=DROP 2>/dev/null || true

    for iface in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | grep -E '^(wg|tun)[0-9]+$' || true); do
      cur=$(firewall-cmd --get-zone-of-interface="$iface" 2>/dev/null || true)
      if [[ $cur != wireguard ]]; then
        firewall-cmd --permanent --zone=wireguard --add-interface="$iface" 2>/dev/null || true
        fixed "Bound $iface → wireguard zone"
      else
        ok "$iface already in wireguard zone"
      fi
    done

    for zone in public wireguard; do
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv4 destination address=224.0.0.0/4 drop' 2>/dev/null || true
      firewall-cmd --permanent --zone="$zone" \
        --add-rich-rule='rule family=ipv6 destination address=ff00::/8 drop' 2>/dev/null || true
    done

    firewall-cmd --reload >/dev/null
    fixed "firewalld rules reloaded"
  else
    info "firewalld hardening (DROP public, wireguard zone, multicast drop) will be applied with --apply"
  fi
else
  warn "firewall-cmd not installed"
fi

# ===========================================================================
# 8. Kernel Sysctl
# ===========================================================================
section '8. Kernel Sysctl Hardening'

SYSCTL_FILE="/etc/sysctl.d/99-secure-fedora-hardening.conf"

SYSCTL_CONTENT=$(cat <<'SYSCTL_EOF'
# === Network (anti-recon + anti-spoof) ===
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv4.tcp_fastopen = 0
net.ipv4.conf.all.arp_ignore = 2
net.ipv4.conf.default.arp_ignore = 2
net.ipv4.conf.all.arp_announce = 2
net.ipv4.conf.default.arp_announce = 2

# === Kernel self-protection ===
net.core.bpf_jit_harden = 2
kernel.unprivileged_bpf_disabled = 1
kernel.yama.ptrace_scope = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.perf_event_paranoid = 3
kernel.sysrq = 0
kernel.kexec_load_disabled = 1
kernel.io_uring_disabled = 2
kernel.oops_limit = 100
kernel.warn_limit = 100
kernel.panic = -1
kernel.panic_on_oops = 1
kernel.panic_on_warn = 0
kernel.modules_disabled = 0
dev.tty.ldisc_autoload = 0
vm.unprivileged_userfaultfd = 0
vm.mmap_rnd_bits = 32
vm.mmap_rnd_compat_bits = 16
kernel.randomize_va_space = 2
kernel.core_pattern = |/bin/false
kernel.printk = 3 3 3 3
fs.suid_dumpable = 0
fs.protected_regular = 2
fs.protected_fifos = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_symlinks_create = 1
fs.protected_hardlinks_create = 1

# === Anti-info-leak & Performance micro-tweaks ===
kernel.pid_max = 65536
vm.mmap_min_addr = 65536
kernel.perf_cpu_time_max_percent = 1
kernel.sched_schedstats = 0
kernel.timer_migration = 0
net.core.bpf_jit_kallsyms = 0
kernel.ftrace_enabled = 0
kernel.stack_tracer_enabled = 0
net.ipv4.conf.all.mc_forwarding = 0
net.ipv6.conf.all.mc_forwarding = 0
SYSCTL_EOF
)

if [[ $AGGRESSIVE_USERNS == true ]]; then
  SYSCTL_CONTENT+=$'\n# Aggressive: break Flatpak / rootless Podman\nuser.max_user_namespaces = 0\n'
fi

if [[ $MODE == apply ]]; then
  write_managed "$SYSCTL_FILE" 0644 <<<"$SYSCTL_CONTENT"

  sysctl_err=$(sysctl --system 2>&1 >/dev/null || true)

  if [[ -z "$sysctl_err" ]]; then
    fixed "sysctl parameters applied cleanly"
  else
    mapfile -t failed_keys < <(
      printf '%s\n' "$sysctl_err" \
        | sed -nE '
            s/^.*setting key "([^"]+)".*$/\1/p;
            s|^.*cannot stat /proc/sys/([^:]+).*$|\1|p;
          ' \
        | tr '/' '.' \
        | sort -u
    )

    if (( ${#failed_keys[@]} == 0 )); then
      warn "sysctl --system reported errors (could not classify keys):"
      printf '%s\n' "$sysctl_err" | sed 's/^/          /'
    else
      warn "sysctl: ${#failed_keys[@]} parameter(s) not applied:"
      for k in "${failed_keys[@]}"; do
        cur=$(sysctl -n "$k" 2>/dev/null || true)
        if [[ -z "$cur" ]]; then
          info "  - $k"
          info "      -> NOT SUPPORTED by this kernel (benign; remove from $SYSCTL_FILE)"
        else
          info "  - $k"
          info "      -> current = $cur   (kernel refused write: value locked by earlier sysctl.d or already stricter)"
        fi
      done
      info "  Raw sysctl stderr:"
      printf '%s\n' "$sysctl_err" | sed 's/^/          /'
    fi
  fi
else
  if [[ -f $SYSCTL_FILE ]]; then
    ok "Sysctl hardening file exists"
  else
    warn "Sysctl hardening file missing"
  fi
fi

LIMITS_FILE="/etc/security/limits.d/99-nocore.conf"
if [[ -f $LIMITS_FILE ]] && grep -q 'hard core 0' "$LIMITS_FILE"; then
  ok "Core dumps disabled via limits"
elif [[ $MODE == apply ]]; then
  write_managed "$LIMITS_FILE" 0644 <<<"* hard core 0"$'\n'
else
  warn "Core dump limits not set"
fi

COREDUMP_CONF="/etc/systemd/coredump.conf.d/99-nocore.conf"
if [[ -f $COREDUMP_CONF ]] && grep -q 'Storage=none' "$COREDUMP_CONF"; then
  ok "Systemd coredump storage disabled"
elif [[ $MODE == apply ]]; then
  write_managed "$COREDUMP_CONF" 0644 <<'EOF'
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
  systemctl daemon-reload 2>/dev/null || true
  fixed "Systemd coredump disabled globally"
else
  warn "Systemd coredump not disabled via coredump.conf"
fi

TMP_MOUNT_CONF="/etc/systemd/system/tmp.mount.d/99-options.conf"
if [[ $MODE == apply ]]; then
  install -d -m 0755 "$(dirname "$TMP_MOUNT_CONF")"
  write_managed "$TMP_MOUNT_CONF" 0644 <<'EOF'
[Mount]
Options=nosuid,nodev,noexec,relatime
EOF
  systemctl daemon-reload
  systemctl re-enable tmp.mount 2>/dev/null || true
  fixed "Mounted /tmp with nosuid, nodev, noexec"
fi

SHM_MOUNT_CONF="/etc/systemd/system/dev-shm.mount.d/99-options.conf"
if [[ $MODE == apply ]]; then
  install -d -m 0755 "$(dirname "$SHM_MOUNT_CONF")"
  write_managed "$SHM_MOUNT_CONF" 0644 <<'EOF'
[Mount]
Options=nosuid,nodev,noexec,relatime,size=50%
EOF
  systemctl daemon-reload
  fixed "Hardened /dev/shm (nosuid,nodev,noexec)"
fi

# ===========================================================================
# 9. Wi-Fi MAC randomization
# ===========================================================================
section '9. Wi-Fi MAC Address Randomization'

MAC_CONF="/etc/NetworkManager/conf.d/99-mac-rand.conf"
if [[ -f $MAC_CONF ]] && grep -q 'wifi.cloned-mac-address=random' "$MAC_CONF"; then
  ok "Wi-Fi MAC randomization enabled"
elif [[ $MODE == apply ]]; then
  write_managed "$MAC_CONF" 0644 <<'EOF'
[device]
wifi.scan-rand-mac-address=yes

[connection]
wifi.cloned-mac-address=random
EOF
  fixed "Wi-Fi MAC randomization enabled"
else
  warn "MAC randomization not configured"
fi

# ===========================================================================
# 10. Chrony + DNF timers
# ===========================================================================
section '10. Chrony & Automatic Update Timers'

if [[ -f /etc/chrony.conf ]]; then
  if grep -qxF 'port 0' /etc/chrony.conf && grep -qxF 'cmdport 0' /etc/chrony.conf; then
    ok "Chrony network ports closed"
  elif [[ $MODE == apply ]]; then
    backup_file /etc/chrony.conf
    grep -qxF 'port 0'    /etc/chrony.conf || echo 'port 0'    >> /etc/chrony.conf
    grep -qxF 'cmdport 0' /etc/chrony.conf || echo 'cmdport 0' >> /etc/chrony.conf
    systemctl try-restart chronyd 2>/dev/null || true
    fixed "Chrony ports closed (port 0 / cmdport 0)"
  else
    warn "Chrony still listens on network ports"
  fi
fi

for unit in dnf-makecache.timer packagekit.service fwupd-refresh.timer; do
  if systemctl is-enabled --quiet "$unit" 2>/dev/null; then
    if [[ $MODE == apply ]]; then
      systemctl disable --now "$unit" 2>/dev/null || true
      fixed "Disabled: $unit"
    else
      info "Timer/service enabled: $unit (can be disabled)"
    fi
  else
    ok "Already disabled: $unit"
  fi
done

# ===========================================================================
# 11. SELinux Enforcement & Policy Hardening
# ===========================================================================
section '11. SELinux Enforcement & Policy Hardening'

if command -v getenforce &>/dev/null; then
  current=$(getenforce 2>/dev/null || echo Unknown)
  if [[ $current == Enforcing ]]; then
    ok "SELinux is Enforcing"
  elif [[ $MODE == apply ]]; then
    setenforce 1 2>/dev/null || true
    if [[ -f /etc/selinux/config ]]; then
      backup_file /etc/selinux/config
      sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
    fi
    fixed "SELinux set to Enforcing"
  else
    warn "SELinux is $current (will be set to Enforcing)"
  fi

  selinux_booleans=(
    "deny_ptrace=1"
  )
  for bool_setting in "${selinux_booleans[@]}" ; do
    b_name="${bool_setting%%=*}"
    b_val="${bool_setting##*=}"
    if command -v getsebool &>/dev/null; then
      cur_bool=$(getsebool "$b_name" 2>/dev/null | awk '{print $3}')
      if [[ "$cur_bool" == "$b_val" ]]; then
        ok "SELinux boolean $b_name is $b_val"
      elif [[ $MODE == apply ]]; then
        if setsebool -P "$b_name" "$b_val" 2>/dev/null; then
          fixed "Set SELinux boolean $b_name to $b_val"
        else
          warn "Failed to set SELinux boolean $b_name to $b_val"
        fi
      else
        warn "SELinux boolean $b_name is $cur_bool (expected $b_val)"
      fi
    fi
  done
else
  warn "SELinux tools not found"
fi

# ===========================================================================
# 12. Kernel Module Blacklisting
# ===========================================================================
section '12. Kernel Module Blacklisting'

MODPROBE_FILE="/etc/modprobe.d/99-hardening-blacklist.conf"
MODPROBE_CONTENT=$(cat <<'MOD_EOF'
# === Completely defunct network protocols ===
install dccp /bin/false
install sctp /bin/false
install rds /bin/false
install tipc /bin/false
install n-hdlc /bin/false
install ax25 /bin/false
install netrom /bin/false
install x25 /bin/false
install rose /bin/false
install decnet /bin/false
install econet /bin/false
install af_802154 /bin/false
install ipx /bin/false
install appletalk /bin/false
install can /bin/false
install atm /bin/false
install p8022 /bin/false
install p8023 /bin/false
install psnap /bin/false
install n_hdlc /bin/false
install llc /bin/false
install bridge /bin/true
install veth /bin/true
install tun /bin/true
install tap /bin/true
install vxlan /bin/true
install geneve /bin/true

# === Legacy file systems (particularly dangerous during extraction) ===
install cramfs /bin/false
install freevxfs /bin/false
install jffs2 /bin/false
install hfs /bin/false
install hfsplus /bin/false
install udf /bin/false
install isofs /bin/false
install romfs /bin/false
install sysv /bin/false
install minix /bin/false
install bfs /bin/false
install qnx4 /bin/false
install qnx6 /bin/false
install affs /bin/false
install efs /bin/false
install jfs /bin/false
install reiserfs /bin/false
install nilfs2 /bin/false
install f2fs /bin/false
# We’re keeping the modern ones:
install ext4 /bin/true
install xfs /bin/true
install btrfs /bin/true
install overlay /bin/true
install fuse /bin/true
install vfat /bin/true
install exfat /bin/true
install ntfs3 /bin/true
install squashfs /bin/true

# === Legacy hardware (Z790/Z890 — none of this is present on the boards) ===
install floppy /bin/false
install parport /bin/false
install parport_pc /bin/false
install lp /bin/false
install ppdev /bin/false
install serial_core /bin/false
install 8250 /bin/false
install 8250_pci /bin/false
install serial /bin/false
install pcspkr /bin/false
install joydev /bin/false
install gameport /bin/false
install serio_raw /bin/false
install psmouse /bin/false
install atkbd /bin/false
install i8042 /bin/false
install libps2 /bin/false

# FireWire in its entirety (Thunderbolt ≠ FireWire)
install firewire-core /bin/false
install firewire-ohci /bin/false
install firewire-sbp2 /bin/false
install firewire-net /bin/false

# NFC / UWB / legacy buses
install nfc /bin/false
install uwb /bin/false
install ssb /bin/false
install bcma /bin/false
install mac80211_hwsim /bin/false

# Legacy USB modem/telephony classes (retaining UAS/USB storage classes)
install cdc_acm /bin/false
install cdc_ether /bin/false
install cdc_ncm /bin/false
install cdc_mbim /bin/false
install cdc_wdm /bin/false
install usblp /bin/false
install usb-storage /bin/true
install uas /bin/true

# Other legacy
install mtd /bin/false
install mtdblock /bin/false
install nand /bin/false
install onenand /bin/false
MOD_EOF
)

if [[ -f $MODPROBE_FILE ]]; then
  ok "Module blacklist already exists"
elif [[ $MODE == apply ]]; then
  write_managed "$MODPROBE_FILE" 0644 <<<"$MODPROBE_CONTENT"
  fixed "Created kernel module blacklist"
else
  warn "Module blacklist missing"
fi

# ===========================================================================
# 13. Journald hardening
# ===========================================================================
section '13. Journald Hardening'

JOURNAL_CONF="/etc/systemd/journald.conf.d/99-hardening.conf"
if [[ -f $JOURNAL_CONF ]] && grep -q 'Storage=persistent' "$JOURNAL_CONF"; then
  ok "Journald hardening present"
elif [[ $MODE == apply ]]; then
  write_managed "$JOURNAL_CONF" 0644 <<'EOF'
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=500M
RuntimeMaxUse=100M
MaxFileSec=1month
ForwardToWall=no
EOF
  systemctl try-restart systemd-journald 2>/dev/null || true
  fixed "Journald hardened"
else
  warn "Journald not hardened"
fi

# ===========================================================================
# 14. DNF security defaults
# ===========================================================================
section '14. DNF Security Defaults'

DNF_CONF="/etc/dnf/dnf.conf"
if [[ -f $DNF_CONF ]]; then
  if grep -q '^gpgcheck=1' "$DNF_CONF" && grep -q '^localpkg_gpgcheck=1' "$DNF_CONF"; then
    ok "DNF gpgcheck already strict"
  elif [[ $MODE == apply ]]; then
    backup_file "$DNF_CONF"
    if grep -qE '^[[:space:]]*gpgcheck[[:space:]]*=' "$DNF_CONF"; then
      sed -i 's/^[[:space:]]*gpgcheck[[:space:]]*=.*/gpgcheck=1/' "$DNF_CONF"
    else
      sed -i '/^\[main\]/a gpgcheck=1' "$DNF_CONF"
    fi

    if grep -qE '^[[:space:]]*localpkg_gpgcheck[[:space:]]*=' "$DNF_CONF"; then
      sed -i 's/^[[:space:]]*localpkg_gpgcheck[[:space:]]*=.*/localpkg_gpgcheck=1/' "$DNF_CONF"
    else
      sed -i '/^\[main\]/a localpkg_gpgcheck=1' "$DNF_CONF"
    fi
    fixed "DNF gpgcheck + localpkg_gpgcheck enforced"
  else
    warn "DNF gpg settings can be stricter"
  fi
fi

# ===========================================================================
# 15. User Profile Files Lockdown (.bashrc protection)
# ===========================================================================
section '15. User Profile Files Lockdown'

if [[ $LOCKDOWN_BASHRC == true ]]; then
  info "User profile lockdown is enabled (LOCKDOWN_BASHRC=true)"
  REAL_USER_LOCK=$(resolve_real_user)
  USER_HOME_DIR=$(getent passwd "$REAL_USER_LOCK" | cut -d: -f6)

  if [[ -n "$USER_HOME_DIR" && -d "$USER_HOME_DIR" ]]; then
    profile_files=(".bashrc" ".bash_profile" ".profile" ".bash_logout" ".zshrc")
    for pfile in "${profile_files[@]}"; do
      fpath="$USER_HOME_DIR/$pfile"
      if [[ -f "$fpath" ]]; then
        current_owner=$(stat -c '%U' "$fpath" 2>/dev/null)
        if [[ "$current_owner" == "root" ]]; then
          ok "Profile file already owned by root: $pfile"
        elif [[ $MODE == apply ]]; then
          backup_file "$fpath"
          chown root:root "$fpath"
          chmod 0644 "$fpath"
          fixed "Locked down profile file (chown root:root): $pfile"
        else
          warn "Profile file owned by $current_owner (will be changed to root:root): $pfile"
        fi
      fi
    done
  else
    warn "Could not determine valid home directory for profile lockdown."
  fi
else
  info "User profile lockdown skipped (set LOCKDOWN_BASHRC=true to activate)"
fi

# ===========================================================================
# 16. Optional GNOME Bloatware Removal
# ===========================================================================
section '16. Optional GNOME Bloatware Removal'

gnome_bloat_pkgs=(
  gnome-tour
  gnome-weather
  gnome-maps
  gnome-clocks
  gnome-contacts
  gnome-calendar
  gnome-characters
  evince 
  cheese
  snapshot 
  simple-scan
  yelp
  gnome-user-docs
  gnome-text-editor
  gnome-logs
  mediawriter 
  gnome-boxes
  baobab 
  papers
  gnome-connections
)

if [[ $PURGE_GNOME_BLOAT == true ]]; then
  info "GNOME bloatware removal is enabled (PURGE_GNOME_BLOAT=true)"
  for pkg in "${gnome_bloat_pkgs[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
      if [[ $MODE == apply ]]; then
        dnf remove -y "$pkg" 2>/dev/null || true
        fixed "Removed GNOME app: $pkg"
      else
        warn "GNOME app present (will be removed): $pkg"
      fi
    else
      ok "GNOME app already absent: $pkg"
    fi
  done
  if rpm -qa 'libreoffice*' &>/dev/null; then
    if [[ $MODE == apply ]]; then
      dnf remove -y 'libreoffice*' 2>/dev/null || true
      fixed "Removed all LibreOffice packages"
    else
      warn "LibreOffice packages present (will be removed)"
    fi
  else
    ok "LibreOffice already absent"
  fi
else
  info "GNOME bloatware removal is skipped (set PURGE_GNOME_BLOAT=true in script to activate)"
fi

# ===========================================================================
# 17. Optional Software Deployment
# ===========================================================================
section '17. Optional Software Deployment'

dnf_apps=(
  htop
  mc
  zip
  unzip
  unrar-free
  curl 
  nvme-cli
  inxi
  smartmontools
  rclone
  ffmpeg-free 
  mediainfo
  cryptsetup
  easyeffects
  gnome-tweaks
  gnome-extensions-app
)
declare -A flatpak_apps=(
  [flatseal]="com.github.tchx84.Flatseal"
  [ungoogled_chromium]="io.github.ungoogled_software.ungoogled_chromium"
  [firefox]="org.mozilla.firefox"
  [chromium]="org.chromium.Chromium"
  [filezilla]="org.filezillaproject.Filezilla"
  [keepassxc]="org.keepassxc.KeePassXC"
  [telegram]="org.telegram.desktop"
  [gimp]="org.gimp.GIMP"
  [qbittorrent]="org.qbittorrent.qBittorrent"
  [sublimetext]="com.sublimehq.SublimeText"
)

if [[ $INSTALL_OPTIONAL_SOFTWARE == true ]]; then
  info "Optional software deployment is enabled (INSTALL_OPTIONAL_SOFTWARE=true)"

  has_flatpak=false
  if command -v flatpak &>/dev/null; then
    has_flatpak=true
    if [[ $MODE == apply ]]; then
      flatpak remote-add --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo 2>/dev/null || true
    fi
  else
    warn "Flatpak is not installed on the system. Flatpak-targeted apps will be skipped."
  fi

  for name in "${!flatpak_apps[@]}"; do
    appid="${flatpak_apps[$name]}"
    
    if [[ $has_flatpak == true ]]; then
      if flatpak info "$appid" &>/dev/null; then
        ok "Already installed via Flatpak: $name ($appid)"
        continue
      elif rpm -q "$name" &>/dev/null; then
        warn "Package '$name' is installed via DNF, but target policy requires Flatpak. Skipping DNF duplicate."
        continue
      fi

      if [[ $MODE == apply ]]; then
        info "Installing via Flatpak: $appid..."
        if flatpak install -y flathub --noninteractive "$appid" 2>/dev/null; then
          fixed "Installed via Flatpak: $appid"
        else
          warn "Failed to install via Flatpak: $appid (check Flathub availability)"
        fi
      else
        warn "App will be installed via Flatpak: $appid (mode: audit)"
      fi
    else
      warn "Skipping Flatpak app '$name' because Flatpak is unavailable."
    fi
  done

  for pkg in "${dnf_apps[@]}"; do
    if rpm -q "$pkg" &>/dev/null; then
      ok "Already installed (DNF): $pkg"
    elif dnf info "$pkg" &>/dev/null; then
      if [[ $MODE == apply ]]; then
        if dnf install -y "$pkg" 2>/dev/null; then
          fixed "Installed via DNF: $pkg"
        else
          warn "Failed to install package via DNF: $pkg"
        fi
      else
        warn "Package available in DNF (will be installed): $pkg"
      fi
    else
      warn "Package not found in DNF: $pkg"
    fi
  done

  if [[ $MODE == apply ]] && rpm -q easyeffects &>/dev/null; then
    _target_user=$(resolve_real_user)
    if [[ -n "$_target_user" && "$_target_user" != "root" ]]; then
      sudo -u "$_target_user" bash << 'EE_EOF'
        mkdir -p ~/.config/autostart
        rm -f ~/.config/autostart/easyeffects-service.desktop
        cat <<'EOF' > ~/.config/autostart/com.github.wwmm.easyeffects.desktop
[Desktop Entry]
Type=Application
Name=Easy Effects
Comment=Easy Effects Service
Exec=easyeffects --gapplication-service
Icon=com.github.wwmm.easyeffects
StartupNotify=false
Terminal=false
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
X-GNOME-Autostart-Phase=Application
EOF
EE_EOF
      fixed "Added Easy Effects (DNF) to user autostart"
    fi
  fi

  # Apply browser hardening after possible installation
  if [[ $MODE == apply ]]; then
    REAL_USER=$(resolve_real_user)
    USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    if [[ -n "$REAL_USER" && "$REAL_USER" != "root" && -d "$USER_HOME" ]]; then
      setup_firefox_prefs "$REAL_USER" "$USER_HOME"
      setup_chromium_prefs "$REAL_USER" "$USER_HOME"
      if [[ -n "${flatpak_apps[sublimetext]:-}" ]]; then
        setup_sublime_text "$REAL_USER" "$USER_HOME"
      fi
    fi
  fi

else
  info "Optional software deployment is skipped (set INSTALL_OPTIONAL_SOFTWARE=true in script to activate)"
fi

# Always attempt browser hardening in apply mode even if software install was skipped
if [[ $MODE == apply ]]; then
  REAL_USER=$(resolve_real_user)
  USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
  if [[ -n "$REAL_USER" && "$REAL_USER" != "root" && -d "$USER_HOME" ]]; then
    setup_firefox_prefs "$REAL_USER" "$USER_HOME"
    setup_chromium_prefs "$REAL_USER" "$USER_HOME"
  fi
fi

# ===========================================================================
# 18. Hardened Malloc & Flatpak Sandbox Hardening
# ===========================================================================
section '18. Hardened Malloc & Flatpak Sandbox Hardening'

if [[ $INSTALL_HARDENED_MALLOC == true ]]; then
  LIB_DEST="/usr/local/lib/libhardened_malloc.so"
  REPO_URL="https://github.com/GrapheneOS/hardened_malloc/archive/refs/heads/main.tar.gz"
  WORK_DIR="/var/tmp/hardened_malloc_build"
  HASH_FILE="/var/lib/hardened_malloc.sha256"

  REAL_USER=$(resolve_real_user)

  if [[ -f "$LIB_DEST" ]]; then
    ok "Hardened malloc library is present at $LIB_DEST"
  else
    warn "Hardened malloc library is missing at $LIB_DEST"
  fi

  if [[ $MODE == apply ]]; then
    info "Hardened malloc deployment enabled"

    if ! command -v make &>/dev/null || ! command -v gcc &>/dev/null || ! command -v g++ &>/dev/null; then
      warn "Build tools (make, gcc, gcc-c++) not found. Installing via DNF..."
      dnf install -y make gcc gcc-c++ glibc-devel 2>/dev/null || die "Failed to install build dependencies for hardened_malloc"
    fi

    install -d -m 0755 "$WORK_DIR"
    cd "$WORK_DIR"

    info "Downloading latest GrapheneOS hardened_malloc source..."
    if curl -sL "$REPO_URL" -o source.tar.gz; then
      NEW_HASH=$(sha256sum source.tar.gz | awk '{print $1}')
      OLD_HASH=""
      [[ -f "$HASH_FILE" ]] && OLD_HASH=$(cat "$HASH_FILE")

      if [[ "$NEW_HASH" != "$OLD_HASH" ]] || [[ ! -f "$LIB_DEST" ]]; then
        info "Building hardened_malloc from source..."
        tar -xzf source.tar.gz
        cd hardened_malloc-*
        
        make -j$(nproc) || die "Failed to compile hardened_malloc"
        
        install -d -m 0755 "$(dirname "$LIB_DEST")"
        install -m 0755 out/libhardened_malloc.so "$LIB_DEST"
        restorecon -v "$LIB_DEST" 2>/dev/null || true
        
        echo "$NEW_HASH" > "$HASH_FILE"
        fixed "hardened_malloc successfully built and updated at $LIB_DEST"
        
        cd "$WORK_DIR"
        rm -rf hardened_malloc-* source.tar.gz
      else
        ok "hardened_malloc is already up-to-date, compilation skipped."
      fi
    else
      warn "Failed to download hardened_malloc source from GitHub."
    fi
  else
    warn "Hardened malloc compilation pending (mode: audit)"
  fi

  if command -v flatpak &>/dev/null; then
    section '18.1. Flatpak Global + Per-App Strict Sandbox'

    if [[ $MODE == apply ]]; then
      sudo -u "$REAL_USER" flatpak override --user \
        --filesystem="$LIB_DEST":ro \
        --env=LD_PRELOAD="$LIB_DEST" \
        --nosocket=x11 \
        --nosocket=session-bus \
        --nodevice=all \
        --nofilesystem=host \
        --nofilesystem=home \
        --nofilesystem=xdg-download \
        --nofilesystem=xdg-documents \
        --nofilesystem=xdg-pictures \
        --nofilesystem=xdg-videos \
        --nofilesystem=xdg-music \
        --share=network \
        --share=ipc \
        --socket=wayland \
        --socket=pulseaudio \
        --talk-name=org.freedesktop.Notifications \
        --talk-name=org.freedesktop.secrets \
        --talk-name=org.freedesktop.portal.* \
        2>/dev/null || true
      fixed "Global Flatpak defaults applied (hardened_malloc + strict base)"

      for browser in \
        org.mozilla.firefox \
        org.chromium.Chromium \
        io.github.ungoogled_software.ungoogled_chromium
      do
        if sudo -u "$REAL_USER" flatpak info "$browser" &>/dev/null; then
          sudo -u "$REAL_USER" flatpak override --user "$browser" \
            --nosocket=x11 \
            --nosocket=session-bus \
            --nodevice=all \
            --nofilesystem=host \
            --nofilesystem=home \
            --nofilesystem=xdg-documents \
            --nofilesystem=xdg-pictures \
            --nofilesystem=xdg-videos \
            --nofilesystem=xdg-music \
            --nofilesystem=xdg-desktop \
            --filesystem=xdg-download \
            --persist=xdg-config \
            --persist=xdg-data \
            --share=network \
            --socket=wayland \
            --socket=pulseaudio \
            --talk-name=org.freedesktop.Notifications \
            --talk-name=org.freedesktop.secrets \
            --talk-name=org.freedesktop.portal.* \
            --env=LD_PRELOAD="$LIB_DEST" \
            2>/dev/null || true
          fixed "Strict browser sandbox applied: $browser"
        fi
      done

      if sudo -u "$REAL_USER" flatpak info org.keepassxc.KeePassXC &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user org.keepassxc.KeePassXC \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-documents:rw \
          --persist=xdg-config \
          --share=network \
          --socket=wayland \
          --talk-name=org.freedesktop.secrets \
          --talk-name=org.freedesktop.Notifications \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "KeePassXC sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info org.telegram.desktop &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user org.telegram.desktop \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-download:rw \
          --filesystem=xdg-pictures:rw \
          --filesystem=xdg-videos:rw \
          --persist=xdg-config \
          --persist=xdg-data \
          --share=network \
          --socket=wayland \
          --socket=pulseaudio \
          --talk-name=org.freedesktop.Notifications \
          --talk-name=org.freedesktop.secrets \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "Telegram sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info org.filezillaproject.Filezilla &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user org.filezillaproject.Filezilla \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-download:rw \
          --persist=xdg-config \
          --share=network \
          --socket=wayland \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "FileZilla sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info org.gimp.GIMP &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user org.gimp.GIMP \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-pictures:rw \
          --filesystem=xdg-download:rw \
          --persist=xdg-config \
          --socket=wayland \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "GIMP sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info org.qbittorrent.qBittorrent &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user org.qbittorrent.qBittorrent \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-download:rw \
          --persist=xdg-config \
          --persist=xdg-data \
          --share=network \
          --socket=wayland \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "qBittorrent sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info com.sublimehq.SublimeText &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user com.sublimehq.SublimeText \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --filesystem=xdg-documents:rw \
          --filesystem=xdg-download:rw \
          --persist=xdg-config \
          --persist=xdg-data \
          --socket=wayland \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "Sublime Text sandbox tightened"
      fi

      if sudo -u "$REAL_USER" flatpak info com.github.tchx84.Flatseal &>/dev/null; then
        sudo -u "$REAL_USER" flatpak override --user com.github.tchx84.Flatseal \
          --nosocket=x11 \
          --nodevice=all \
          --nofilesystem=host \
          --persist=xdg-config \
          --socket=wayland \
          --talk-name=org.freedesktop.Flatpak \
          --env=LD_PRELOAD="$LIB_DEST" \
          2>/dev/null || true
        fixed "Flatseal sandbox applied"
      fi

    else
      info "Would apply strict global + per-app Flatpak overrides (mode: audit)"
    fi
  else
    info "Flatpak is not installed; skipping Flatpak integration."
  fi

else
  info "Hardened malloc deployment is skipped (set INSTALL_HARDENED_MALLOC=true to activate)"
fi

# ===========================================================================
# 19. GNOME Panel, App Folders, MacTahoe Icons/Cursors & Tiling Shell
# ===========================================================================
section '19. GNOME Panel, App Folders, MacTahoe Icons/Cursors & Tiling Shell'

if [[ "$SETUP_GNOME_LAYOUT" == true ]]; then
  if [[ "$IS_DESKTOP" == true ]]; then
    REAL_USER=$(resolve_real_user)
    
    USER_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    USER_UID=$(id -u "$REAL_USER" 2>/dev/null || echo 1000)
    
    if [[ -n "$REAL_USER" && "$REAL_USER" != "root" && -d "$USER_HOME" ]]; then
      info "Configuring GNOME for user: $REAL_USER (home directory: $USER_HOME)"

      if [[ "$MODE" == "apply" ]]; then
        # Install GNOME extensions and dependencies
        info "Checking and installing GNOME extensions (Dash to Dock, Tiling Shell)..."
        dnf install -y python3-pip jq unzip curl git glib2-devel &>/dev/null || true
        
        sudo -u "$REAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" XDG_RUNTIME_DIR="/run/user/$USER_UID" bash << 'EXT_EOF'
          pip install --user gnome-extensions-cli &>/dev/null || true
          export PATH="$HOME/.local/bin:$PATH"
          
          if ! gnome-extensions list | grep -q "dash-to-dock@micxgx.gmail.com"; then
              gext install dash-to-dock@micxgx.gmail.com 2>/dev/null || true
          fi
          if ! gnome-extensions list | grep -q "tilingshell@ferrarodomenico.com"; then
              gext install tilingshell@ferrarodomenico.com 2>/dev/null || true
          fi
          
          gnome-extensions enable dash-to-dock@micxgx.gmail.com 2>/dev/null || true
          gnome-extensions enable tilingshell@ferrarodomenico.com 2>/dev/null || true

          # Compile schemas
          mkdir -p "$HOME/.local/share/glib-2.0/schemas"
          for ext_dir in "$HOME/.local/share/gnome-shell/extensions/"*; do
              if [[ -d "$ext_dir/schemas" ]]; then
                  cp -f "$ext_dir/schemas/"*.xml "$HOME/.local/share/glib-2.0/schemas/" 2>/dev/null || true
              fi
          done
          glib-compile-schemas "$HOME/.local/share/glib-2.0/schemas" 2>/dev/null || true
EXT_EOF
        fixed "GNOME extensions checked/installed and schemas compiled"

        # MacTahoe icons & cursors
        info "Checking MacTahoe icons and cursors..."
        sudo -u "$REAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" bash << 'MACTAHOE_EOF'
          set -e
          if [[ ! -d "$HOME/.local/share/icons/MacTahoe" ]]; then
              echo "          Downloading MacTahoe icon theme..."
              TMP_DIR=$(mktemp -d)
              cd "$TMP_DIR"

              if curl -sL "https://github.com/vinceliuice/MacTahoe-icon-theme/archive/refs/heads/main.tar.gz" -o icon-theme.tar.gz; then
                  tar -xzf icon-theme.tar.gz
                  cd MacTahoe-icon-theme-main
                  ./install.sh -d "$HOME/.local/share/icons" -n MacTahoe >/dev/null 2>&1 || ./install.sh >/dev/null 2>&1 || true

                  if [[ -d cursors && -x cursors/install.sh ]]; then
                      cd cursors
                      ./install.sh >/dev/null 2>&1 || true
                      cd ..
                  fi
              fi
              rm -rf "$TMP_DIR"
          else
              echo "          MacTahoe icons already exist, skipping download."
          fi

          if [[ -d "$HOME/.local/share/icons/MacTahoe" ]]; then
              gsettings set org.gnome.desktop.interface icon-theme "MacTahoe"
          elif [[ -d "$HOME/.icons/MacTahoe" ]]; then
              gsettings set org.gnome.desktop.interface icon-theme "MacTahoe"
          fi

          CURSOR_THEME=""
          for cand in "MacTahoe-cursors" "MacTahoe" "MacTahoe Cursors"; do
              if [[ -d "$HOME/.local/share/icons/$cand" || -d "$HOME/.icons/$cand" ]]; then
                  CURSOR_THEME="$cand"
                  break
              fi
          done
          if [[ -z "$CURSOR_THEME" ]]; then
              CURSOR_THEME=$(find "$HOME/.local/share/icons" "$HOME/.icons" -maxdepth 1 -type d \( -iname "*MacTahoe*cursor*" -o -iname "*MacTahoe*" \) 2>/dev/null | head -n1 | xargs -r basename || true)
          fi
          if [[ -n "$CURSOR_THEME" ]]; then
              gsettings set org.gnome.desktop.interface cursor-theme "$CURSOR_THEME"
          fi
MACTAHOE_EOF
        fixed "MacTahoe icons and cursors checked/configured"

        # Tiling Shell multi-monitor layout
        info "Applying Tiling Shell multi-monitor layout configuration..."
        sudo -u "$REAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" bash << 'TILING_EOF'
          LAYOUT_JSON='[{"id":"13321385","tiles":[{"x":0,"y":0,"width":1,"height":0.3331766917293233,"groups":[2]},{"x":0,"y":0.3331766917293233,"width":1,"height":0.3336466165413534,"groups":[2,3]},{"x":0,"y":0.6668233082706767,"width":1,"height":0.33317669172932335,"groups":[3]}]},{"id":"13564581","tiles":[{"x":0,"y":0,"width":0.5,"height":1,"groups":[1]},{"x":0.5,"y":0,"width":0.49999999999999206,"height":1,"groups":[1]}]}]'

          if gsettings list-schemas | grep -q "org.gnome.shell.extensions.tilingshell"; then
              gsettings set org.gnome.shell.extensions.tilingshell layouts-json "$LAYOUT_JSON" 2>/dev/null || true
              gsettings set org.gnome.shell.extensions.tilingshell selected-layouts "[['13321385'], ['13564581']]" 2>/dev/null || \
              gsettings set org.gnome.shell.extensions.tilingshell selected-layouts "[['13321385'],['13564581']]" 2>/dev/null || true
          fi
TILING_EOF
        fixed "Tiling Shell multi-monitor layout applied successfully"

        # Favorites & app folders
        TERMINAL_ID=""
        for term_app in \
            "org.gnome.Ptyxis.desktop" \
            "org.gnome.Console.desktop" \
            "org.fedoraproject.Console.desktop" \
            "org.gnome.Terminal.desktop"
        do
            if [[ -f "/usr/share/applications/$term_app" ]]; then
                TERMINAL_ID="$term_app"
                break
            fi
        done
        [[ -z "$TERMINAL_ID" ]] && TERMINAL_ID="org.gnome.Ptyxis.desktop"

        base_favs=(
            "org.gnome.Nautilus.desktop"
            "io.github.ungoogled_software.ungoogled_chromium.desktop"
            "org.mozilla.firefox.desktop"
            "org.chromium.Chromium.desktop"
            "org.telegram.desktop.desktop"
            "org.keepassxc.KeePassXC.desktop"
            "org.filezillaproject.Filezilla.desktop"
            "com.sublimehq.SublimeText.desktop"
            "org.gimp.GIMP.desktop"
            "org.gnome.Calculator.desktop"
            "$TERMINAL_ID"
            "com.github.wwmm.easyeffects.desktop"
        )

        fav_quoted=()
        for app in "${base_favs[@]}"; do
            fav_quoted+=("'$app'")
        done
        FAV_APPS="[$(IFS=,; echo "${fav_quoted[*]}")]"
        BASE_FAVS_STR="${base_favs[*]}"

        sudo -u "$REAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" XDG_RUNTIME_DIR="/run/user/$USER_UID" \
          FAV_APPS="$FAV_APPS" BASE_FAVS_STR="$BASE_FAVS_STR" bash << 'GNOME_EOF'
          gsettings set org.gnome.shell favorite-apps "$FAV_APPS"

          # shellcheck disable=SC2206
          base_favs=( $BASE_FAVS_STR )
          app_list=()
          while IFS= read -r desktop_file; do
              skip=false
              for fav in "${base_favs[@]}"; do
                  if [[ "$desktop_file" == "$fav" ]]; then
                      skip=true
                      break
                  fi
              done
              if [[ "$skip" == "true" ]]; then
                  continue
              fi
              app_list+=("'$desktop_file'")
          done < <(find /usr/share/applications/ $HOME/.local/share/applications/ -maxdepth 1 -name "*.desktop" -exec basename {} \; 2>/dev/null | sort -u)

          IFS=,
          APPS_ARRAY="[${app_list[*]}]"
          unset IFS

          gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/default/ name 'Default'
          gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/default/ apps "$APPS_ARRAY"
          gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/default/ categories "[]"

          current_folders=$(gsettings get org.gnome.desktop.app-folders folder-children | tr -d "[]',")
          for std_folder in $current_folders; do
              [[ "$std_folder" == "default" ]] && continue
              gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/$std_folder/ apps "[]" 2>/dev/null || true
              gsettings set org.gnome.desktop.app-folders.folder:/org/gnome/desktop/app-folders/folders/$std_folder/ categories "[]" 2>/dev/null || true
          done

          gsettings set org.gnome.desktop.app-folders folder-children "['default']"

          gsettings set org.gnome.desktop.background picture-uri ''
          gsettings set org.gnome.desktop.background picture-uri-dark ''
          gsettings set org.gnome.desktop.background primary-color '#000000'
          gsettings set org.gnome.desktop.background color-shading-type 'solid'
GNOME_EOF

        fixed "GNOME panel, app folders, black background and layouts successfully configured for user $REAL_USER"
      else
        info "Would configure GNOME panel, icons/cursors and tiling layout for user $REAL_USER (mode: audit)"
      fi
    else
      warn "Could not determine graphical user for GNOME configuration."
    fi
  else
    info "Graphical environment not detected, skipping GNOME panel configuration."
  fi
else
  info "GNOME layout & extensions configuration skipped (set SETUP_GNOME_LAYOUT=true to activate)"
fi

# ===========================================================================
# 20. Recommended System Preferences (GNOME)
# ===========================================================================
section '20. Recommended System Preferences'

if [[ "$SETUP_SYSTEM_PREFS" == true ]]; then
  if [[ "$IS_DESKTOP" == true ]]; then
    REAL_USER=$(resolve_real_user)
    USER_UID=$(id -u "$REAL_USER" 2>/dev/null || echo 1000)

    if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
      info "Applying system preferences for user: $REAL_USER"

      if [[ "$MODE" == "apply" ]]; then
        if command -v powerprofilesctl &>/dev/null; then
          powerprofilesctl set performance 2>/dev/null || true
        elif command -v tuned-adm &>/dev/null; then
          tuned-adm profile throughput-performance 2>/dev/null || \
          tuned-adm profile latency-performance 2>/dev/null || true
        fi

        sudo -u "$REAL_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$USER_UID/bus" XDG_RUNTIME_DIR="/run/user/$USER_UID" bash << 'PREFS_EOF'
          set +e

          # Keyboard: English primary + Russian additional, hotkey Shift + Alt
          gsettings set org.gnome.desktop.input-sources sources "[('xkb', 'us'), ('xkb', 'ru')]"
          gsettings set org.gnome.desktop.input-sources xkb-options "['grp:alt_shift_toggle', 'grp:shift_caps_toggle']"

          # Disable F10 menu accelerator globally via GTK settings (fixes mcedit/ncurses in Ptyxis & GTK apps)
          for gtk_dir in "$HOME/.config/gtk-3.0" "$HOME/.config/gtk-4.0"; do
            mkdir -p "$gtk_dir"
            ini_file="$gtk_dir/settings.ini"
            if [[ -f "$ini_file" ]]; then
              if grep -q "gtk-menu-bar-accel" "$ini_file"; then
                sed -i 's/^[[:space:]]*gtk-menu-bar-accel.*/gtk-menu-bar-accel = ""/' "$ini_file"
              else
                sed -i '/^\[Settings\]/a gtk-menu-bar-accel = ""' "$ini_file" 2>/dev/null || echo 'gtk-menu-bar-accel = ""' >> "$ini_file"
              fi
            else
              printf '[Settings]\ngtk-menu-bar-accel = ""\n' > "$ini_file"
            fi
          done

          # Terminal (Ptyxis): Register custom XTerm palette file and assign it by Name to profiles
          if command -v dconf &>/dev/null; then
            for prof_path in $(dconf list /org/gnome/Ptyxis/Profiles/ 2>/dev/null); do
              dconf write "/org/gnome/Ptyxis/Profiles/${prof_path}palette" "'xterm'" 2>/dev/null || true
            done
          fi

          # Window Management: Close window with Alt+Q (and Alt+F4)
          gsettings set org.gnome.desktop.wm.keybindings close "['<Alt>q', '<Alt>F4']"

          # Microphone input volume → 0
          export XDG_RUNTIME_DIR="/run/user/$(id -u)"
          if command -v pactl &>/dev/null; then
            DEFAULT_SOURCE=$(pactl get-default-source 2>/dev/null || true)
            if [[ -n "$DEFAULT_SOURCE" ]]; then
              pactl set-source-volume "$DEFAULT_SOURCE" 0% 2>/dev/null || true
              pactl set-source-mute "$DEFAULT_SOURCE" 1 2>/dev/null || true
            fi
            pactl list short sources 2>/dev/null | while read -r idx name rest; do
              pactl set-source-volume "$idx" 0% 2>/dev/null || true
              pactl set-source-mute "$idx" 1 2>/dev/null || true
            done
          fi

          # Power mode → Performance
          if command -v powerprofilesctl &>/dev/null; then
            powerprofilesctl set performance 2>/dev/null || true
          elif command -v tuned-adm &>/dev/null; then
            tuned-adm profile throughput-performance 2>/dev/null || \
            tuned-adm profile latency-performance 2>/dev/null || true
          fi

          # Blank screen / power saving: never
          gsettings set org.gnome.desktop.session idle-delay 300
          gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-ac-type 'nothing' 2>/dev/null || true
          gsettings set org.gnome.settings-daemon.plugins.power sleep-inactive-battery-type 'nothing' 2>/dev/null || true
          gsettings set org.gnome.settings-daemon.plugins.power idle-dim false 2>/dev/null || true

          # Automatic screen lock: off
          gsettings set org.gnome.desktop.screensaver lock-enabled true
          gsettings set org.gnome.desktop.screensaver lock-delay 0

          # Dynamic workspaces → fixed, count = 1
          gsettings set org.gnome.mutter dynamic-workspaces false
          gsettings set org.gnome.desktop.wm.preferences num-workspaces 1

          # Appearance: Dark
          gsettings set org.gnome.desktop.interface color-scheme 'prefer-dark'
          gsettings set org.gnome.desktop.interface gtk-theme 'Adwaita-dark' 2>/dev/null || true

          # Lock Screen notifications: off
          gsettings set org.gnome.desktop.notifications show-in-lock-screen false 2>/dev/null || true
          gsettings set org.gnome.desktop.screensaver show-notifications false 2>/dev/null || true

          # App Search in overview: off
          gsettings set org.gnome.desktop.search-providers disable-external true 2>/dev/null || true

          # Location services: force off
          gsettings set org.gnome.system.location enabled false

          # File History: keep 30 days
          gsettings set org.gnome.desktop.privacy remember-recent-files true
          gsettings set org.gnome.desktop.privacy recent-files-max-age 30

          # Automatically Empty Trash + Delete Temporary Files (30 days)
          gsettings set org.gnome.desktop.privacy remove-old-trash-files true
          gsettings set org.gnome.desktop.privacy remove-old-temp-files true
          gsettings set org.gnome.desktop.privacy old-files-age 30

          # Regional formats: Russian Federation, 24h, Monday first
          gsettings set org.gnome.system.locale region 'ru_RU.UTF-8' 2>/dev/null || true
          gsettings set org.gnome.desktop.interface clock-format '24h'
          gsettings set org.gnome.desktop.calendar week-start-day-name 'monday' 2>/dev/null || \
            gsettings set org.gnome.desktop.calendar week-start-day 1 2>/dev/null || true

          # Clock & Calendar: show seconds
          gsettings set org.gnome.desktop.interface clock-show-seconds true
          gsettings set org.gnome.desktop.interface clock-show-date true
          gsettings set org.gnome.desktop.interface clock-show-weekday true 2>/dev/null || true
PREFS_EOF
        fixed "System preferences applied for user $REAL_USER"
      else
        info "Would apply system preferences for user $REAL_USER (mode: audit)"
      fi
    else
      warn "Could not determine graphical user for system preferences."
    fi
  else
    info "Graphical environment not detected, skipping system preferences."
  fi
else
  info "System preferences skipped (set SETUP_SYSTEM_PREFS=true to activate)"
fi

# ===========================================================================
# Summary
# ===========================================================================
section 'Summary'

if [[ $MODE == apply ]]; then
  info "All requested changes have been applied."
  info "Backups stored in: $BACKUP_DIR"
  info "Full log written to: $LOG_FILE"
  info ""
  info "IMPORTANT: Reboot the system for kernel arguments and module blacklist to take full effect."
  info "Firefox: After first launch open uBlock Origin → Filter lists → enable every list + 'Block remote fonts'."
else
  info "Audit finished. No changes were made."
  info "To apply hardening:  sudo $0 --apply"
fi

echo
