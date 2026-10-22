
#!/usr/bin/env bash
set -Eeuo pipefail

PANEL_SERVICE="clp-nginx"
PHP_SERVICE="clp-php-fpm"
PORT="8443"

STATE_DIR="/var/lib/cloudpanel-toggle"
RULE_MARKER="$STATE_DIR/ufw-rule-added"

if [[ $EUID -ne 0 ]]; then
    echo "Запусти от root: $0 enable|disable" >&2
    exit 1
fi

if [[ $# -ne 1 ]] ||
   [[ "$1" != "enable" && "$1" != "disable" ]]; then
    echo "Использование: $0 {enable|disable}" >&2
    exit 2
fi

ACTION="$1"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_DIR"

systemctl cat "$PANEL_SERVICE" >/dev/null
systemctl cat "$PHP_SERVICE" >/dev/null

close_port() {
    command -v ufw >/dev/null 2>&1 || {
        echo "UFW не установлен; пропускаю firewall."
        return
    }

    ufw status | grep -q '^Status: active' || {
        echo "UFW не активен; пропускаю firewall."
        return
    }

    if [[ -f "$RULE_MARKER" ]]; then
        echo "Правило UFW уже добавлено этим скриптом."
        return
    fi

    if ufw status | grep -Eiq \
        '(^|[[:space:]])8443/tcp([[:space:]]|$).*DENY'; then
        echo "Запрет TCP/$PORT уже существует; не меняю его."
        return
    fi

    ufw insert 1 deny "$PORT/tcp"
    touch "$RULE_MARKER"
    echo "UFW: TCP/$PORT закрыт."
}

open_port() {
    [[ -f "$RULE_MARKER" ]] || {
        echo "Скрипт не добавлял правило UFW; чужие правила не трогаю."
        return
    }

    ufw status | grep -q '^Status: active' || {
        echo "UFW не активен. Правило оставлено без изменений."
        return 1
    }

    ufw --force delete deny "$PORT/tcp"
    rm -f "$RULE_MARKER"
    echo "UFW: правило блокировки TCP/$PORT удалено."
}

case "$ACTION" in
    disable)
        # Сначала закрываем внешний доступ.
        close_port

        # Отключаем PHP CloudPanel и запрещаем его запуск.
        systemctl mask --now "$PHP_SERVICE"

        # Останавливаем панель и отключаем автозапуск.
        systemctl disable --now "$PANEL_SERVICE"

        echo "CloudPanel: выключен."
        echo "CloudPanel PHP-FPM: остановлен и замаскирован."
        ;;

    enable)
        # PHP 8.1 намеренно остаётся masked.
        # Не запускать и не размаскировывать clp-php-fpm!

        systemctl enable "$PANEL_SERVICE"
        systemctl start "$PANEL_SERVICE"

        if ! systemctl is-active --quiet "$PANEL_SERVICE"; then
            echo "Ошибка запуска $PANEL_SERVICE." >&2
            exit 1
        fi

        open_port

        echo "CloudPanel Nginx: запущен."
        echo "CloudPanel PHP-FPM: остаётся masked."
        echo "Внимание: интерфейс может не работать без своего PHP-FPM."
        ;;
esac

echo
echo "Состояние сервисов:"
systemctl is-active "$PANEL_SERVICE" || true
systemctl is-enabled "$PANEL_SERVICE" || true
systemctl is-active "$PHP_SERVICE" || true
systemctl is-enabled "$PHP_SERVICE" || true

echo
echo "PHP-FPM процессы:"
ps -eo pid,args | grep '[p]hp-fpm' || true
