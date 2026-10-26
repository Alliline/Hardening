# Hardening

## PC: Fedora 44/45
```
chmod +x ./fedora.sh
sudo ./fedora.sh [--audit|--apply]
```
- Удаляет весь мусор Gnome, повышает безопасность системы.
- Опционально: установка ПО flatpak; hardened_malloc как в GrapheneOS для flatpak; персонализация (иконки, курсор, черная заливка на обои).
- Протестировано: 18.10.2026 на Fedora 44 (7.2.10-200).

## PC: DNS (Fedora)
```
chmod +x ./wds.sh
sudo ./wds.sh [apply|update|status|restore]
```
- Настраивает и включает локальный DNS, минимизирует вероятность слива IP адреса, снижает вероятность трекинга. 
- Парсит лежащий рядом whitelist.txt - список разрешённых доменов. Заполнение в столбик, каждый с новой строки. 
- Протестировано: 18.10.2026 на Fedora 44 (7.2.10-200).

## PC: Windows 11 PowerShell
```
Set-ExecutionPolicy Unrestricted -Scope Process -Force
.\windows.ps1 -Mode [Audit|Apply]
```
- Удаляет дефолтное ПО Microsoft, повышает безопасность системы.
- Парсит лежащие рядом authorized_keys или id_rsa.pub, добавляет в разрешенные (для авторизации по SSH) ключи. 
- Повторный запуск при ошибке привелегий:
```
powershell.exe -ExecutionPolicy Bypass -File "C:\windows.ps1" -Mode Apply
```
- Протестировано: 18.10.2026 на Windows 25H2 (26200.9711).

## Lab (Router): Asus BQ16
```
chmod +x ./asus.sh
./asus.sh 
```
- Настраивает VLAN на eth2 (порт LAN 10G) + фаервол + маскарадинг, отключает лишние сервисы.
- Для прошивки AM-Reaper (которая отчасти Asus-Merlin). 
- Протестировано: 19.10.2026 на 3006.102.8_Reaper_v3.4.6_BETA_noMCP.

## Lab (NAS): Proxmox
```
chmod +x ./proxmox.sh
./proxmox.sh 
```
- Меняет стандартные порты на кастомные, добавляет пользователя, повышает безопасность ядра и тд.
- Парсит лежащий рядом id_rsa.pub, добавляет в ssh (nopass). 
- Протестировано: 26.10.2026 на Proxmox 9.2 (7.0.2-6-pve).

## Web / Lab (LAMP): Fedora Server 44/45
```
chmod +x ./server.sh
./server.sh 
```
- Предварительная версия, НЕ ТЕСТИРОВАЛАСЬ, НЕ ЗАПУСКАЛАСЬ!

## Web: Cloudpanel
```
chmod +x ./cloudpanel.sh
./cloudpanel.sh [enable|disable]
```
- Отключение веб-доступа к панели (clp-nginx) и отдельного сервиса PHP (clp-php-fpm).
- Временный фикс для избавления от PHP 8.1, на котором работает сама панель (сопутствие лечению CVE-2026-109618 и CVE-2026-109619)
- Когда переход на 8.5.12 уже состоялся и другие версии не нужны, желательно также:
```
systemctl stop php7.1-fpm php7.2-fpm php7.3-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm
systemctl disable php7.1-fpm php7.2-fpm php7.3-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm
```
- Проверить активные:
```
systemctl is-enabled clp-nginx clp-php-fpm
ps -eo pid,args | grep -E '[p]hp-fpm|[p]hp-cgi'
grep -RInE 'fastcgi_pass|proxy_pass|8443|php-fpm' /etc/nginx /home/clp/services/nginx 2>/dev/null
```
- Протестировано 21.10.2026 на 2.5.4.
