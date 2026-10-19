# Hardening

## PC: Fedora 44/45:
```
chmod +x ./fedora.sh
sudo ./fedora.sh --apply
```
- Удаляет весь мусор Gnome, повышает безопасность системы.
- Опционально: установка ПО flatpak; hardened_malloc как в GrapheneOS для flatpak; персонализация (иконки, курсор, черная заливка на обои).

## PC: DNS (Fedora):
```
chmod +x ./wds.sh
sudo ./wds.sh --apply
```
- Настраивает и включает локальный DNS, минимизирует вероятность слива IP адреса, снижает вероятность трекинга. 
- Парсит лежащий рядом whitelist.txt - список разрешённых доменов. Заполнение в столбик, каждый с новой строки. 

## PC: Windows 11 PowerShell:
```
Set-ExecutionPolicy Unrestricted -Scope Process -Force
.\windows.ps1 -Mode Apply
```
- Парсит лежащие рядом authorized_keys или id_rsa.pub, добавляет в разрешенные (для авторизации по SSH) ключи. 

## Router: Asus BQ16:
```
chmod +x ./asus.sh
./asus.sh
```
- Настраивает VLAN на eth2 (порт LAN 10G) + фаервол + маскарадинг, отключает лишние сервисы.
- Для прошивки AM-Reaper (которая отчасти Asus-Merlin). 
