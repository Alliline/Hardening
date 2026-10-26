# Hardening

## Win
```
Set-ExecutionPolicy Unrestricted -Scope Process -Force
.\windows.ps1 -Mode [Audit|Apply]
```
Maybe or
```
powershell.exe -ExecutionPolicy Bypass -File "C:\windows.ps1" -Mode Apply
```

## Cloudpanel
```
systemctl stop php7.1-fpm php7.2-fpm php7.3-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm
systemctl disable php7.1-fpm php7.2-fpm php7.3-fpm php7.4-fpm php8.0-fpm php8.1-fpm php8.2-fpm php8.3-fpm php8.4-fpm
```
Check up
```
systemctl is-enabled clp-nginx clp-php-fpm
ps -eo pid,args | grep -E '[p]hp-fpm|[p]hp-cgi'
grep -RInE 'fastcgi_pass|proxy_pass|8443|php-fpm' /etc/nginx /home/clp/services/nginx 2>/dev/null
```
