#!/bin/bash

# === OpenWrt One-Time Checker ===
# Запускается, проверяет, выводит результат и закрывается.

# Цвета
G='\033[0;32m'
R='\033[0;31m'
NC='\033[0m'

# 1. Принимаем ссылку (аргумент $1)
URL="$1"
# Если не передали аргументом, спрашиваем
if [[ -z "$URL" ]]; then
    read -p "Link: " URL
fi

# Если пусто - выход
[ -z "$URL" ] && exit 1

# Функция DNS (Google DNS 8.8.8.8)
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

echo -ne "Download... "
# Скачиваем с User-Agent браузера
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo "Error (Empty response)"; exit 1
fi
echo "OK (${#RAW} bytes)"

# === ПАРСИНГ (HTML -> Link -> Domain) ===
echo "Parsing..."

# 1. Ищем явные ссылки (vless://...)
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')

# 2. Если пусто, чистим HTML и декодируем Base64
if [[ -z "$LINKS" ]]; then
    # Удаляем теги
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ')
    # Fix Base64 URL Safe (+ и /)
    CLEAN=$(echo "$CLEAN" | sed 's/-/+/g; s/_/\//g')
    # Декодируем
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    # Ищем ссылки внутри
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
    SEARCH_TEXT="$RAW $DECODED"
else
    SEARCH_TEXT="$RAW"
fi

# 3. Выдираем домены из найденного
HOSTS=""
if [[ -n "$LINKS" ]]; then
    for link in $LINKS; do
        # Убираем протокол
        NOPROTO=$(echo "$link" | sed -E 's/^[a-z]+:\/\///')
        # Ищем домен между @ и : (vless стандарт)
        D=$(echo "$NOPROTO" | grep -oE '@[a-zA-Z0-9.-]+' | sed 's/@//')
        # Если не вышло (vmess), ищем просто паттерн домена
        if [[ -z "$D" ]]; then D=$(echo "$link" | grep -oE '[a-zA-Z0-9.-]+\.[a-z]{2,}'); fi
        HOSTS+="$D "
    done
else
    # Fallback: просто ищем домены в тексте
    HOSTS=$(echo "$SEARCH_TEXT" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}')
fi

# 4. Фильтр мусора (исключаем google, vk, ozon и локальные IP)
FINAL_LIST=$(echo "$HOSTS" | tr ' ' '\n' | sort -u | grep -vE "^$|127\.0|192\.168|10\.|0\.0|html|body|href|src|style|width|height|google|github|cloudflare|vk\.com|ozon|yandex|mail|userapi|tradingview")

COUNT=$(echo "$FINAL_LIST" | wc -w)
if [ "$COUNT" -eq 0 ]; then
    echo "No nodes found."; exit 1
fi

echo "Found: $COUNT nodes"
echo "--------------------------------------------------------"
printf "%-25s | %-15s | %s\n" "HOST" "IP" "HTTPS Status"
echo "--------------------------------------------------------"

for host in $FINAL_LIST; do
    # Пропускаем короткий мусор
    if [ ${#host} -lt 4 ]; then continue; fi
    
    # Резолв IP
    IP=$(get_ip "$host")
    if [[ -z "$IP" ]]; then continue; fi

    # Проверка CURL (SSL Handshake)
    if curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1; then
        STATUS="${G}ALIVE${NC}"
    else
        STATUS="${R}BLOCKED${NC}"
    fi
    
    # ВАЖНО: Используем %b для корректного вывода цветов
    printf "%-25.25s | %-15s | %b\n" "$host" "$IP" "$STATUS"
done
