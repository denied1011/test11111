#!/bin/bash

# === OpenWrt Checker v2.2 (Ровная Таблица) ===
# Исправлено: жесткая ширина колонок, обрезка длинных имен

# Цвета
G='\033[0;32m' # Зеленый
R='\033[0;31m' # Красный
Y='\033[1;33m' # Желтый
NC='\033[0m'   # Сброс

# 1. Принимаем ссылку
URL="$1"
if [[ -z "$URL" ]]; then
    read -p "Вставьте ссылку: " URL
fi
[ -z "$URL" ] && exit 1

# Функция DNS
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

# Декодирование URL
urldecode() {
    echo "$1" | sed 's/%20/ /g' | sed 's/%[0-9A-Fa-f]\{2\}//g'
}

echo -ne "Скачивание... "
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo "Ошибка (Пустой ответ)"; exit 1
fi
echo "OK (${#RAW} байт)"

# === ПОДГОТОВКА ===
echo "Обработка..."

# 1. Поиск ссылок
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')

# 2. Декод Base64 если нужно
if [[ -z "$LINKS" ]]; then
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ' | sed 's/-/+/g; s/_/\//g')
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
fi

if [[ -z "$LINKS" ]]; then
    echo -e "${R}Ссылки не найдены!${NC}"
    exit 1
fi

COUNT=$(echo "$LINKS" | wc -l)
echo "Найдено: $COUNT"

# === ТАБЛИЦА (СТРОГОЕ ФОРМАТИРОВАНИЕ) ===
# Используем формат %-20.20s -> это значит: выделить 20 символов и ОБРЕЗАТЬ, если длиннее 20.

echo "-------------------------------------------------------------------------------------"
printf "| %-22s | %-22s | %-15s | %s\n" "ИМЯ" "ХОСТ (SNI)" "IP АДРЕС" "СТАТУС"
echo "-------------------------------------------------------------------------------------"

IFS=$'\n'
for link in $LINKS; do
    NAME="NoName"
    HOST=""
    
    # Парсинг VMESS
    if echo "$link" | grep -q "^vmess://"; then
        B64_JSON=$(echo "$link" | sed 's/vmess:\/\///')
        JSON=$(echo "$B64_JSON" | base64 -d 2>/dev/null)
        NAME=$(echo "$JSON" | grep -oE '"ps":"[^"]+"' | cut -d'"' -f4)
        HOST=$(echo "$JSON" | grep -oE '"add":"[^"]+"' | cut -d'"' -f4)
        if [[ -z "$HOST" ]]; then HOST=$(echo "$JSON" | grep -oE '"host":"[^"]+"' | cut -d'"' -f4); fi
        
    # Парсинг VLESS/Trojan/SS
    elif echo "$link" | grep -qE "^(vless|trojan|ss)://"; then
        if echo "$link" | grep -q "#"; then
            RAW_NAME=$(echo "$link" | sed 's/.*#//')
            NAME=$(urldecode "$RAW_NAME")
        fi
        CLEAN_LINK=$(echo "$link" | cut -d'?' -f1 | cut -d'#' -f1)
        NO_PROTO=$(echo "$CLEAN_LINK" | sed -E 's/^[a-z]+:\/\///')
        HOST=$(echo "$NO_PROTO" | sed 's/.*@//' | cut -d':' -f1)
    fi

    # Фильтры
    [[ -z "$NAME" ]] && NAME="NoName"
    if [[ -z "$HOST" ]] || echo "$HOST" | grep -qE '^127\.|^192\.168\.|^10\.|^0\.'; then continue; fi
    
    # === ЧИСТКА ДАННЫХ ===
    # Убираем вертикальные палки из имени, чтобы не ломать таблицу визуально
    CLEAN_NAME=$(echo "$NAME" | tr '|' '-')
    
    # Резолв IP
    IP=$(get_ip "$HOST")
    if [[ -z "$IP" ]]; then
        printf "| %-22.22s | %-22.22s | %-15.15s | %b\n" "$CLEAN_NAME" "$HOST" "???" "${Y}DNS Error${NC}"
        continue
    fi
    
    # Проверка
    if curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1; then
        STATUS="${G}Активно${NC}"
    else
        STATUS="${R}Блок РКН${NC}"
    fi
    
    # === ВЫВОД С ОБРЕЗКОЙ ===
    # %.22s означает "обрезать строку, если она длиннее 22 символов"
    # Это гарантирует, что таблица никогда не поплывет.
    printf "| %-22.22s | %-22.22s | %-15.15s | %b\n" "$CLEAN_NAME" "$HOST" "$IP" "$STATUS"
    
done
unset IFS
echo "-------------------------------------------------------------------------------------"
