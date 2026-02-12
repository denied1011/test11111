#!/bin/bash

# === OpenWrt Checker v3.3 (Cyrillic Safe) ===
# Исправлено: удаление эмодзи без поломки русских букв через iconv

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; NC='\033[0m'

URL="$1"
[[ -z "$URL" ]] && read -p "Вставьте ссылку: " URL
[[ -z "$URL" ]] && exit 1

# DNS Резолв
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

# Декодирование имен
urldecode() {
    echo "$1" | sed 's/%20/ /g' | sed 's/%[0-9A-Fa-f]\{2\}//g'
}

echo -ne "Скачивание... "
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")
[[ -z "$RAW" ]] && { echo "Ошибка"; exit 1; }
echo "OK"

# Поиск ссылок
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
if [[ -z "$LINKS" ]]; then
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ' | sed 's/-/+/g; s/_/\//g')
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
fi

[[ -z "$LINKS" ]] && { echo "Узлы не найдены"; exit 1; }

echo "------------------------------------------------------------------------------------------------------"
printf "| %-30s | %-25s | %-15s | %b\n" "ИМЯ" "SNI / ХОСТ" "IP АДРЕС" "СТАТУС"
echo "------------------------------------------------------------------------------------------------------"

IFS=$'\n'
for link in $LINKS; do
    NAME="Node"
    HOST=""
    
    if echo "$link" | grep -q "^vmess://"; then
        JSON=$(echo "$link" | sed 's/vmess:\/\///' | base64 -d 2>/dev/null)
        NAME=$(echo "$JSON" | grep -oE '"ps":"[^"]+"' | cut -d'"' -f4)
        HOST=$(echo "$JSON" | grep -oE '"add":"[^"]+"' | cut -d'"' -f4)
        [[ -z "$HOST" ]] && HOST=$(echo "$JSON" | grep -oE '"host":"[^"]+"' | cut -d'"' -f4)
    elif echo "$link" | grep -qE "^(vless|trojan|ss)://"; then
        [[ "$link" == *"#"* ]] && NAME=$(urldecode "$(echo "$link" | sed 's/.*#//')")
        HOST=$(echo "$link" | cut -d'?' -f1 | cut -d'#' -f1 | sed -E 's/^[a-z]+:\/\///' | sed 's/.*@//' | cut -d':' -f1)
    fi

    [[ -z "$HOST" ]] || echo "$HOST" | grep -qE '^127\.|^192\.168\.|^10\.' && continue

    # --- ГЛАВНЫЙ ФИКС ВОПРОСОВ (????) ---
    # 1. Используем iconv для удаления символов, которые не входят в UTF-8/Кириллицу
    # 2. Очищаем от остатков спецсимволов через sed (безопасно для кириллицы)
    CLEAN_NAME=$(echo "$NAME" | iconv -c -t UTF-8 2>/dev/null | sed 's/[^a-zA-Z0-9а-яА-ЯёЁ ._-]//g')
    
    # Убираем пробелы по краям
    CLEAN_NAME=$(echo "$CLEAN_NAME" | sed 's/^ *//;s/ *$//')
    [[ -z "$CLEAN_NAME" ]] && CLEAN_NAME="Node"

    IP=$(get_ip "$HOST")
    if [[ -z "$IP" ]]; then
        printf "| %-30.30s | %-25.25s | %-15s | %b\n" "$CLEAN_NAME" "$HOST" "???" "${Y}DNS Error${NC}"
        continue
    fi
    
    curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1 && STATUS="${G}Активно${NC}" || STATUS="${R}Блок РКН${NC}"
    
    # Печать (строго 30 - 25 - 15)
    printf "| %-30.30s | %-25.25s | %-15s | %b\n" "$CLEAN_NAME" "$HOST" "$IP" "$STATUS"
    
done
unset IFS
echo "------------------------------------------------------------------------------------------------------"
