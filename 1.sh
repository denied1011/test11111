#!/bin/bash

# === OpenWrt Checker v4.0 (Byte-Level Fix) ===
# Исправлено: Кириллица не бьется, Эмодзи удаляются байтовыми паттернами.
# Не требует дополнительных пакетов.

G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; NC='\033[0m'

URL="$1"
[[ -z "$URL" ]] && read -p "Вставьте ссылку: " URL
[[ -z "$URL" ]] && exit 1

# DNS
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

# URL Decode
urldecode() {
    echo "$1" | sed 's/%20/ /g' | sed 's/%[0-9A-Fa-f]\{2\}//g'
}

echo -ne "Скачивание... "
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")
[[ -z "$RAW" ]] && { echo "Ошибка"; exit 1; }
echo "OK"

# Парсинг
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
if [[ -z "$LINKS" ]]; then
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ' | sed 's/-/+/g; s/_/\//g')
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
fi
[[ -z "$LINKS" ]] && { echo "Узлы не найдены"; exit 1; }

# Шапка
echo "----------------------------------------------------------------------------------------------------"
printf "| %-30s | %-22s | %-15s | %b\n" "ИМЯ" "SNI / ХОСТ" "IP АДРЕС" "СТАТУС"
echo "----------------------------------------------------------------------------------------------------"

IFS=$'\n'
for link in $LINKS; do
    NAME="Node"
    HOST=""
    
    # 1. Извлечение грязного имени и хоста
    if echo "$link" | grep -q "^vmess://"; then
        JSON=$(echo "$link" | sed 's/vmess:\/\///' | base64 -d 2>/dev/null)
        NAME=$(echo "$JSON" | grep -oE '"ps":"[^"]+"' | cut -d'"' -f4)
        HOST=$(echo "$JSON" | grep -oE '"add":"[^"]+"' | cut -d'"' -f4)
        [[ -z "$HOST" ]] && HOST=$(echo "$JSON" | grep -oE '"host":"[^"]+"' | cut -d'"' -f4)
    elif echo "$link" | grep -qE "^(vless|trojan|ss)://"; then
        [[ "$link" == *"#"* ]] && NAME=$(urldecode "$(echo "$link" | sed 's/.*#//')")
        HOST=$(echo "$link" | cut -d'?' -f1 | cut -d'#' -f1 | sed -E 's/^[a-z]+:\/\///' | sed 's/.*@//' | cut -d':' -f1)
    fi

    # Фильтр пустых
    [[ -z "$HOST" ]] || echo "$HOST" | grep -qE '^127\.|^192\.168\.|^10\.' && continue

    # === ГЛАВНОЕ ИСПРАВЛЕНИЕ (ОЧИСТКА) ===
    # Мы удаляем байтовые последовательности, которые НЕ являются ASCII или Кириллицей.
    
    # 1. Удаляем 4-байтовые последовательности (Эмодзи: F0-F7 + хвосты)
    # В octal: \360-\367
    CLEAN_NAME=$(echo "$NAME" | sed 's/[\360-\367][\200-\277][\200-\277][\200-\277]//g')
    
    # 2. Удаляем 3-байтовые последовательности (Иероглифы, стрелочки, символы: E0-EF + хвосты)
    # В octal: \340-\357
    CLEAN_NAME=$(echo "$CLEAN_NAME" | sed 's/[\340-\357][\200-\277][\200-\277]//g')
    
    # 3. Чистим остальной визуальный мусор (вертикальные черты, лишние знаки)
    # Но НЕ трогаем диапазон букв, чтобы не сломать кириллицу.
    CLEAN_NAME=$(echo "$CLEAN_NAME" | tr -d '|@#')
    
    # 4. Убираем пробелы по краям
    CLEAN_NAME=$(echo "$CLEAN_NAME" | sed 's/^ *//;s/ *$//')
    [[ -z "$CLEAN_NAME" ]] && CLEAN_NAME="Node"

    # Резолв и Проверка
    IP=$(get_ip "$HOST")
    if [[ -z "$IP" ]]; then
        printf "| %-30.30s | %-22.22s | %-15s | %b\n" "$CLEAN_NAME" "$HOST" "???" "${Y}DNS Error${NC}"
        continue
    fi
    
    curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1 && STATUS="${G}Активно${NC}" || STATUS="${R}Блок РКН${NC}"
    
    # Печать
    printf "| %-30.30s | %-22.22s | %-15s | %b\n" "$CLEAN_NAME" "$HOST" "$IP" "$STATUS"
    
done
unset IFS
echo "----------------------------------------------------------------------------------------------------"
