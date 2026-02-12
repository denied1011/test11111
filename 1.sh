#!/bin/bash

# === OpenWrt Checker v2.0 (С Именами) ===
# Поддержка: Названия (Remarks), IP, SNI, Статусы РКН

# Цвета
G='\033[0;32m' # Зеленый
R='\033[0;31m' # Красный
Y='\033[1;33m' # Желтый
B='\033[0;34m' # Синий
NC='\033[0m'   # Сброс

# 1. Принимаем ссылку
URL="$1"
if [[ -z "$URL" ]]; then
    read -p "Вставьте ссылку: " URL
fi
[ -z "$URL" ] && exit 1

# Функция DNS (Google DNS)
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

# Функция декодирования URL (например %20 -> пробел)
urldecode() {
    echo "$1" | sed 's/%20/ /g' | sed 's/%[0-9A-Fa-f]\{2\}//g' # Простое очищение
}

echo -ne "Скачивание... "
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo "Ошибка (Пустой ответ)"; exit 1
fi
echo "OK (${#RAW} байт)"

# === ПОДГОТОВКА ДАННЫХ ===
echo "Обработка подписки..."

# 1. Сначала пробуем найти ссылки в явном виде
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')

# 2. Если пусто - декодируем Base64
if [[ -z "$LINKS" ]]; then
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ' | sed 's/-/+/g; s/_/\//g')
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
fi

if [[ -z "$LINKS" ]]; then
    echo -e "${R}Ссылки не найдены!${NC} Возможно, неизвестный формат."
    exit 1
fi

COUNT=$(echo "$LINKS" | wc -l)
echo "Найдено узлов: $COUNT"

# === ВЫВОД ТАБЛИЦЫ ===
echo "--------------------------------------------------------------------------------"
printf "%-15s | %-20s | %-15s | %s\n" "ИМЯ" "ХОСТ (SNI)" "IP АДРЕС" "СТАТУС"
echo "--------------------------------------------------------------------------------"

# Разделитель для цикла for (по строкам)
IFS=$'\n'
for link in $LINKS; do
    NAME="Без имени"
    HOST=""
    
    # Определяем протокол
    if echo "$link" | grep -q "^vmess://"; then
        # --- VMESS PARSING ---
        # Убираем префикс
        B64_JSON=$(echo "$link" | sed 's/vmess:\/\///')
        # Декодируем JSON
        JSON=$(echo "$B64_JSON" | base64 -d 2>/dev/null)
        
        # Вытаскиваем "ps" (Имя) и "add" (Хост) грубым grep-ом (т.к. jq может не быть)
        NAME=$(echo "$JSON" | grep -oE '"ps":"[^"]+"' | cut -d'"' -f4)
        HOST=$(echo "$JSON" | grep -oE '"add":"[^"]+"' | cut -d'"' -f4)
        
        # Если хоста нет, ищем "host"
        if [[ -z "$HOST" ]]; then
            HOST=$(echo "$JSON" | grep -oE '"host":"[^"]+"' | cut -d'"' -f4)
        fi
        
    elif echo "$link" | grep -qE "^(vless|trojan|ss)://"; then
        # --- VLESS/TROJAN PARSING ---
        # Формат: protocol://uuid@host:port?params#Name
        
        # 1. Достаем Имя (всё после #)
        if echo "$link" | grep -q "#"; then
            RAW_NAME=$(echo "$link" | sed 's/.*#//')
            NAME=$(urldecode "$RAW_NAME")
        fi
        
        # 2. Достаем Хост
        # Убираем всё после ? или #
        CLEAN_LINK=$(echo "$link" | cut -d'?' -f1 | cut -d'#' -f1)
        # Убираем протокол
        NO_PROTO=$(echo "$CLEAN_LINK" | sed -E 's/^[a-z]+:\/\///')
        # Берем всё между @ и :
        HOST=$(echo "$NO_PROTO" | sed 's/.*@//' | cut -d':' -f1)
    fi

    # --- ФИЛЬТРАЦИЯ И ПРОВЕРКА ---
    
    # Если имя пустое
    [[ -z "$NAME" ]] && NAME="NoName"
    
    # Если хост пустой или локальный - пропускаем
    if [[ -z "$HOST" ]] || echo "$HOST" | grep -qE '^127\.|^192\.168\.|^10\.|^0\.'; then
        continue
    fi
    
    # Обрезаем слишком длинные имена для красоты таблицы
    D_NAME="${NAME:0:15}"
    D_HOST="${HOST:0:20}"
    
    # Резолв IP
    IP=$(get_ip "$HOST")
    
    if [[ -z "$IP" ]]; then
        printf "%-15s | %-20s | %-15s | %b\n" "$D_NAME" "$D_HOST" "???" "${Y}DNS Error${NC}"
        continue
    fi
    
    # Проверка HTTPS (CURL)
    if curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1; then
        STATUS="${G}Активно${NC}"
    else
        STATUS="${R}Блок РКН${NC}"
    fi
    
    # Вывод строки
    printf "%-15s | %-20s | %-15s | %b\n" "$D_NAME" "$D_HOST" "$IP" "$STATUS"
    
done
unset IFS
echo "--------------------------------------------------------------------------------"
