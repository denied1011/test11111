#!/bin/bash

# === OpenWrt Одноразовый Чекер ===
# Русский интерфейс + Статусы РКН

# Цвета
G='\033[0;32m' # Зеленый
R='\033[0;31m' # Красный
NC='\033[0m'   # Сброс цвета

# 1. Принимаем ссылку
URL="$1"
# Если не передали аргументом, спрашиваем
if [[ -z "$URL" ]]; then
    read -p "Вставьте ссылку: " URL
fi

# Если пусто - выход
[ -z "$URL" ] && exit 1

# Функция DNS (используем Google DNS 8.8.8.8 для обхода локальных подмен)
get_ip() {
    nslookup "$1" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
}

echo -ne "Скачивание... "
# Скачиваем с User-Agent браузера
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo "Ошибка (Пустой ответ)"; exit 1
fi
echo "OK (${#RAW} байт)"

# === ПАРСИНГ ДАННЫХ ===
echo "Поиск узлов..."

# 1. Ищем явные ссылки (vless://...)
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')

# 2. Если пусто, чистим HTML и декодируем Base64
if [[ -z "$LINKS" ]]; then
    # Удаляем HTML теги
    CLEAN=$(echo "$RAW" | sed 's/<[^>]*>//g' | tr -d '\n\r ')
    # Исправляем спецсимволы Base64 (+ и /)
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
        # Ищем домен между @ и : (стандарт vless)
        D=$(echo "$NOPROTO" | grep -oE '@[a-zA-Z0-9.-]+' | sed 's/@//')
        # Если не вышло (vmess), ищем просто паттерн домена
        if [[ -z "$D" ]]; then D=$(echo "$link" | grep -oE '[a-zA-Z0-9.-]+\.[a-z]{2,}'); fi
        HOSTS+="$D "
    done
else
    # Резервный метод: просто ищем любые домены в тексте
    HOSTS=$(echo "$SEARCH_TEXT" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}')
fi

# 4. Фильтр мусора (исключаем google, vk, ozon и локальные IP)
FINAL_LIST=$(echo "$HOSTS" | tr ' ' '\n' | sort -u | grep -vE "^$|127\.0|192\.168|10\.|0\.0|html|body|href|src|style|width|height|google|github|cloudflare|vk\.com|ozon|yandex|mail|userapi|tradingview")

COUNT=$(echo "$FINAL_LIST" | wc -w)
if [ "$COUNT" -eq 0 ]; then
    echo "Узлы не найдены."; exit 1
fi

echo "Найдено: $COUNT шт."
echo "--------------------------------------------------------"
printf "%-25s | %-15s | %s\n" "Хост" "IP" "Статус"
echo "--------------------------------------------------------"

for host in $FINAL_LIST; do
    # Пропускаем короткий мусор
    if [ ${#host} -lt 4 ]; then continue; fi
    
    # Резолв IP
    IP=$(get_ip "$host")
    if [[ -z "$IP" ]]; then continue; fi

    # Проверка CURL (SSL Handshake / HTTPS порт 443)
    if curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1; then
        STATUS="${G}Активно${NC}"
    else
        STATUS="${R}Заблокировано РКН${NC}"
    fi
    
    # ВАЖНО: Используем %b для корректного вывода цветов
    printf "%-25.25s | %-15s | %b\n" "$host" "$IP" "$STATUS"
done
