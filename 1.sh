#!/bin/bash

# === OpenWrt Xray/V2Ray Checker (GitHub Version) ===
# Адаптирован для: OpenWrt 24.10 / BusyBox
# Возможности: Парсинг HTML, декодирование Base64, проверка SSL Handshake

# Цвета
G='\033[0;32m' # Green
R='\033[0;31m' # Red
Y='\033[1;33m' # Yellow
NC='\033[0m'   # No Color

# 1. Проверка аргументов
URL="$1"
if [[ -z "$URL" ]]; then
    echo -e "${Y}=== Xray Checker (OpenWrt) ===${NC}"
    read -p "Вставьте ссылку: " URL
fi

# Если ссылка пустая - выход
[ -z "$URL" ] && exit 1

# 2. Функция резолва IP (через Google DNS 8.8.8.8)
# Это нужно, чтобы обойти локальные блокировки DNS или кэш роутера
resolve_ip() {
    local host="$1"
    # Если на входе уже IP - возвращаем его
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
    else
        # nslookup для BusyBox (парсим вывод)
        nslookup "$host" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
    fi
}

echo -ne "Скачивание... "
# Скачиваем страницу (прикидываемся браузером Mozilla, чтобы сервер не заблокировал запрос)
# -k : игнорировать ошибки SSL (нам важно скачать контент)
# -L : следовать за редиректами
RAW=$(curl -sL -k --connect-timeout 15 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" "$URL")

if [[ -z "$RAW" ]]; then
    echo -e "${R}Ошибка: Пустой ответ от сервера.${NC}"
    exit 1
fi
echo -e "${G}OK (${#RAW} байт)${NC}"

# === ЛОГИКА ПАРСИНГА ("ТАНК") ===
echo -ne "Поиск узлов... "

# Шаг 1: Ищем явные ссылки (vless://...) в исходном коде
LINKS=$(echo "$RAW" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')

# Шаг 2: Если ссылок нет, пробуем очистить HTML и декодировать Base64
if [[ -z "$LINKS" ]]; then
    # Удаляем все HTML теги (<...>)
    CLEAN_HTML=$(echo "$RAW" | sed 's/<[^>]*>//g')
    
    # Удаляем пробелы и переносы строк
    CLEAN_TEXT=$(echo "$CLEAN_HTML" | tr -d '\n\r ')
    
    # Исправляем URL-safe Base64 символы (- -> +, _ -> /)
    # Используем sed, так как tr в OpenWrt может капризничать
    CLEAN_B64=$(echo "$CLEAN_TEXT" | sed 's/-/+/g' | sed 's/_/\//g')
    
    # Декодируем (пробуем системный base64)
    DECODED=$(echo "$CLEAN_B64" | base64 -d 2>/dev/null)
    
    # Ищем ссылки внутри декодированного текста
    LINKS=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^"'\''<>[:space:]]+')
    
    # Сохраняем текст для поиска доменов (на случай провала)
    SEARCH_POOL="$RAW $DECODED"
else
    SEARCH_POOL="$RAW"
fi

# Шаг 3: Извлекаем домены (Хосты)
HOSTS=""

# Если нашли ссылки - парсим их
if [[ -n "$LINKS" ]]; then
    for link in $LINKS; do
        # Убираем протокол (vless://)
        NOPROTO=$(echo "$link" | sed -E 's/^[a-z]+:\/\///')
        
        # Попытка 1: Найти домен между @ и : (стандарт vless)
        D=$(echo "$NOPROTO" | grep -oE '@[a-zA-Z0-9.-]+' | sed 's/@//')
        
        # Попытка 2: Если не вышло (vmess), ищем просто строку похожую на домен
        if [[ -z "$D" ]]; then
             D=$(echo "$link" | grep -oE '[a-zA-Z0-9.-]+\.[a-z]{2,}')
        fi
        HOSTS+="$D "
    done
else
    # Если ссылок нет вообще - ищем любые домены в тексте (Грубая сила)
    HOSTS=$(echo "$SEARCH_POOL" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}')
fi

# Шаг 4: Фильтрация мусора
# Удаляем пустые строки, локальные IP, и слова-исключения (html теги, google, vk и т.д.)
FINAL_LIST=$(echo "$HOSTS" | tr ' ' '\n' | sort -u | grep -vE "^$|127\.0|192\.168|10\.|0\.0|html|body|div|span|href|src|style|width|height|color|font|script|link|meta|head|title|google|github|cloudflare|vk\.com|ozon|yandex|mail|userapi|tradingview")

COUNT=$(echo "$FINAL_LIST" | wc -w)

if [ "$COUNT" -eq 0 ]; then
    echo -e "${R}Ничего не найдено.${NC}"
    echo "Возможные причины:"
    echo "1. Ссылка ведет на страницу логина/капчи."
    echo "2. Подписка истекла."
    echo "3. Формат кодировки неизвестен скрипту."
    exit 1
fi

echo -e "${G}Найдено хостов: $COUNT${NC}"
echo "--------------------------------------------------------"
printf "%-25s | %-15s | %s\n" "Хост" "IP" "Статус (HTTPS)"
echo "--------------------------------------------------------"

# Шаг 5: Проверка доступности
for host in $FINAL_LIST; do
    # Пропускаем слова короче 4 символов (мусор)
    if [ ${#host} -lt 4 ]; then continue; fi

    # Резолвим IP
    IP=$(resolve_ip "$host")
    
    # Если DNS не ответил
    if [[ -z "$IP" ]]; then
        # printf "%-25.25s | %-15s | %s\n" "$host" "???" "DNS Error"
        continue
    fi

    # Проверка CURL (SSL Handshake)
    # Мы проверяем именно HTTPS порт 443. 
    # Если РКН блокирует - будет таймаут или ошибка соединения.
    if curl -I -k --connect-timeout 2 "https://$IP" >/dev/null 2>&1; then
        STATUS="${G}ALIVE${NC}"
    else
        STATUS="${R}BLOCKED${NC}"
    fi
    
    printf "%-25.25s | %-15s | %s\n" "$host" "$IP" "$STATUS"
done

echo ""
