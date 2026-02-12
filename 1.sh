#!/bin/bash

# Цвета
G='\033[0;32m'
R='\033[0;31m'
Y='\033[1;33m'
NC='\033[0m'

URL="$1"
# Если аргумента нет, просим ввести
if [[ -z "$URL" ]]; then
    echo -e "${Y}=== Xray TCP/SSL Checker (OpenWrt) ===${NC}"
    read -p "Ссылка: " URL
fi

[ -z "$URL" ] && exit 1

# Функция резолва (DNS Google)
resolve_ip() {
    local host="$1"
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
    else
        nslookup "$host" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
    fi
}

echo -ne "Скачивание списка... "
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo -e "${R}Ошибка скачивания!${NC}"; exit 1;
fi
echo -e "${G}OK${NC}"

# Очистка и извлечение
CLEAN=$(echo "$RAW" | sed ':a;N;$!ba;s/\n//g' | sed 's/\r//g' | sed 's/-/+/g' | sed 's/_/\//g')

# Декодинг (если нужно)
if echo "$RAW" | grep -q "vless://"; then
    TEXT="$RAW"
else
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    TEXT="${DECODED:-$RAW}"
fi

# Поиск хостов (фильтр мусора)
NODES=$(echo "$TEXT" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -vE '^(vless|vmess|trojan|ss|http|https|tcp|udp|google|github|cloudflare|mozilla|android|apple|microsoft|windows|linux|curl|body|html|div|span|title|head|meta|link|script|true|false|null|ozon|vk|userapi|tradingview)$' | sort -u)

# Фильтр локальных IP
FINAL_LIST=""
for node in $NODES; do
    if echo "$node" | grep -qE '^192\.168\.|^127\.|^10\.|^0\.'; then continue; fi
    FINAL_LIST+="$node "
done

COUNT=$(echo "$FINAL_LIST" | wc -w)
echo -e "${G}Найдено серверов: $COUNT${NC}"
echo "----------------------------------------------------------------"
echo -e "Хост                         | IP              | SSL/TCP"
echo "----------------------------------------------------------------"

for host in $FINAL_LIST; do
    IP=$(resolve_ip "$host")
    
    if [[ -z "$IP" ]]; then
        echo -e "${host} | ??? | DNS Error"
        continue
    fi

    # === САМОЕ ГЛАВНОЕ: ПРОВЕРКА CURL ===
    # -I (только заголовки)
    # -k (игнорировать ошибки сертификата - нам важен сам факт соединения)
    # --connect-timeout 3 (если за 3 сек нет ответа - блокировка)
    # Мы стучимся прямо по IP, чтобы исключить DNS-фокусы
    
    if curl -I -k --connect-timeout 3 "https://$IP" >/dev/null 2>&1; then
        # Если curl вернул 0 (ОК), значит Handshake прошел
        echo -e "${host} | ${IP} | ${G}ALIVE (Работает)${NC}"
    else
        # Если таймаут или сброс
        echo -e "${host} | ${IP} | ${R}BLOCKED (РКН)${NC}"
    fi
done
echo ""
EOF

chmod +x /usr/bin/xcheck
