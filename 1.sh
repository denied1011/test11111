#!/bin/bash

# Цвета для вывода
G='\033[0;32m'
R='\033[0;31m'
NC='\033[0m'

echo -e "=== OpenWrt V2Ray Fix (No-TR version) ==="
read -p "Вставьте ссылку: " URL

# Функция для получения IP (работает на OpenWrt/BusyBox)
get_ip() {
    local host="$1"
    # Если это уже IP
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
    else
        # nslookup для BusyBox
        nslookup "$host" 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
    fi
}

echo -ne "Скачивание... "
# Скачиваем с таймаутом и пропуском проверки SSL (-k)
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo -e "${R}Ошибка: Пустой ответ от сервера.${NC}"
    exit 1
fi
echo -e "${G}OK (${#RAW} байт)${NC}"

# === ИСПРАВЛЕННАЯ ЧАСТЬ (БЕЗ TR) ===
echo -ne "Декодирование... "

# 1. Удаляем переносы строк (используем tr только для удаления, это безопасно)
CLEAN=$(echo "$RAW" | tr -d '\n\r ')

# 2. Заменяем URL-safe символы.
# ВМЕСТО tr '_-' '/+' ИСПОЛЬЗУЕМ SED. Это решает вашу ошибку.
CLEAN=$(echo "$CLEAN" | sed 's/-/+/g' | sed 's/_/\//g')

# 3. Добавляем "padding" (=), если строка не кратна 4
LEN=${#CLEAN}
MOD=$((LEN % 4))
if [ $MOD -eq 2 ]; then CLEAN="${CLEAN}=="; fi
if [ $MOD -eq 3 ]; then CLEAN="${CLEAN}="; fi

# 4. Декодируем
# Пробуем полную версию base64, затем встроенную
if [ -x /usr/bin/base64 ]; then
    DECODED=$(echo "$CLEAN" | /usr/bin/base64 -d 2>/dev/null)
else
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
fi

# Проверка результата
if [[ -n "$DECODED" ]]; then
    echo -e "${G}Успешно${NC}"
    SEARCH_TEXT="$DECODED"
else
    echo -e "${R}Не вышло (пробуем искать в сыром тексте)${NC}"
    SEARCH_TEXT="$RAW"
fi

# === ПОИСК СЕРВЕРОВ ===
echo "Поиск узлов..."

# Ищем строки, похожие на домены или IP
NODES=$(echo "$SEARCH_TEXT" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -vE '^(vless|vmess|trojan|ss|tcp|udp|http|https|www|google|github|cloudflare|mozilla|android|apple|microsoft|windows|linux|curl|body|html|div|span|title|head|meta|link|script)$' | sort -u)

# Фильтруем пустые строки и локальные IP
FINAL_LIST=""
for node in $NODES; do
    if echo "$node" | grep -qE '^192\.168\.|^127\.|^10\.|^0\.'; then continue; fi
    FINAL_LIST+="$node "
done

if [[ -z "$FINAL_LIST" ]]; then
    echo -e "${R}Узлы не найдены!${NC}"
    echo "Возможно, ссылка ведет на страницу с капчей или формат подписки неизвестен."
    exit 1
fi

# === ПРОВЕРКА ===
printf "\n%-25s | %-15s | %s\n" "Хост" "IP" "Статус (Порт 443)"
echo "------------------------------------------------------------"

for host in $FINAL_LIST; do
    # Получаем IP
    IP=$(get_ip "$host")
    
    if [[ -z "$IP" ]]; then
        printf "%-25.25s | %-15s | %s\n" "$host" "???" "DNS Error"
        continue
    fi

    # Проверяем порт 443 через netcat (nc)
    if nc -z -w 3 "$IP" 443 2>/dev/null; then
        echo -e "${G}%-25.25s | %-15s | OPEN${NC}" "$host" "$IP"
    else
        echo -e "${R}%-25.25s | %-15s | FAIL${NC}" "$host" "$IP"
    fi
done
echo ""
EOF
