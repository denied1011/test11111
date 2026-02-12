#!/bin/bash

# Цвета
G='\033[0;32m'; R='\033[0;31m'; NC='\033[0m'

echo -e "${G}=== OpenWrt Checker (No-TR / Direct DNS) ===${NC}"
read -p "Ссылка: " URL

# Функция резолва напрямую через Google DNS (обход локального DNS/Подкопа)
resolve_ip() {
    local host="$1"
    # Если это IP - возвращаем как есть
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
    else
        # Запрос к 8.8.8.8, тайм-аут 2 сек
        nslookup "$host" 8.8.8.8 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
    fi
}

echo -ne "Скачивание... "
# Скачиваем с User-Agent браузера
RAW=$(curl -sL -k --connect-timeout 10 -A "Mozilla/5.0" "$URL")

if [[ -z "$RAW" ]]; then
    echo -e "${R}ОШИБКА: Пустой ответ!${NC}"
    echo "Curl не смог скачать данные. Проверьте интернет или ссылку."
    exit 1
fi
echo -e "${G}OK (${#RAW} байт)${NC}"

# === ОТЛАДКА: ЧТО МЫ СКАЧАЛИ? ===
echo "Начало файла: ${RAW:0:60}..." 
# ================================

echo -ne "Обработка данных... "

# 1. Чистим текст (sed вместо tr)
# Удаляем переносы строк
CLEAN=$(echo "$RAW" | sed ':a;N;$!ba;s/\n//g')
# Заменяем URL-safe символы (+ и /)
CLEAN=$(echo "$CLEAN" | sed 's/-/+/g' | sed 's/_/\//g')

# 2. Декодируем
# Пробуем coreutils-base64 (он лучше), если нет - встроенный
if [ -f /usr/bin/base64 ]; then
    DECODED=$(echo "$CLEAN" | /usr/bin/base64 -d 2>/dev/null)
else
    # Добавляем паддинг вручную для BusyBox base64
    LEN=${#CLEAN}
    MOD=$((LEN % 4))
    if [ $MOD -eq 2 ]; then CLEAN="${CLEAN}=="; fi
    if [ $MOD -eq 3 ]; then CLEAN="${CLEAN}="; fi
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
fi

# Если декодирование не дало результата, используем сырой текст
if [[ -z "$DECODED" ]]; then
    WORK_TEXT="$RAW"
else
    WORK_TEXT="$DECODED"
fi

# 3. Парсинг (выдираем всё, что похоже на домен или IP)
# Ищем строки вида example.com или 1.2.3.4
NODES=$(echo "$WORK_TEXT" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -vE '^(vless|vmess|trojan|ss|http|https|tcp|udp|google|github|cloudflare|mozilla|android|apple|microsoft|windows|linux|curl|body|html|div|span|title|head|meta|link|script)$' | sort -u)

if [[ -z "$NODES" ]]; then
    echo -e "${R}Узлы не найдены!${NC}"
    echo "Скрипт не смог найти домены или IP в ответе сервера."
    exit 1
fi
echo -e "${G}Найдено потенциальных узлов: $(echo "$NODES" | wc -l)${NC}"

echo -e "\nПроверка доступности (через Google DNS)..."
printf "%-25s | %-15s | %s\n" "Хост" "IP" "Статус 443"
echo "--------------------------------------------------------"

for node in $NODES; do
    # Пропускаем явно локальные IP
    if echo "$node" | grep -qE '^192\.168\.|^127\.|^10\.'; then continue; fi

    IP=$(resolve_ip "$node")
    
    if [[ -z "$IP" ]]; then
        printf "%-25.25s | %-15s | %s\n" "$node" "???" "DNS Error"
        continue
    fi

    # Проверка порта
    if nc -z -w 3 "$IP" 443 2>/dev/null; then
        echo -e "${G}%-25.25s | %-15s | OPEN${NC}" "$node" "$IP"
    else
        echo -e "${R}%-25.25s | %-15s | FAIL${NC}" "$node" "$IP"
    fi
done
echo ""
EOF
