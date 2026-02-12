#!/bin/bash

# Цвета
G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; NC='\033[0m'

echo -e "${B}=== OpenWrt V2Ray/Xray Checker ===${NC}"
read -p "Вставьте ссылку на подписку: " URL

# Функция для получения IP через nslookup (адаптирована для BusyBox)
resolve_ip() {
    local host="$1"
    # Если это уже IP - возвращаем его
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "$host"
        return
    fi
    # Пытаемся резолвить. Ищем строку с "Address" и берем последний IP (обычно IPv4)
    nslookup "$host" 2>/dev/null | awk '/Address/ { print $3 }' | grep -v ":" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
}

# 1. Скачивание
echo -ne "${B}Скачивание... ${NC}"
# Используем -k (insecure) на случай проблем с SSL и User-Agent от Chrome
RAW_DATA=$(curl -sL -k -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" --connect-timeout 10 "$URL")

if [[ -z "$RAW_DATA" ]]; then
    echo -e "${R}Ошибка! Пустой ответ.${NC}"
    echo "Проверьте ссылку или интернет на роутере (ping 8.8.8.8)."
    exit 1
fi
echo -e "${G}OK (${#RAW_DATA} байт)${NC}"

# 2. Подготовка и Декодирование
# Сначала ищем ссылки в явном виде
NODES=$(echo "$RAW_DATA" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^[:space:]"<>]+')

# Если явных ссылок мало, пробуем декодировать Base64
if [[ -z "$NODES" ]]; then
    echo -ne "${B}Декодирование Base64... ${NC}"
    
    # Очистка мусора и нормализация Base64 (замена -_ на +/)
    CLEAN_B64=$(echo "$RAW_DATA" | tr -d '\n\r ' | tr '-_' '+/')
    
    # Добиваем "=" до кратности 4 (padding), иначе base64 упадет
    REM=$((${#CLEAN_B64} % 4))
    if [ $REM -eq 2 ]; then CLEAN_B64="${CLEAN_B64}=="; fi
    if [ $REM -eq 3 ]; then CLEAN_B64="${CLEAN_B64}="; fi

    # Декодируем (используем coreutils-base64 если есть, или встроенный)
    DECODED=$(echo "$CLEAN_B64" | base64 -d 2>/dev/null)
    
    # Ищем ссылки внутри декодированного
    NODES=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^[:space:]"<>]+')
    
    if [[ -n "$NODES" ]]; then
        echo -e "${G}Успешно${NC}"
    else
        echo -e "${R}Не найдено${NC}"
        # Последний шанс: ищем просто IP/Домены в decoded тексте (для старых форматов)
        NODES=$(echo "$DECODED" | grep -oE '[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | grep -vE 'google|github|cloudflare')
    fi
fi

# 3. Извлечение хостов/IP из ссылок
HOST_LIST=""
for node in $NODES; do
    # Убираем префикс протокола
    noprot=$(echo "$node" | sed -E 's/^(vless|vmess|trojan|ss|ssr):\/\///')
    
    # Парсинг vmess (часто зашифрован еще раз в json base64, но мы ищем адрес "в лоб")
    # Простейший вариант: ищем то, что после @ (vless/trojan) или просто пробуем найти домен
    
    # Попытка вырезать адрес после @ и до :
    addr_part=$(echo "$noprot" | grep -oE '@[a-zA-Z0-9.-]+' | sed 's/@//')
    
    # Если не вышло (vmess), ищем json "add":"..." или "host":"..."
    if [[ -z "$addr_part" ]]; then
        # Это хак для vmess, раскодировать каждую строку долго. 
        # Мы просто поищем домены в исходном декодированном тексте ранее.
        continue 
    fi
    HOST_LIST+="$addr_part "
done

# Если список пуст, берем "грязный" список доменов из текста
if [[ -z "$HOST_LIST" ]]; then
    HOST_LIST=$(echo "$DECODED" "$RAW_DATA" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(null|true|false|www|api|cdn|http|https|github|google|cloudflare|nginx|title|body|center|hr|html|div|span|class)$' | sort -u)
fi

# 4. Проверка
echo -e "\n${B}==> Начинаем проверку доступности <==${NC}"
printf "%-20s | %-15s | %-10s | %s\n" "Хост/Домен" "IP Адрес" "Порт 443" "Вердикт"
echo "----------------------------------------------------------------"

# Убираем дубликаты
UNIQUE_HOSTS=$(echo "$HOST_LIST" | tr ' ' '\n' | sort -u | grep -v "^$")

if [[ -z "$UNIQUE_HOSTS" ]]; then
    echo -e "${R}КРИТИЧЕСКАЯ ОШИБКА: Не удалось извлечь ни одного адреса.${NC}"
    exit 1
fi

for host in $UNIQUE_HOSTS; do
    # Резолвим IP
    IP=$(resolve_ip "$host")
    
    if [[ -z "$IP" ]]; then
        printf "%-20.20s | %-15s | %-10s | %s\n" "$host" "???" "SKIP" "DNS Fail"
        continue
    fi

    # Проверка порта 443 (используем nc так как /dev/tcp может не работать в sh)
    if nc -z -w 2 "$IP" 443 2>/dev/null; then
        STATUS="${G}OPEN${NC}"
        VERDICT="Alive"
    else
        STATUS="${R}FAIL${NC}"
        VERDICT="Blocked/Down"
    fi
    
    printf "%-20.20s | %-15s | %-10s | %s\n" "$host" "$IP" "$STATUS" "$VERDICT"
done
echo ""
EOF
