cat << 'EOF' > /tmp/check_fix.sh && chmod +x /tmp/check_fix.sh && bash /tmp/check_fix.sh && rm /tmp/check_fix.sh
#!/bin/bash
# TC|_|Y v0.1.4-OpenWrt - Fix for routers (nslookup + sequential check)

G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; NC='\033[0m'

read -p "Укажите ссылку или домен: " INPUT

# Функция резолва через nslookup (так как host нет по умолчанию)
get_ip() {
    local target=$(echo "$1" | tr -d '"'\''/ ')
    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$target"
    else
        # Используем nslookup и парсим вывод
        nslookup "$target" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | tail -n1 | grep -v "0.0.0.0"
    fi
}

echo -ne "${B}==> Получение данных... ${NC}"

if [[ $INPUT == http* ]]; then
    # Пробуем скачать
    BODY=$(curl -sL -k --connect-timeout 15 "$INPUT")
    
    if [[ -z "$BODY" ]]; then
        echo -e "${R}Ошибка: Пустой ответ от сервера. Проверьте ссылку.${NC}"
        exit 1
    fi
    echo -e "${G}DONE (${#BODY} байт)${NC}"

    NODES_LIST=""
    # Поиск ссылок
    NODES_LIST+=$(echo "$BODY" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^@]+@[^:/]+' | sed -E 's/.*@//' | cut -d':' -f1)
    NODES_LIST+=$'\n'
    
    # Декод Base64
    DECODED=$(echo "$BODY" | tr '_-' '/+' | base64 -d 2>/dev/null)
    if [[ -n "$DECODED" ]]; then
        NODES_LIST+=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^@]+@[^:/]+' | sed -E 's/.*@//' | cut -d':' -f1)
        NODES_LIST+=$'\n'
        NODES_LIST+=$(echo "$DECODED" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(null|true|false)$')
    fi
    
    # Грубый поиск IP/Доменов
    NODES_LIST+=$(echo "$BODY" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(null|true|false|www|api|cdn|http|https|github|google|cloudflare|nginx|title|body|center|hr|html|div|span|class)$')
    NODES_LIST+=$'\n'
    NODES_LIST+=$(echo "$BODY" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -vE '^(0\.0\.0\.0|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)')
    
    NODES_LIST=$(echo "$NODES_LIST" | sort -u | grep -v '^$')
else
    # Режим домена
    echo -ne "${B}Разведка домена... ${NC}"
    NODES_LIST=$(curl -s "https://crt.sh/?q=%25.$INPUT&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr ' ' '\n' | sort -u)
    [[ -z "$NODES_LIST" || "$NODES_LIST" == "null" ]] && NODES_LIST="$INPUT"
    echo -e "${G}OK${NC}"
fi

echo -e "${B}==> Резолв DNS...${NC}"
declare -A DNS_MAP; FINAL_IPS=""
for d in $NODES_LIST; do
    IP=$(get_ip "$d")
    if [[ ! -z "$IP" && "$IP" != "127.0.0.1" ]]; then
         DNS_MAP[$IP]=$d
         FINAL_IPS+="$IP "
         # echo -n "." # раскомментируйте для прогресс-бара
    fi
done
echo ""

NODES=($(echo "$FINAL_IPS" | tr ' ' '\n' | sort -u))

if [[ ${#NODES[@]} -eq 0 ]]; then
    echo -e "${R}Ошибка: Узлы не найдены после фильтрации.${NC}"
    echo "Возможно, скрипт не смог распознать формат подписки или DNS не работает."
    exit 1
fi

printf "\n${B}%-15s | %-25s | %-6s | %-4s | %-8s | %s${NC}\n" "IP" "Хост" "Статус" "Гео" "ASN" "Вердикт"
echo "----------------------------------------------------------------------------------"

# Функция проверки одного узла
audit_node() {
    local ip=$1
    local name="${DNS_MAP[$ip]}"
    
    # Проверка порта (nc быстрее и есть в openwrt, но проверим через /dev/tcp для совместимости с bash)
    if (echo >/dev/tcp/"$ip"/443) &>/dev/null; then
        ST="OK"
    else
        ST="BAN"
    fi
    
    # Инфо об IP
    RAW=$(curl -s --connect-timeout 2 "http://ip-api.com/csv/$ip?fields=countryCode,as")
    CO=$(echo "$RAW" | cut -d',' -f1 | tr -d '"')
    AS=$(echo "$RAW" | cut -d',' -f2 | grep -oE 'AS[0-9]+' | head -n1)
    
    [[ -z "$CO" ]] && CO="??"
    [[ -z "$AS" ]] && AS="AS?"
    
    if [[ "$ST" == "OK" ]]; then
        C=$G; VERDICT="Alive"
    else
        C=$R; VERDICT="Blocked"
    fi
    
    printf "${C}%-15s | %-25.25s | %-6s | [%-2s] | %-8s | %s${NC}\n" "$ip" "$name" "$ST" "$CO" "$AS" "$VERDICT"
}

# Последовательный запуск (без xargs -P, чтобы не крашить роутер)
for ip in "${NODES[@]}"; do
    audit_node "$ip"
done

echo ""
EOF
