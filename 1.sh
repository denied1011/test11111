#!/bin/bash
# TC|_|Y v0.1.3.9 - Упрощённая версия, фикс нулевых байтов

G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; Y='\033[1;33m'; NC='\033[0m'

read -p "Укажите ссылку или домен: " INPUT

get_ip() {
    local target=$(echo "$1" | tr -d '"'\''/ ')
    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        echo "$target"
    else
        host -t A "$target" 2>/dev/null | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -n1
    fi
}

if [[ $INPUT == http* ]]; then
    echo -ne "${B}==> Получение данных... ${NC}"
    
    # Основной запрос
    BODY=$(curl -sL -k -A "Happ/2.0.5/Linux" --connect-timeout 15 --max-time 30 "$INPUT" 2>/dev/null)
    
    # Если пусто, пробуем с другим UA
    if [[ -z "$BODY" ]]; then
        BODY=$(curl -sL -k -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" --connect-timeout 15 "$INPUT" 2>/dev/null)
    fi
    
    echo -e "${G}DONE${NC}"
    
    NODES_LIST=""
    
    # 1. VLESS/vmess/trojan/SS URL напрямую
    NODES_LIST+=$(echo "$BODY" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^@]+@[^:/]+' | sed -E 's/.*@//' | cut -d':' -f1)
    NODES_LIST+=$'\n'
    
    # 2. Декодируем Base64 и ищем URL
    DECODED=$(echo "$BODY" | tr '_-' '/+' | base64 -d 2>/dev/null)
    if [[ -n "$DECODED" ]]; then
        NODES_LIST+=$(echo "$DECODED" | grep -oE '(vless|vmess|trojan|ss|ssr)://[^@]+@[^:/]+' | sed -E 's/.*@//' | cut -d':' -f1)
        NODES_LIST+=$'\n'
        NODES_LIST+=$(echo "$DECODED" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b')
        NODES_LIST+=$'\n'
        NODES_LIST+=$(echo "$DECODED" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(null|true|false)$')
    fi
    
    # 3. JSON поля
    NODES_LIST+=$(echo "$BODY" | grep -oE '"add"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -oE '"[^"]+"$' | tr -d '"')
    NODES_LIST+=$'\n'
    NODES_LIST+=$(echo "$BODY" | grep -oE '"host"[[:space:]]*:[[:space:]]*"[^"]*"' | grep -oE '"[^"]+"$' | tr -d '"')
    NODES_LIST+=$'\n'
    
    # 4. Домены и IP напрямую из body
    NODES_LIST+=$(echo "$BODY" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(null|true|false|www|api|cdn|http|https|github|google|cloudflare|nginx|title|body|center|hr)$')
    NODES_LIST+=$'\n'
    NODES_LIST+=$(echo "$BODY" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -vE '^(0\.0\.0\.0|127\.|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)')
    
    NODES_LIST=$(echo "$NODES_LIST" | sort -u | grep -v '^$')
    
else
    echo -ne "${B}==> Разведка домена... ${NC}"
    NODES_LIST=$(curl -s --connect-timeout 8 "https://crt.sh/?q=%25.$INPUT&output=json" | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g' | tr ' ' '\n' | sort -u)
    [[ -z "$NODES_LIST" || "$NODES_LIST" == "null" ]] && NODES_LIST="$INPUT"
    echo -e "${G}OK${NC}"
fi

declare -A DNS_MAP; FINAL_IPS=""
for d in $NODES_LIST; do
    IP=$(get_ip "$d")
    [[ ! -z "$IP" && "$IP" != "0.0.0.0" ]] && { DNS_MAP[$IP]=$d; FINAL_IPS+="$IP "; }
done

NODES=($(echo "$FINAL_IPS" | tr ' ' '\n' | sort -u))
[[ ${#NODES[@]} -eq 0 ]] && { echo -e "${R}Ошибка: Узлы не найдены.${NC}"; exit 1; }

printf "\n${B}%-15s | %-30s | %-6s | %-4s | %-10s | %s${NC}\n" "IP Адрес" "Источник / Хост" "Статус" "Гео" "ASN" "Вердикт"
echo "----------------------------------------------------------------------------------------------------------"

audit_node() {
    local ip=$1; local name=$2
    (echo >/dev/tcp/"$ip"/443) &>/dev/null && ST="OK" || ST="BANNED"
    
    RAW=$(curl -s --connect-timeout 3 "http://ip-api.com/csv/$ip?fields=countryCode,as" 2>/dev/null)
    CO=$(echo "$RAW" | cut -d',' -f1 | tr -d '"')
    AS=$(echo "$RAW" | cut -d',' -f2 | tr -d '"')
    
    AS_NUM=$(echo "$AS" | grep -oE '^AS[0-9]+')
    [[ -z "$CO" ]] && CO="??"
    [[ -z "$AS_NUM" ]] && AS_NUM="AS???"
    
    VERDICT=$([[ "$ST" == "OK" ]] && echo "Alive / Pass" || echo "TSP_DROP / Blocked")
    
    echo "$ip|$name|$ST|$CO|$AS_NUM|$VERDICT"
}

export -f audit_node; export G R B Y NC
for ip in "${NODES[@]}"; do 
    echo "$ip ${DNS_MAP[$ip]}"
done | xargs -P 15 -n 2 bash -c 'audit_node "$0" "$1"' | while IFS='|' read -r ip name st co as verdict; do
    [[ "$st" == "OK" ]] && C=$G || C=$R
    printf "${C}%-15s | %-30.30s | %-6s | [%-2s] | %-10s | %s${NC}\n" "$ip" "$name" "$st" "$co" "$as" "$verdict"
done

echo ""
