#!/bin/bash

G='\033[0;32m'; R='\033[0;31m'; B='\033[0;34m'; NC='\033[0m'

echo -e "${B}=== OpenWrt V2Ray Checker (Fix v3) ===${NC}"
read -p "Вставьте ссылку: " URL

# Функция для получения IP
resolve_ip() {
    local host="$1"
    # Если это IP
    if echo "$host" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$host"
    else
        # nslookup в OpenWrt специфичен
        nslookup "$host" 2>/dev/null | awk '/^Address: / { print $2 }' | grep -v ":" | tail -n1
    fi
}

echo -ne "${B}Скачивание... ${NC}"
RAW=$(curl -sL -k --connect-timeout 10 "$URL")

if [[ -z "$RAW" ]]; then
    echo -e "${R}Пусто!${NC}"
    exit 1
fi
echo -e "${G}OK (${#RAW} байт)${NC}"

# === БЛОК ДЕКОДИРОВАНИЯ (ИСПРАВЛЕННЫЙ) ===
# Проверяем, закодирован ли файл (нет явных ссылок vless/vmess)
if ! echo "$RAW" | grep -qE "vless://|vmess://|trojan://|ss://"; then
    echo -ne "${B}Декодирование Base64... ${NC}"
    
    # 1. Убираем пробелы и переносы
    CLEAN=$(echo "$RAW" | tr -d '\n\r ')
    
    # 2. Заменяем URL-safe символы (- и _) на стандартные (+ и /)
    # ИСПОЛЬЗУЕМ SED ВМЕСТО TR, чтобы избежать ошибки "unrecognized option"
    CLEAN=$(echo "$CLEAN" | sed 's/-/+/g' | sed 's/_/\//g')

    # 3. Добавляем паддинг (=), если длина не кратна 4
    LEN=${#CLEAN}
    MOD=$((LEN % 4))
    if [ $MOD -eq 2 ]; then CLEAN="${CLEAN}=="; fi
    if [ $MOD -eq 3 ]; then CLEAN="${CLEAN}="; fi

    # 4. Декодируем
    DECODED=$(echo "$CLEAN" | base64 -d 2>/dev/null)
    
    # Если base64 не сработал, вернем исходник (вдруг это просто список IP)
    if [[ -z "$DECODED" ]]; then
        TEXT="$RAW"
        echo -e "${R}Ошибка декодирования (пробуем как текст)${NC}"
    else
        TEXT="$DECODED"
        echo -e "${G}OK${NC}"
    fi
else
    TEXT="$RAW"
fi
# ==========================================

echo -e "${B}Парсинг узлов...${NC}"
# Ищем всё, что похоже на домен или IP
# Исключаем мусорные слова, характерные для конфигов (log, dns, routing и т.д.)
HOSTS=$(echo "$TEXT" | grep -oE '[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}' | grep -vE '^(vless|vmess|trojan|ss|tcp|udp|http|https|www|google|github|cloudflare|microsoft|instagram|facebook|telegram|whatsapp|twitter|youtube|netflix|disney|hbo|prime|apple|amazonaws|azure|digitalocean|oracle|alibaba|tencent|baidu|yandex|mail|vk|ok|dzen|rutube|tiktok|twitch|steam|epicgames|origin|uplay|blizzard|riotgames|gog|itch|discord|slack|skype|zoom|teams|webex|meet|jitsi|signal|viber|threema|wire|wickr|session|matrix|element|rocket|mattermost|zulip|irc|xmpp|jabber|mumble|teamspeak|ventrilo|raidcall|curse|curseforge|overwolf|faceit|esea|battlefy|challonge|smashgg|startgg|toornament|binarybeast|battlefly|img|png|jpg|jpeg|gif|css|js|json|html|xml|php|asp|aspx|jsp|do|action|cgi|pl|py|rb|sh|bat|cmd|exe|msi|apk|ipa|dmg|iso|zip|rar|7z|tar|gz|bz2|xz|zst|lz4|lzh|arj|cab|deb|rpm|jar|war|ear|sar|nar|kar|gar|par|xar|dar|cpio|shar|lshar|gshar|mshar|ashar|zshar|sharutils|uudecode|b64decode|base64|uuencode|b64encode|openssl|gpg|pgp|ssh|scp|sftp|ftp|telnet|rsh|rlogin|rexec|rcp|rsync|git|svn|hg|bzr|cvs|rcs|sccs|bk|bitkeeper|tla|arch|monotone|darcs|fossil|veracity|plastic|plasticscm|accurev|clearcase|synergy|cm|cmvc|cm synergy|pvcs|vm|vms|vmanager|harvest|dimensions|starteam|mks|integrity|perforce|p4|helix|bitbucket|gitlab|gitea|gogs|phabricator|kallithea|rhodecode|tfs|vsts|ado|azure devops|jira|confluence|bamboo|crucible|fisheye|upsource|youtrack|teamcity|hub|jetbrains|idea|clion|pycharm|webstorm|phpstorm|rubymine|appcode|datagrip|goland|rider|mps|android studio|xcode|visual studio|vscode|sublime|atom|brackets|notepad|vim|emacs|nano|pico|ed|sed|awk|grep|find|locate|which|whereis|whatis|man|info|help|alias|unalias|export|unset|set|env|printenv|echo|printf|read|readlink|realpath|basename|dirname|stat|touch|mkdir|rmdir|rm|mv|cp|ln|link|unlink|chmod|chown|chgrp|umask|useradd|usermod|userdel|groupadd|groupmod|groupdel|passwd|chage|chfn|chsh|su|sudo|doas|visudo|id|who|w|users|last|lastb|lastlog|wall|write|mesg|talk|uptime|proc|sys|dev|run|tmp|var|etc|usr|bin|sbin|lib|lib64|opt|mnt|media|srv|home|root|boot)$' | sort -u)

# Добавляем IP адреса напрямую (если они есть в конфиге)
IPS=$(echo "$TEXT" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | grep -vE '^(127\.|10\.|172\.|192\.168\.|0\.)')

ALL_NODES="$HOSTS $IPS"
UNIQUE_NODES=$(echo "$ALL_NODES" | tr ' ' '\n' | sort -u | grep -v "^$")

if [[ -z "$UNIQUE_NODES" ]]; then
    echo -e "${R}Узлы не найдены. Возможно формат подписки нестандартный.${NC}"
    exit 1
fi

printf "\n%-25s | %-15s | %-6s\n" "Хост" "IP" "Статус"
echo "--------------------------------------------------------"

for node in $UNIQUE_NODES; do
    # Пытаемся резолвить
    IP=$(resolve_ip "$node")
    
    if [[ -z "$IP" ]]; then
        continue # Пропускаем, если DNS не ответил
    fi

    # Проверка порта 443 через netcat (nc)
    # -z: сканирование, -w 2: таймаут 2 сек
    if nc -z -w 2 "$IP" 443 2>/dev/null; then
        echo -e "${G}%-25.25s | %-15s | OPEN${NC}" "$node" "$IP"
    else
        echo -e "${R}%-25.25s | %-15s | FAIL${NC}" "$node" "$IP"
    fi
done
echo ""
EOF
