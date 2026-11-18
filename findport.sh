#!/usr/bin/env bash
# =============================================================================
#  FindPort - Gerenciador Interativo de Portas e Firewall para Termux (Android)
# =============================================================================
#  Audita portas abertas (TCP e UDP), detecta nível de exposição (Local vs Rede),
#  identifica serviços conhecidos, encerra processos e gerencia bloqueio de portas
#  via iptables (Firewall do Linux/Android), mantendo log de auditoria.
# =============================================================================

# Definir diretório base do script e log de auditoria
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/findport_audit.log"
RULES_FILE="${SCRIPT_DIR}/.findport_rules"

# Cores ANSI
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_RED="\033[1;31m"
C_GREEN="\033[1;32m"
C_YELLOW="\033[1;33m"
C_BLUE="\033[1;34m"
C_MAGENTA="\033[1;35m"
C_CYAN="\033[1;36m"
C_GRAY="\033[0;90m"
C_WHITE="\033[1;37m"

# Processos críticos essenciais do Android / Linux
PROCESSOS_CRITICOS=(
    "init" "zygote" "zygote64" "system_server" "surfaceflinger"
    "vold" "netd" "servicemanager" "hwservicemanager" "vndservicemanager"
    "adbd" "logd" "lmkd" "keystore" "keystore2" "ueventd" "sh" "bash"
)

# Verifica se é root
is_root() {
    [ "$(id -u)" -eq 0 ]
}

# Registra ação no log de auditoria
write_audit_log() {
    local acao="$1"
    local porta="$2"
    local proto="${3:-TCP}"
    local pid="${4:-0}"
    local processo="${5:-N/A}"
    local detalhes="${6:-}"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    
    echo "[$timestamp] [$acao] Proto: $proto | Porta: $porta | PID: $pid | Processo: $processo | $detalhes" >> "$LOG_FILE" 2>/dev/null || true
}

# Dicionário de serviços conhecidos (com adições específicas do Android / Termux)
get_servico_conhecido() {
    local porta="$1"
    case "$porta" in
        21)    echo "FTP (Transferencia de arquivos)" ;;
        22)    echo "SSH (Acesso remoto padrao)" ;;
        53)    echo "DNS (Resolucao de nomes)" ;;
        80)    echo "HTTP (Servidor Web)" ;;
        443)   echo "HTTPS (Web Seguro / SSL)" ;;
        1433)  echo "Microsoft SQL Server" ;;
        1521)  echo "Oracle Database" ;;
        2049)  echo "NFS (Network File System)" ;;
        3000)  echo "Node.js / React / Grafana" ;;
        3306)  echo "MySQL / MariaDB" ;;
        4200)  echo "Angular Dev Server" ;;
        5000)  echo "Flask / Python / .NET" ;;
        5037)  echo "ADB Host (Android Debug Bridge)" ;;
        5173)  echo "Vite Dev Server" ;;
        5353)  echo "mDNS / Avahi ZeroConf" ;;
        5432)  echo "PostgreSQL Database" ;;
        5555)  echo "ADB Wireless (Android Debug)" ;;
        5901)  echo "VNC Server (:1 Display)" ;;
        6000)  echo "X11 Server (Termux:X11)" ;;
        6379)  echo "Redis Cache" ;;
        7070)  echo "AnyDesk (Acesso Remoto)" ;;
        8000)  echo "Django / Python HTTP Server" ;;
        8022)  echo "Termux OpenSSH Server" ;;
        8080)  echo "HTTP Alternativo / Tomcat / Dev" ;;
        8081)  echo "Proxy / Metro Bundler (React Native)" ;;
        8086)  echo "InfluxDB / Dev Server" ;;
        8888)  echo "Jupyter Notebook" ;;
        9000)  echo "PHP-FPM / Portainer / SonarQube" ;;
        9090)  echo "Prometheus / Cockpit Web" ;;
        9200)  echo "Elasticsearch" ;;
        27017) echo "MongoDB Database" ;;
        *)     echo "-" ;;
    esac
}

# Classifica exposição de rede
get_tipo_exposicao() {
    local endereco="$1"
    case "$endereco" in
        127.0.0.1|::1|*localhost*)
            echo "Local (Aparelho)"
            ;;
        *)
            echo "Rede / Exposta"
            ;;
    esac
}

# Obtém regras de bloqueio FindPort ativas no iptables ou no arquivo de controle
obter_regras_bloqueadas() {
    local regras=()
    if is_root && command -v iptables >/dev/null 2>&1; then
        while IFS= read -r line; do
            # Formato esperado: -A INPUT -p tcp -m tcp --dport 8080 -m comment --comment FindPort_Block_TCP_8080 -j DROP
            if [[ "$line" =~ FindPort_Block_([A-Za-z]+)_([0-9]+) ]]; then
                local proto="${BASH_REMATCH[1]}"
                local porta="${BASH_REMATCH[2]}"
                regras+=("${proto}:${porta}")
            fi
        done < <(iptables -S INPUT 2>/dev/null | grep "FindPort_Block_")
    fi

    # Fallback se tiver arquivo de regras persistido
    if [ ${#regras[@]} -eq 0 ] && [ -f "$RULES_FILE" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && regras+=("$line")
        done < "$RULES_FILE"
    fi

    # Retorna regras únicas separadas por espaço
    printf "%s\n" "${regras[@]}" 2>/dev/null | sort -u
}

# Verifica se uma porta está bloqueada
is_porta_bloqueada() {
    local proto="$1"
    local porta="$2"
    local regra_alvo="${proto}:${porta}"
    for r in "${REGRAS_BLOQUEADAS_CACHE[@]}"; do
        if [ "$r" = "$regra_alvo" ]; then
            return 0
        fi
    done
    return 1
}

# Bloquear porta via iptables (requer root)
bloquear_porta_firewall() {
    local porta="$1"
    local proto="${2:-TCP}"
    local pid="${3:-0}"
    local processo="${4:-N/A}"

    local proto_lower
    proto_lower="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"

    if ! is_root; then
        echo -e "\n${C_RED}ERRO: O bloqueio de portas no Firewall (iptables) exige privilégios de ROOT!${C_RESET}"
        echo -e "${C_YELLOW}Dica: No Termux com Root, execute 'tsu' ou 'su' antes de rodar o findport.sh.${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi

    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "\n${C_RED}ERRO: 'iptables' não foi encontrado. Instale com: pkg install iptables${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi

    local comment_tag="FindPort_Block_${proto}_${porta}"

    # Remove regra anterior idêntica para evitar duplicação
    iptables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null || true

    # Insere regra no topo do INPUT
    if iptables -I INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; then
        # Tenta também no ip6tables se disponível
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -I INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null || true
        fi

        # Salva em arquivo de controle
        grep -v "^${proto}:${porta}$" "$RULES_FILE" 2>/dev/null > "${RULES_FILE}.tmp" || true
        echo "${proto}:${porta}" >> "${RULES_FILE}.tmp"
        mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true

        write_audit_log "FIREWALL_BLOQUEADO" "$porta" "$proto" "$pid" "$processo" "Regra iptables criada: $comment_tag"

        echo -e "\n${C_GREEN}[OK] Porta $porta ($proto) bloqueada com sucesso no Firewall (iptables)!${C_RESET}"
        echo -e "${C_CYAN}O aplicativo continua rodando no Android, mas conexões externas serão descartadas.${C_RESET}"
        sleep 2
        return 0
    else
        echo -e "\n${C_RED}Falha ao aplicar regra no iptables.${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi
}

# Desbloquear porta no Firewall (iptables)
desbloquear_porta_firewall() {
    local proto="$1"
    local porta="$2"

    local proto_lower
    proto_lower="$(echo "$proto" | tr '[:upper:]' '[:lower:]')"

    if ! is_root; then
        echo -e "\n${C_RED}ERRO: O desbloqueio no Firewall exige privilégios de ROOT!${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi

    local comment_tag="FindPort_Block_${proto}_${porta}"

    # Remove regra do iptables
    local removeu=0
    while iptables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; do
        removeu=1
    done

    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; do
            removeu=1
        done
    fi

    # Atualiza arquivo de regras
    if [ -f "$RULES_FILE" ]; then
        grep -v "^${proto}:${porta}$" "$RULES_FILE" > "${RULES_FILE}.tmp" 2>/dev/null || true
        mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true
    fi

    write_audit_log "FIREWALL_DESBLOQUEADO" "$porta" "$proto" 0 "N/A" "Regra iptables removida: $comment_tag"

    echo -e "\n${C_GREEN}[OK] Regra removida! Porta $porta ($proto) DESBLOQUEADA no Firewall.${C_RESET}"
    sleep 2
    return 0
}

# Classifica processo e criticidade
classificar_processo() {
    local pid="$1"
    local nome="$2"
    local porta="$3"

    # Checar se é processo crítico
    if [ "$pid" -le 1 ]; then
        echo "NUNCA|Sistema Crítico|Processo vital do Kernel/Init"
        return
    fi

    for crit in "${PROCESSOS_CRITICOS[@]}"; do
        if [ "$nome" = "$crit" ]; then
            echo "NUNCA|Sistema Crítico|Processo essencial do Android"
            return
        fi
    done

    case "$nome" in
        *node*|*python*|*java*|*mariadb*|*mysqld*|*postgres*|*redis*|*httpd*|*nginx*|*php*|*sshd*)
            echo "SIM|Dev / Servidor Local|Servidor ou ferramenta de desenvolvimento"
            ;;
        *termux*|*dropbear*)
            echo "CUIDADO|Ambiente Termux|Pode fechar sua sessão atual"
            ;;
        *)
            echo "SIM (Se inativo)|Aplicativo / Usuário|Processo em execução"
            ;;
    esac
}

# Coleta conexões abertas (TCP Listen e UDP)
coletar_portas() {
    # Limpa arquivos temporários
    local tmp_raw
    tmp_raw="$(mktemp 2>/dev/null || echo "/data/data/com.termux/files/usr/tmp/findport_$$.tmp")"

    # Tenta usar 'ss'
    if command -v ss >/dev/null 2>&1; then
        # ss -tulpn
        ss -H -t -u -l -n -p 2>/dev/null > "$tmp_raw" || true
    fi

    # Se 'ss' falhar ou retornar vazio, tenta 'netstat'
    if [ ! -s "$tmp_raw" ] && command -v netstat >/dev/null 2>&1; then
        netstat -tulnp 2>/dev/null | grep -E 'LISTEN|udp' > "$tmp_raw" || true
    fi

    # Se ainda vazio, tenta 'lsof'
    if [ ! -s "$tmp_raw" ] && command -v lsof >/dev/null 2>&1; then
        lsof -iTCP -sTCP:LISTEN -n -P 2>/dev/null | awk 'NR>1 {print "tcp LISTEN 0 0 "$9" * users:((\""$1"\",pid="$2",fd=0))"}' >> "$tmp_raw" || true
        lsof -iUDP -n -P 2>/dev/null | awk 'NR>1 {print "udp UNCONN 0 0 "$9" * users:((\""$1"\",pid="$2",fd=0))"}' >> "$tmp_raw" || true
    fi

    # Se ainda vazio, lê diretamente de /proc/net/tcp e /proc/net/udp
    if [ ! -s "$tmp_raw" ] && [ -r "/proc/net/tcp" ]; then
        awk '
        function hex2dec(h) {
            return sprintf("%d", "0x" h);
        }
        function hex2ip(h) {
            return sprintf("%d.%d.%d.%d", "0x" substr(h,7,2), "0x" substr(h,5,2), "0x" substr(h,3,2), "0x" substr(h,1,2));
        }
        NR > 1 {
            split($2, local, ":");
            ip = hex2ip(local[1]);
            port = hex2dec(local[2]);
            state = $4;
            if (state == "0A") {
                print "tcp LISTEN 0 0 " ip ":" port " 0.0.0.0:* pid=-"
            }
        }' /proc/net/tcp >> "$tmp_raw" 2>/dev/null || true

        awk '
        function hex2dec(h) {
            return sprintf("%d", "0x" h);
        }
        function hex2ip(h) {
            return sprintf("%d.%d.%d.%d", "0x" substr(h,7,2), "0x" substr(h,5,2), "0x" substr(h,3,2), "0x" substr(h,1,2));
        }
        NR > 1 {
            split($2, local, ":");
            ip = hex2ip(local[1]);
            port = hex2dec(local[2]);
            print "udp UNCONN 0 0 " ip ":" port " 0.0.0.0:* pid=-"
        }' /proc/net/udp >> "$tmp_raw" 2>/dev/null || true
    fi

    # Processar as linhas capturadas
    # Formato unificado no array: PORTA|PROTO|ENDERECO|PID|PROCESSO
    local resultados=()

    while IFS= read -r line; do
        [ -z "$line" ] && continue

        local proto="TCP"
        if echo "$line" | grep -qi "udp"; then
            proto="UDP"
        fi

        # Extrair endereço local e porta
        # ss / netstat / lsof produzem padrões como 0.0.0.0:8080 ou 127.0.0.1:8022 ou [::]:8080 ou *:8080
        local addr_col=""
        for token in $line; do
            if [[ "$token" =~ :[0-9]+$ ]]; then
                addr_col="$token"
                break
            fi
        done

        [ -z "$addr_col" ] && continue

        local porta="${addr_col##*:}"
        local endereco="${addr_col%:*}"
        endereco="${endereco//\[/}"
        endereco="${endereco//\]/}"
        [ "$endereco" = "*" ] && endereco="0.0.0.0"

        # Extrair PID e Nome do Processo
        local pid="0"
        local proc_name="Desconhecido"

        if [[ "$line" =~ pid=([0-9]+) ]]; then
            pid="${BASH_REMATCH[1]}"
        elif [[ "$line" =~ ([0-9]+)/([^ ]+) ]]; then
            pid="${BASH_REMATCH[1]}"
            proc_name="${BASH_REMATCH[2]}"
        fi

        # Se temos o PID mas não o nome, busca em /proc/$pid/comm ou ps
        if [ "$pid" -gt 0 ] && [ "$proc_name" = "Desconhecido" ]; then
            if [ -r "/proc/$pid/comm" ]; then
                proc_name="$(tr -d '\0\n' < "/proc/$pid/comm" 2>/dev/null || echo "PID:$pid")"
            elif [ -r "/proc/$pid/cmdline" ]; then
                proc_name="$(awk -F'\0' '{print $1}' "/proc/$pid/cmdline" 2>/dev/null || echo "PID:$pid")"
                proc_name="$(basename "$proc_name" 2>/dev/null || echo "$proc_name")"
            fi
        fi

        # Extração de users:(("name",pid=123,fd=3))
        if [[ "$line" =~ users:\(\(\"([^\"]+)\" ]]; then
            proc_name="${BASH_REMATCH[1]}"
        fi

        # Normaliza proc_name
        [ -z "$proc_name" ] && proc_name="N/A"

        resultados+=("${porta}|${proto}|${endereco}|${pid}|${proc_name}")
    done < "$tmp_raw"

    rm -f "$tmp_raw" 2>/dev/null || true

    # Ordena e remove duplicados
    printf "%s\n" "${resultados[@]}" 2>/dev/null | sort -t'|' -k1,1n -k2,2 -u
}

# =============================================================================
# LOOP PRINCIPAL DA INTERFACE
# =============================================================================

filtro_seguras=0
termo_busca=""

while true; do
    clear

    IS_ROOT=0
    if is_root; then
        IS_ROOT=1
    fi

    # Atualiza cache de regras bloqueadas
    mapfile -t REGRAS_BLOQUEADAS_CACHE < <(obter_regras_bloqueadas)

    echo -e "${C_CYAN}===================================================================================================${C_RESET}"
    echo -e "${C_CYAN}                    FINDPORT - AUDITORIA DE REDE, PORTAS & FIREWALL (TERMUX)                       ${C_RESET}"
    echo -e "${C_CYAN}===================================================================================================${C_RESET}"

    if [ "$IS_ROOT" -eq 1 ]; then
        echo -e "  ${C_BOLD}STATUS:${C_RESET} ${C_GREEN}ROOT ATIVO [Permissão Total: Visualização Completa, Kill & Firewall iptables]${C_RESET}"
    else
        echo -e "  ${C_BOLD}STATUS:${C_RESET} ${C_YELLOW}USUÁRIO COMUM (Termux) [Visualiza processos do Termux. Para iptables/root use 'tsu']${C_RESET}"
    fi
    echo -e "${C_GRAY}---------------------------------------------------------------------------------------------------${C_RESET}"

    # Painel de portas bloqueadas no Firewall
    if [ ${#REGRAS_BLOQUEADAS_CACHE[@]} -gt 0 ]; then
        echo -e "  ${C_MAGENTA}🛡️  PORTAS ATUALMENTE BLOQUEADAS NO FIREWALL (IPTABLES):${C_RESET}"
        b_idx=1
        for rb in "${REGRAS_BLOQUEADAS_CACHE[@]}"; do
            [ -z "$rb" ] && continue
            proto_b="${rb%%:*}"
            porta_b="${rb##*:}"
            echo -e "     ${C_YELLOW}[B${b_idx}] Porta ${porta_b} (${proto_b}) - Bloqueada no iptables${C_RESET}"
            ((b_idx++))
        done
        echo -e "     ${C_GRAY}(Pressione 'D' no menu para desbloquear qualquer uma delas)${C_RESET}"
        echo -e "${C_GRAY}---------------------------------------------------------------------------------------------------${C_RESET}"
    fi

    echo -e "${C_GRAY}Coletando conexões de rede ativas (TCP Listen & UDP)...${C_RESET}"
    mapfile -t LISTA_RAW < <(coletar_portas)

    # Filtragem e montagem dos itens
    ITENS_FILTRADOS=()
    for row in "${LISTA_RAW[@]}"; do
        [ -z "$row" ] && continue
        IFS='|' read -r r_porta r_proto r_addr r_pid r_proc <<< "$row"

        # Obter detalhes
        r_exposicao="$(get_tipo_exposicao "$r_addr")"
        r_servico="$(get_servico_conhecido "$r_porta")"

        classificacao="$(classificar_processo "$r_pid" "$r_proc" "$r_porta")"
        IFS='|' read -r r_podefechar r_categoria r_motivo <<< "$classificacao"

        r_firewall="Livre"
        if is_porta_bloqueada "$r_proto" "$r_porta"; then
            r_firewall="BLOQUEADA"
        fi

        # Filtro de seguras
        if [ "$filtro_seguras" -eq 1 ]; then
            if [[ "$r_podefechar" != SIM* ]]; then
                continue
            fi
        fi

        # Filtro de busca
        if [ -n "$termo_busca" ]; then
            termo_lower="$(echo "$termo_busca" | tr '[:upper:]' '[:lower:]')"
            conteudo_linha="$(echo "$r_porta $r_proc $r_servico $r_categoria $r_proto" | tr '[:upper:]' '[:lower:]')"
            if [[ "$conteudo_linha" != *"$termo_lower"* ]]; then
                continue
            fi
        fi

        ITENS_FILTRADOS+=("${r_porta}|${r_proto}|${r_addr}|${r_pid}|${r_proc}|${r_exposicao}|${r_podefechar}|${r_firewall}|${r_servico}|${r_categoria}|${r_motivo}")
    done

    # Status de filtros
    txt_filtro="Todas as portas"
    [ "$filtro_seguras" -eq 1 ] && txt_filtro="Apenas seguras para fechar [ATIVO]"
    txt_busca=""
    [ -n "$termo_busca" ] && txt_busca=" | Busca: '${termo_busca}'"

    echo -e "${C_WHITE}Filtro: ${txt_filtro}${txt_busca} | Total encontrado: ${#ITENS_FILTRADOS[@]}${C_RESET}\n"

    # Cabeçalho da tabela
    printf "${C_CYAN}%-5s | %-6s | %-5s | %-7s | %-18s | %-15s | %-12s | %-10s | %-16s${C_RESET}\n" \
        "#" "PORTA" "PROTO" "PID" "PROCESSO" "EXPOSIÇÃO" "FECHAR?" "FIREWALL" "SERVIÇO / NOTA"
    echo -e "${C_GRAY}---------------------------------------------------------------------------------------------------${C_RESET}"

    contador=1
    declare -A MAPA_ITENS

    for item in "${ITENS_FILTRADOS[@]}"; do
        MAPA_ITENS[$contador]="$item"
        IFS='|' read -r p_porta p_proto p_addr p_pid p_proc p_expo p_fechar p_fw p_serv p_cat p_mot <<< "$item"

        # Cor da linha
        cor_linha="$C_WHITE"
        if [ "$p_fechar" = "NUNCA" ]; then
            cor_linha="$C_GRAY"
        elif [ "$p_fw" = "BLOQUEADA" ]; then
            cor_linha="$C_MAGENTA"
        elif [[ "$p_expo" == *"Exposta"* ]]; then
            cor_linha="$C_YELLOW"
        elif [[ "$p_fechar" == SIM* ]]; then
            cor_linha="$C_GREEN"
        fi

        # Truncamentos para manter alinhamento
        proc_trunc="${p_proc:0:18}"
        serv_trunc="${p_serv:0:16}"
        expo_trunc="${p_expo:0:15}"

        printf "${cor_linha}[%-3d] | %-6s | %-5s | %-7s | %-18s | %-15s | %-12s | %-10s | %-16s${C_RESET}\n" \
            "$contador" "$p_porta" "$p_proto" "$p_pid" "$proc_trunc" "$expo_trunc" "$p_fechar" "$p_fw" "$serv_trunc"

        ((contador++))
    done

    echo -e "${C_GRAY}---------------------------------------------------------------------------------------------------${C_RESET}"
    echo -e "${C_CYAN}MENU DE OPÇÕES:${C_RESET}"
    echo -e "  ${C_WHITE}[1-$((contador-1))] Selecionar número para gerenciar (Encerrar Processo ou Bloquear no Firewall)${C_RESET}"
    echo -e "  ${C_YELLOW}[B]     Buscar / Filtrar por texto (Porta, Processo ou Serviço)${C_RESET}"
    if [ -n "$termo_busca" ]; then
        echo -e "  ${C_YELLOW}[C]     Limpar busca ativa${C_RESET}"
    fi
    if [ ${#REGRAS_BLOQUEADAS_CACHE[@]} -gt 0 ]; then
        echo -e "  ${C_MAGENTA}[D]     Desbloquear porta(s) no Firewall (iptables)${C_RESET}"
    fi
    if [ "$filtro_seguras" -eq 1 ]; then
        echo -e "  ${C_WHITE}[F]     Alternar filtro de seguras: [DESATIVAR]${C_RESET}"
    else
        echo -e "  ${C_WHITE}[F]     Alternar filtro de seguras: [ATIVAR]${C_RESET}"
    fi
    echo -e "  ${C_WHITE}[R]     Recarregar lista${C_RESET}"
    if [ "$IS_ROOT" -eq 0 ]; then
        echo -e "  ${C_CYAN}[A]     Tentar elevar para ROOT (tsu / su)${C_RESET}"
    fi
    echo -e "  ${C_GRAY}[S/Q]   Sair${C_RESET}\n"

    read -r -p "Digite sua opção: " escolha
    escolha="$(echo "$escolha" | tr -d '[:space:]')"

    case "$escolha" in
        [sSqQ])
            echo -e "${C_CYAN}Encerrando FindPort Termux. Até logo!${C_RESET}"
            break
            ;;
        [rR])
            continue
            ;;
        [fF])
            if [ "$filtro_seguras" -eq 1 ]; then
                filtro_seguras=0
            else
                filtro_seguras=1
            fi
            continue
            ;;
        [bB])
            echo ""
            read -r -p "Digite o termo para filtrar (ex: node, 8080, ssh, etc.): " termo_input
            termo_busca="$termo_input"
            continue
            ;;
        [cC])
            termo_busca=""
            continue
            ;;
        [aA])
            if [ "$IS_ROOT" -eq 0 ]; then
                if command -v tsu >/dev/null 2>&1; then
                    echo -e "${C_CYAN}Reiniciando via 'tsu'...${C_RESET}"
                    exec tsu -c "bash \"${BASH_SOURCE[0]}\""
                elif command -v su >/dev/null 2>&1; then
                    echo -e "${C_CYAN}Reiniciando via 'su'...${C_RESET}"
                    exec su -c "bash \"${BASH_SOURCE[0]}\""
                else
                    echo -e "${C_RED}Comando 'tsu' ou 'su' não encontrado. Seu dispositivo precisa de acesso Root para essa opção.${C_RESET}"
                    read -r -p "Pressione ENTER para continuar..."
                fi
            fi
            continue
            ;;
        [dD])
            # Menu de Desbloqueio
            clear
            echo -e "${C_MAGENTA}===================================================================================================${C_RESET}"
            echo -e "${C_MAGENTA}                         DESBLOQUEIO DE PORTAS NO FIREWALL (IPTABLES)                              ${C_RESET}"
            echo -e "${C_MAGENTA}===================================================================================================${C_RESET}"

            if [ ${#REGRAS_BLOQUEADAS_CACHE[@]} -eq 0 ]; then
                echo -e "${C_YELLOW}Nenhuma regra de bloqueio encontrada.${C_RESET}"
                sleep 2
                continue
            fi

            d_i=1
            for rb in "${REGRAS_BLOQUEADAS_CACHE[@]}"; do
                [ -z "$rb" ] && continue
                proto_d="${rb%%:*}"
                porta_d="${rb##*:}"
                echo -e "  ${C_WHITE}[${d_i}] Porta ${porta_d} (${proto_d}) - Bloqueio FindPort no iptables${C_RESET}"
                ((d_i++))
            done
            echo ""
            echo -e "  ${C_YELLOW}[T] Desbloquear TODAS as portas bloqueadas${C_RESET}"
            echo -e "  ${C_GRAY}[0] Voltar ao menu principal${C_RESET}\n"

            read -r -p "Escolha o número da porta para desbloquear: " desb_escolha
            desb_escolha="$(echo "$desb_escolha" | tr -d '[:space:]')"

            if [ "$desb_escolha" = "0" ] || [ -z "$desb_escolha" ]; then
                continue
            elif [[ "$desb_escolha" =~ ^[tT]$ ]]; then
                for rb in "${REGRAS_BLOQUEADAS_CACHE[@]}"; do
                    [ -z "$rb" ] && continue
                    desbloquear_porta_firewall "${rb%%:*}" "${rb##*:}"
                done
            elif [[ "$desb_escolha" =~ ^[0-9]+$ ]] && [ "$desb_escolha" -ge 1 ] && [ "$desb_escolha" -lt "$d_i" ]; then
                regra_sel="${REGRAS_BLOQUEADAS_CACHE[$((desb_escolha-1))]}"
                desbloquear_porta_firewall "${regra_sel%%:*}" "${regra_sel##*:}"
            else
                echo -e "${C_RED}Opção inválida.${C_RESET}"
                sleep 1
            fi
            continue
            ;;
        *)
            # Checar se selecionou um número da lista
            if [[ "$escolha" =~ ^[0-9]+$ ]] && [ -n "${MAPA_ITENS[$escolha]}" ]; then
                selecionado="${MAPA_ITENS[$escolha]}"
                IFS='|' read -r s_porta s_proto s_addr s_pid s_proc s_expo s_fechar s_fw s_serv s_cat s_mot <<< "$selecionado"

                clear
                echo -e "${C_CYAN}===================================================================================================${C_RESET}"
                echo -e "${C_CYAN}                  GERENCIAR PORTA ${s_porta} (${s_proto}) - TERMUX / ANDROID                       ${C_RESET}"
                echo -e "${C_CYAN}===================================================================================================${C_RESET}"
                echo -e "  Porta:           ${C_WHITE}${s_porta} (${s_proto})${C_RESET}"
                if [[ "$s_expo" == *"Exposta"* ]]; then
                    echo -e "  Endereço IP:     ${s_addr} -> Exposição: ${C_YELLOW}${s_expo}${C_RESET}"
                else
                    echo -e "  Endereço IP:     ${s_addr} -> Exposição: ${C_GREEN}${s_expo}${C_RESET}"
                fi
                echo -e "  Serviço Notável: ${C_WHITE}${s_serv}${C_RESET}"
                echo -e "  Processo:        ${C_WHITE}${s_proc} (PID: ${s_pid})${C_RESET}"
                echo -e "  Categoria:       ${C_WHITE}${s_cat}${C_RESET}"
                echo -e "  Pode Fechar?:    ${C_YELLOW}${s_fechar} - ${s_mot}${C_RESET}"
                echo -e "  Status Firewall: ${C_WHITE}${s_fw}${C_RESET}"
                echo -e "${C_GRAY}---------------------------------------------------------------------------------------------------${C_RESET}"
                echo -e "${C_CYAN}O QUE VOCÊ DESEJA FAZER?${C_RESET}\n"
                echo -e "  ${C_RED}[1] Encerrar o processo (kill -9) - Finaliza o aplicativo e libera a porta${C_RESET}"
                echo -e "  ${C_YELLOW}[2] Bloquear a porta no Firewall (iptables) - SEM fechar o aplicativo (Requer Root)${C_RESET}"
                echo -e "  ${C_GRAY}[0] Voltar ao menu principal${C_RESET}\n"

                read -r -p "Selecione a ação desejada (1, 2 ou 0): " acao
                acao="$(echo "$acao" | tr -d '[:space:]')"

                if [ "$acao" = "1" ]; then
                    if [ "$s_pid" -le 0 ]; then
                        echo -e "\n${C_RED}ERRO: PID não identificado para esta porta (ou pertence a outro usuário/sistema restrito pelo Android).${C_RESET}"
                        read -r -p "Pressione ENTER para voltar..."
                        continue
                    fi

                    if [ "$s_fechar" = "NUNCA" ]; then
                        echo -e "\n${C_RED}⚠️ BLOQUEIO DE SEGURANÇA: O processo '${s_proc}' (PID ${s_pid}) é vital para o Android!${C_RESET}"
                        echo -e "${C_RED}Finalizá-lo causará reinicialização súbita ou travamento do sistema Android.${C_RESET}"
                        read -r -p "Tem certeza absoluta? Digite 'SIM' em maiúsculo para forçar: " conf_forcar
                        if [ "$conf_forcar" != "SIM" ]; then
                            echo -e "${C_GREEN}Operação cancelada por segurança.${C_RESET}"
                            sleep 2
                            continue
                        fi
                    else
                        read -r -p "Confirma o encerramento de '${s_proc}' (PID ${s_pid})? (S/N): " conf_encerra
                        if [[ ! "$conf_encerra" =~ ^[sSyY] ]]; then
                            echo -e "${C_GRAY}Operação cancelada.${C_RESET}"
                            sleep 1
                            continue
                        fi
                    fi

                    # Executa encerramento
                    if kill -9 "$s_pid" 2>/dev/null; then
                        write_audit_log "PROCESSO_ENCERRADO" "$s_porta" "$s_proto" "$s_pid" "$s_proc" "Encerrado com kill -9 pelo usuario"
                        echo -e "\n${C_GREEN}[OK] Processo '${s_proc}' (PID ${s_pid}) encerrado! Porta ${s_porta} liberada.${C_RESET}"
                        sleep 2
                    else
                        echo -e "\n${C_RED}Falha ao encerrar o processo ${s_pid}.${C_RESET}"
                        echo -e "${C_YELLOW}Dica: Processos de outros apps no Android exigem permissão Root para serem finalizados.${C_RESET}"
                        read -r -p "Pressione ENTER para continuar..."
                    fi
                elif [ "$acao" = "2" ]; then
                    bloquear_porta_firewall "$s_porta" "$s_proto" "$s_pid" "$s_proc"
                else
                    echo -e "${C_GRAY}Voltando ao menu...${C_RESET}"
                fi
            else
                echo -e "${C_RED}Opção inválida. Digite o número da porta ou uma letra do menu.${C_RESET}"
                sleep 1
            fi
            ;;
    esac
done
