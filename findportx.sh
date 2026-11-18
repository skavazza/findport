#!/usr/bin/env bash
# =============================================================================
#  FindPort - Gerenciador Interativo de Portas e Firewall para Termux (Android)
# =============================================================================
#  Audita portas abertas (TCP e UDP), detecta nível de exposição (Local vs Rede),
#  identifica serviços conhecidos, encerra processos e gerencia bloqueio de portas
#  via iptables (Firewall do Linux/Android), mantendo log de auditoria.
# =============================================================================

# Diretório base e arquivos de controle
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/findport_audit.log"
RULES_FILE="${SCRIPT_DIR}/.findport_rules"

# Diretório temporário seguro para o Termux
TMP_DIR="${TMPDIR:-${PREFIX:-/data/data/com.termux/files/usr}/tmp}"
mkdir -p "$TMP_DIR" 2>/dev/null || TMP_DIR="${SCRIPT_DIR}"

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

# Portas padrão para checagem ativa caso ss/netstat não estejam disponíveis
PORTAS_COMUNS=(
    21 22 53 80 443 1433 1521 2049 3000 3306 4200 5000
    5037 5173 5353 5432 5555 5901 6000 6379 7070 8000 8022
    8080 8081 8086 8888 9000 9090 9200 27017
)

# Detecta largura do terminal
get_term_width() {
    local w
    w="$(tput cols 2>/dev/null || stty size 2>/dev/null | awk '{print $2}')"
    if [ -z "$w" ] || [ "$w" -le 20 ] 2>/dev/null; then
        w=60
    fi
    echo "$w"
}

# Imprime linha divisória adaptada à largura da tela
print_divider() {
    local char="${1:--}"
    local color="${2:-$C_GRAY}"
    local w
    w="$(get_term_width)"
    local line=""
    for ((i=0; i<w; i++)); do
        line="${line}${char}"
    done
    echo -e "${color}${line}${C_RESET}"
}

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

# Dicionário de serviços conhecidos
get_servico_conhecido() {
    local porta="$1"
    case "$porta" in
        21)    echo "FTP (Transferência)" ;;
        22)    echo "SSH (Acesso remoto)" ;;
        53)    echo "DNS (Resolução nomes)" ;;
        80)    echo "HTTP (Servidor Web)" ;;
        443)   echo "HTTPS (Web Seguro/SSL)" ;;
        1433)  echo "MS SQL Server" ;;
        1521)  echo "Oracle Database" ;;
        2049)  echo "NFS (Network File)" ;;
        3000)  echo "Node.js / React / Dev" ;;
        3306)  echo "MySQL / MariaDB" ;;
        4200)  echo "Angular Dev Server" ;;
        5000)  echo "Flask / Python / .NET" ;;
        5037)  echo "ADB Host (Android Debug)" ;;
        5173)  echo "Vite Dev Server" ;;
        5353)  echo "mDNS / Avahi ZeroConf" ;;
        5432)  echo "PostgreSQL Database" ;;
        5555)  echo "ADB Wireless (Android)" ;;
        5901)  echo "VNC Server (:1 Display)" ;;
        6000)  echo "X11 Server (Termux:X11)" ;;
        6379)  echo "Redis Cache" ;;
        7070)  echo "AnyDesk (Acesso Remoto)" ;;
        8000)  echo "Django / HTTP Server" ;;
        8022)  echo "Termux OpenSSH Server" ;;
        8080)  echo "HTTP Dev / Tomcat / Web" ;;
        8081)  echo "Proxy / Metro Bundler" ;;
        8086)  echo "InfluxDB / Dev Server" ;;
        8888)  echo "Jupyter Notebook" ;;
        9000)  echo "PHP-FPM / Portainer" ;;
        9090)  echo "Prometheus / Cockpit" ;;
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
            if [[ "$line" =~ FindPort_Block_([A-Za-z]+)_([0-9]+) ]]; then
                local proto="${BASH_REMATCH[1]}"
                local porta="${BASH_REMATCH[2]}"
                regras+=("${proto}:${porta}")
            fi
        done < <(iptables -S INPUT 2>/dev/null | grep "FindPort_Block_")
    fi

    # Fallback para arquivo persistido
    if [ ${#regras[@]} -eq 0 ] && [ -f "$RULES_FILE" ]; then
        while IFS= read -r line; do
            [ -n "$line" ] && regras+=("$line")
        done < "$RULES_FILE"
    fi

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
        echo -e "${C_YELLOW}Dica: No Termux com Root, execute 'tsu' ou 'su' antes de rodar o findport.${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi

    if ! command -v iptables >/dev/null 2>&1; then
        echo -e "\n${C_RED}ERRO: 'iptables' não foi encontrado. Instale com: pkg install iptables${C_RESET}"
        read -r -p "Pressione ENTER para voltar..."
        return 1
    fi

    local comment_tag="FindPort_Block_${proto}_${porta}"

    iptables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null || true

    if iptables -I INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; then
        if command -v ip6tables >/dev/null 2>&1; then
            ip6tables -I INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null || true
        fi

        grep -v "^${proto}:${porta}$" "$RULES_FILE" 2>/dev/null > "${RULES_FILE}.tmp" || true
        echo "${proto}:${porta}" >> "${RULES_FILE}.tmp"
        mv "${RULES_FILE}.tmp" "$RULES_FILE" 2>/dev/null || true

        write_audit_log "FIREWALL_BLOQUEADO" "$porta" "$proto" "$pid" "$processo" "Regra iptables criada: $comment_tag"

        echo -e "\n${C_GREEN}[OK] Porta $porta ($proto) bloqueada com sucesso no Firewall (iptables)!${C_RESET}"
        echo -e "${C_CYAN}O aplicativo continua rodando no Android, mas conexões de rede externas serão descartadas.${C_RESET}"
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

    while iptables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; do
        :
    done

    if command -v ip6tables >/dev/null 2>&1; then
        while ip6tables -D INPUT -p "$proto_lower" --dport "$porta" -m comment --comment "$comment_tag" -j DROP 2>/dev/null; do
            :
        done
    fi

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

    if [ "$pid" -le 1 ] 2>/dev/null; then
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
            echo "SIM|Dev / Servidor Local|Servidor ou ferramenta de dev"
            ;;
        *termux*|*dropbear*)
            echo "CUIDADO|Ambiente Termux|Pode fechar sua sessão atual"
            ;;
        *)
            echo "SIM (Se inativo)|Aplicativo / Usuário|Processo em execução"
            ;;
    esac
}

# Coleta de processos locais do Termux para associação com portas
obter_mapa_processos_termux() {
    if command -v ps >/dev/null 2>&1; then
        ps -ef 2>/dev/null || ps aux 2>/dev/null || ps 2>/dev/null
    fi
}

# Tenta descobrir o processo associado a uma porta inspecionando processos do Termux
descobrir_processo_por_porta() {
    local porta="$1"
    local ps_texto="$2"

    if [ -n "$ps_texto" ]; then
        while IFS= read -r line; do
            if [[ "$line" =~ (:[0-9]*${porta}[^0-9]|port[ =]*${porta}|-p[ =]*${porta}|${porta}) ]]; then
                local pid
                pid="$(echo "$line" | awk '{print $2}')"
                local cmd
                cmd="$(echo "$line" | awk '{print $8}')"
                [ -z "$cmd" ] && cmd="$(echo "$line" | awk '{print $NF}')"
                cmd="$(basename "$cmd" 2>/dev/null || echo "$cmd")"
                if [ -n "$pid" ] && [[ "$pid" =~ ^[0-9]+$ ]]; then
                    echo "${pid}|${cmd}"
                    return
                fi
            fi
        done <<< "$ps_texto"
    fi
    echo "0|Desconhecido"
}

# Sonda portas ativas usando Python (ultra-rápido e compatível com Android não-root)
sonda_python() {
    local py_bin=""
    if command -v python >/dev/null 2>&1; then
        py_bin="python"
    elif command -v python3 >/dev/null 2>&1; then
        py_bin="python3"
    fi

    [ -z "$py_bin" ] && return 1

    $py_bin -c '
import socket, sys, os, subprocess, re

ports_check = [
    21, 22, 53, 80, 443, 1433, 1521, 2049, 3000, 3306, 4200, 5000,
    5037, 5173, 5353, 5432, 5555, 5901, 6000, 6379, 7070, 8000, 8022,
    8080, 8081, 8086, 8888, 9000, 9090, 9200, 27017
]

ps_lines = []
try:
    ps_out = subprocess.check_output(["ps", "-ef"], stderr=subprocess.DEVNULL).decode("utf-8", errors="ignore")
    ps_lines = ps_out.splitlines()
    for m in re.finditer(r"(?:-p|--port|:|port\s*=\s*)(\d{2,5})", ps_out):
        p = int(m.group(1))
        if 1 <= p <= 65535 and p not in ports_check:
            ports_check.append(p)
except:
    pass

for p in sorted(set(ports_check)):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.06)
    res = s.connect_ex(("127.0.0.1", p))
    s.close()
    if res == 0:
        pid = 0
        pname = "Serviço TCP"
        for line in ps_lines:
            if str(p) in line:
                parts = line.split()
                if len(parts) >= 8:
                    pid = parts[1]
                    pname = os.path.basename(parts[7])
                elif len(parts) >= 2:
                    pid = parts[1]
                    pname = os.path.basename(parts[-1])
                break
        print(f"{p}|TCP|127.0.0.1|{pid}|{pname}")
' 2>/dev/null
}

# Sonda portas ativas usando recursos nativos do Bash (/dev/tcp)
sonda_bash_devtcp() {
    local ps_info="$1"
    for p in "${PORTAS_COMUNS[@]}"; do
        if (echo > /dev/tcp/127.0.0.1/"$p") 2>/dev/null; then
            local p_info
            p_info="$(descobrir_processo_por_porta "$p" "$ps_info")"
            local pid="${p_info%%|*}"
            local proc="${p_info##*|}"
            [ "$proc" = "Desconhecido" ] && proc="Serviço TCP"
            echo "${p}|TCP|127.0.0.1|${pid}|${proc}"
        fi
    done
}

# Coleta principal de conexões abertas
coletar_portas() {
    local resultados=()
    local ps_snapshot
    ps_snapshot="$(obter_mapa_processos_termux)"

    local coletou_algo=0

    # 1. Tentativa via 'ss' (sem a flag problemática -H)
    if command -v ss >/dev/null 2>&1; then
        local raw_ss
        raw_ss="$(ss -tulnp 2>/dev/null || ss -tuln 2>/dev/null)"
        if [ -n "$raw_ss" ]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^(Netid|State|Proto) ]] && continue
                [ -z "$line" ] && continue

                local proto="TCP"
                echo "$line" | grep -qi "udp" && proto="UDP"

                local addr_col=""
                for tok in $line; do
                    if [[ "$tok" =~ :[0-9]+$ ]]; then
                        addr_col="$tok"
                        break
                    fi
                done
                [ -z "$addr_col" ] && continue

                local porta="${addr_col##*:}"
                local endereco="${addr_col%:*}"
                endereco="${endereco//\[/}"
                endereco="${endereco//\]/}"
                [ "$endereco" = "*" ] && endereco="0.0.0.0"

                local pid="0"
                local proc_name="Desconhecido"

                if [[ "$line" =~ pid=([0-9]+) ]]; then
                    pid="${BASH_REMATCH[1]}"
                elif [[ "$line" =~ ([0-9]+)/([^ ]+) ]]; then
                    pid="${BASH_REMATCH[1]}"
                    proc_name="${BASH_REMATCH[2]}"
                fi

                if [[ "$line" =~ users:\(\(\"([^\"]+)\" ]]; then
                    proc_name="${BASH_REMATCH[1]}"
                fi

                if [ "$pid" -eq 0 ] || [ "$proc_name" = "Desconhecido" ]; then
                    local disc
                    disc="$(descobrir_processo_por_porta "$porta" "$ps_snapshot")"
                    [ "$pid" -eq 0 ] && pid="${disc%%|*}"
                    [ "$proc_name" = "Desconhecido" ] && proc_name="${disc##*|}"
                fi

                resultados+=("${porta}|${proto}|${endereco}|${pid}|${proc_name}")
                coletou_algo=1
            done <<< "$raw_ss"
        fi
    fi

    # 2. Tentativa via 'netstat' (se ss não encontrou nada)
    if [ "$coletou_algo" -eq 0 ] && command -v netstat >/dev/null 2>&1; then
        local raw_ns
        raw_ns="$(netstat -tulnp 2>/dev/null || netstat -tlpn 2>/dev/null || netstat -an 2>/dev/null | grep -i listen)"
        if [ -n "$raw_ns" ]; then
            while IFS= read -r line; do
                [[ "$line" =~ ^(Proto|Active) ]] && continue
                [ -z "$line" ] && continue

                local proto="TCP"
                echo "$line" | grep -qi "udp" && proto="UDP"

                local addr_col=""
                for tok in $line; do
                    if [[ "$tok" =~ :[0-9]+$ ]]; then
                        addr_col="$tok"
                        break
                    fi
                done
                [ -z "$addr_col" ] && continue

                local porta="${addr_col##*:}"
                local endereco="${addr_col%:*}"
                endereco="${endereco//\[/}"
                endereco="${endereco//\]/}"
                [ "$endereco" = "*" ] && endereco="0.0.0.0"

                local pid="0"
                local proc_name="Desconhecido"
                if [[ "$line" =~ ([0-9]+)/([^ ]+) ]]; then
                    pid="${BASH_REMATCH[1]}"
                    proc_name="${BASH_REMATCH[2]}"
                fi

                if [ "$pid" -eq 0 ] || [ "$proc_name" = "Desconhecido" ]; then
                    local disc
                    disc="$(descobrir_processo_por_porta "$porta" "$ps_snapshot")"
                    [ "$pid" -eq 0 ] && pid="${disc%%|*}"
                    [ "$proc_name" = "Desconhecido" ] && proc_name="${disc##*|}"
                fi

                resultados+=("${porta}|${proto}|${endereco}|${pid}|${proc_name}")
                coletou_algo=1
            done <<< "$raw_ns"
        fi
    fi

    # 3. Tentativa via /proc/net/tcp e /proc/net/udp
    if [ "$coletou_algo" -eq 0 ] && [ -r "/proc/net/tcp" ]; then
        while IFS= read -r p_line; do
            [ -n "$p_line" ] && resultados+=("$p_line") && coletou_algo=1
        done < <(awk '
        function hex2dec(h) { return sprintf("%d", "0x" h); }
        function hex2ip(h) {
            return sprintf("%d.%d.%d.%d", "0x" substr(h,7,2), "0x" substr(h,5,2), "0x" substr(h,3,2), "0x" substr(h,1,2));
        }
        NR > 1 {
            split($2, local, ":");
            ip = hex2ip(local[1]);
            port = hex2dec(local[2]);
            if ($4 == "0A") {
                print port "|TCP|" ip "|0|Kernel/App"
            }
        }' /proc/net/tcp 2>/dev/null)
    fi

    # 4. Complemento via Sonda Python (Detecta servidores ativos no aparelho mesmo sem root/iproute2)
    while IFS= read -r py_line; do
        if [ -n "$py_line" ]; then
            resultados+=("$py_line")
            coletou_algo=1
        fi
    done < <(sonda_python)

    # 5. Complemento via Bash /dev/tcp para portas comuns
    if [ "$coletou_algo" -eq 0 ]; then
        while IFS= read -r dev_line; do
            if [ -n "$dev_line" ]; then
                resultados+=("$dev_line")
                coletou_algo=1
            fi
        done < <(sonda_bash_devtcp "$ps_snapshot")
    fi

    # Retorna resultados únicos ordenados por porta
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
    is_root && IS_ROOT=1

    TERM_WIDTH="$(get_term_width)"
    IS_MOBILE=0
    [ "$TERM_WIDTH" -lt 85 ] && IS_MOBILE=1

    mapfile -t REGRAS_BLOQUEADAS_CACHE < <(obter_regras_bloqueadas)

    print_divider "=" "$C_CYAN"
    echo -e "${C_CYAN}${C_BOLD}   🛡️  FINDPORT - AUDITORIA DE REDE & FIREWALL (TERMUX)${C_RESET}"
    print_divider "=" "$C_CYAN"

    if [ "$IS_ROOT" -eq 1 ]; then
        echo -e "  ${C_BOLD}STATUS:${C_RESET} ${C_GREEN}ROOT ATIVO [Acesso Total: Kill & Firewall iptables]${C_RESET}"
    else
        echo -e "  ${C_BOLD}STATUS:${C_RESET} ${C_YELLOW}USUÁRIO COMUM (Termux)${C_RESET}"
        if ! command -v ss >/dev/null 2>&1; then
            echo -e "  ${C_GRAY}Dica: Instale ferramentas completas com a opção [I] abaixo.${C_RESET}"
        fi
    fi
    print_divider "-" "$C_GRAY"

    # Painel de portas bloqueadas no Firewall
    if [ ${#REGRAS_BLOQUEADAS_CACHE[@]} -gt 0 ]; then
        echo -e "  ${C_MAGENTA}🛡️  PORTAS BLOQUEADAS NO FIREWALL (IPTABLES):${C_RESET}"
        b_idx=1
        for rb in "${REGRAS_BLOQUEADAS_CACHE[@]}"; do
            [ -z "$rb" ] && continue
            proto_b="${rb%%:*}"
            porta_b="${rb##*:}"
            echo -e "     ${C_YELLOW}[B${b_idx}] Porta ${porta_b} (${proto_b}) - Bloqueada no iptables${C_RESET}"
            ((b_idx++))
        done
        echo -e "     ${C_GRAY}(Pressione 'D' no menu para desbloquear)${C_RESET}"
        print_divider "-" "$C_GRAY"
    fi

    echo -e "${C_GRAY}Coletando conexões de rede ativas (TCP Listen & UDP)...${C_RESET}"
    mapfile -t LISTA_RAW < <(coletar_portas)

    # Filtragem dos itens
    ITENS_FILTRADOS=()
    for row in "${LISTA_RAW[@]}"; do
        [ -z "$row" ] && continue
        IFS='|' read -r r_porta r_proto r_addr r_pid r_proc <<< "$row"

        r_exposicao="$(get_tipo_exposicao "$r_addr")"
        r_servico="$(get_servico_conhecido "$r_porta")"

        classificacao="$(classificar_processo "$r_pid" "$r_proc" "$r_porta")"
        IFS='|' read -r r_podefechar r_categoria r_motivo <<< "$classificacao"

        r_firewall="Livre"
        if is_porta_bloqueada "$r_proto" "$r_porta"; then
            r_firewall="BLOQUEADA"
        fi

        # Filtro de seguras
        if [ "$filtro_seguras" -eq 1 ] && [[ "$r_podefechar" != SIM* ]]; then
            continue
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

    contador=1
    declare -A MAPA_ITENS

    if [ ${#ITENS_FILTRADOS[@]} -eq 0 ]; then
        echo -e "${C_YELLOW}  ⚠️  Nenhuma porta em escuta detectada no momento.${C_RESET}"
        echo -e "${C_GRAY}  • Se você acabou de iniciar um servidor (Python, Node, etc.), tecle [R] para recarregar.${C_RESET}"
        echo -e "${C_GRAY}  • Para auditar todos os processos do Android, instale o pacote [I] ou use Root [A].${C_RESET}\n"
    else
        # RENDERIZAÇÃO DA LISTA
        if [ "$IS_MOBILE" -eq 1 ]; then
            # MODO MOBILE: Formato de Cards compactos adaptados à tela do celular
            for item in "${ITENS_FILTRADOS[@]}"; do
                MAPA_ITENS[$contador]="$item"
                IFS='|' read -r p_porta p_proto p_addr p_pid p_proc p_expo p_fechar p_fw p_serv p_cat p_mot <<< "$item"

                # Badges de status
                cor_status="$C_GREEN"
                [ "$p_fechar" = "NUNCA" ] && cor_status="$C_RED"
                [ "$p_fechar" = "CUIDADO" ] && cor_status="$C_YELLOW"

                cor_fw="$C_GRAY"
                [ "$p_fw" = "BLOQUEADA" ] && cor_fw="$C_MAGENTA"

                cor_expo="$C_GREEN"
                [[ "$p_expo" == *"Exposta"* ]] && cor_expo="$C_YELLOW"

                echo -e "${C_CYAN}[${contador}]${C_RESET} ${C_BOLD}${p_porta}/${p_proto}${C_RESET}  ${cor_status}[${p_fechar}]${C_RESET}  ${cor_fw}FW:${p_fw}${C_RESET}"
                echo -e "    ${cor_expo}● ${p_expo}${C_RESET} (${p_addr})"
                echo -e "    ${C_WHITE}App:${C_RESET} ${p_proc} (PID: ${p_pid})"
                [ "$p_serv" != "-" ] && echo -e "    ${C_GRAY}Nota:${C_RESET} ${p_serv}"
                print_divider "." "$C_GRAY"

                ((contador++))
            done
        else
            # MODO DESKTOP / WIDE: Tabela completa alinhada
            printf "${C_CYAN}%-5s | %-6s | %-5s | %-7s | %-16s | %-14s | %-10s | %-9s | %-16s${C_RESET}\n" \
                "#" "PORTA" "PROTO" "PID" "PROCESSO" "EXPOSIÇÃO" "FECHAR?" "FIREWALL" "SERVIÇO / NOTA"
            print_divider "-" "$C_GRAY"

            for item in "${ITENS_FILTRADOS[@]}"; do
                MAPA_ITENS[$contador]="$item"
                IFS='|' read -r p_porta p_proto p_addr p_pid p_proc p_expo p_fechar p_fw p_serv p_cat p_mot <<< "$item"

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

                proc_trunc="${p_proc:0:16}"
                serv_trunc="${p_serv:0:16}"
                expo_trunc="${p_expo:0:14}"

                printf "${cor_linha}[%-3d] | %-6s | %-5s | %-7s | %-16s | %-14s | %-10s | %-9s | %-16s${C_RESET}\n" \
                    "$contador" "$p_porta" "$p_proto" "$p_pid" "$proc_trunc" "$expo_trunc" "$p_fechar" "$p_fw" "$serv_trunc"

                ((contador++))
            done
        fi
    fi

    print_divider "-" "$C_GRAY"
    echo -e "${C_CYAN}${C_BOLD}MENU DE OPÇÕES:${C_RESET}"
    if [ ${#ITENS_FILTRADOS[@]} -gt 0 ]; then
        echo -e "  ${C_WHITE}[1-$((contador-1))] Selecionar número para gerenciar (Kill ou Firewall)${C_RESET}"
    fi
    echo -e "  ${C_YELLOW}[B]     Buscar / Filtrar por texto (Porta, Processo ou Serviço)${C_RESET}"
    if [ -n "$termo_busca" ]; then
        echo -e "  ${C_YELLOW}[C]     Limpar busca ativa${C_RESET}"
    fi
    if [ ${#REGRAS_BLOQUEADAS_CACHE[@]} -gt 0 ]; then
        echo -e "  ${C_MAGENTA}[D]     Desbloquear porta(s) no Firewall (iptables)${C_RESET}"
    fi
    if [ "$filtro_seguras" -eq 1 ]; then
        echo -e "  ${C_WHITE}[F]     Filtro seguras: [DESATIVAR]${C_RESET}"
    else
        echo -e "  ${C_WHITE}[F]     Filtro seguras: [ATIVAR]${C_RESET}"
    fi
    echo -e "  ${C_WHITE}[R]     Recarregar lista${C_RESET}"
    if ! command -v ss >/dev/null 2>&1; then
        echo -e "  ${C_GREEN}[I]     Instalar iproute2/procps (Melhora detecção)${C_RESET}"
    fi
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
        [iI])
            clear
            echo -e "${C_GREEN}Instalando pacotes recomendados no Termux (iproute2 procps)...${C_RESET}"
            pkg install -y iproute2 procps 2>/dev/null || apt-get install -y iproute2 procps 2>/dev/null
            echo -e "\n${C_GREEN}Instalação finalizada! Pressione ENTER para recarregar...${C_RESET}"
            read -r
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
            read -r -p "Digite o termo para filtrar (ex: 8080, node, python): " termo_input
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
                    echo -e "${C_RED}Comandos 'tsu' ou 'su' não encontrados no Termux.${C_RESET}"
                    echo -e "${C_YELLOW}Dica: Instale o tsu com 'pkg install tsu' se seu aparelho tiver Root.${C_RESET}"
                    read -r -p "Pressione ENTER para continuar..."
                fi
            fi
            continue
            ;;
        [dD])
            clear
            print_divider "=" "$C_MAGENTA"
            echo -e "${C_MAGENTA}${C_BOLD}           DESBLOQUEIO DE PORTAS NO FIREWALL (IPTABLES)${C_RESET}"
            print_divider "=" "$C_MAGENTA"

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

            read -r -p "Escolha o número da regra para desbloquear: " desb_escolha
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
            if [[ "$escolha" =~ ^[0-9]+$ ]] && [ -n "${MAPA_ITENS[$escolha]}" ]; then
                selecionado="${MAPA_ITENS[$escolha]}"
                IFS='|' read -r s_porta s_proto s_addr s_pid s_proc s_expo s_fechar s_fw s_serv s_cat s_mot <<< "$selecionado"

                clear
                print_divider "=" "$C_CYAN"
                echo -e "${C_CYAN}${C_BOLD}          GERENCIAR PORTA ${s_porta} (${s_proto}) - TERMUX / ANDROID${C_RESET}"
                print_divider "=" "$C_CYAN"
                echo -e "  Porta:           ${C_WHITE}${s_porta} (${s_proto})${C_RESET}"
                if [[ "$s_expo" == *"Exposta"* ]]; then
                    echo -e "  Endereço IP:     ${s_addr} -> ${C_YELLOW}${s_expo}${C_RESET}"
                else
                    echo -e "  Endereço IP:     ${s_addr} -> ${C_GREEN}${s_expo}${C_RESET}"
                fi
                echo -e "  Serviço Notável: ${C_WHITE}${s_serv}${C_RESET}"
                echo -e "  Processo:        ${C_WHITE}${s_proc} (PID: ${s_pid})${C_RESET}"
                echo -e "  Categoria:       ${C_WHITE}${s_cat}${C_RESET}"
                echo -e "  Pode Fechar?:    ${C_YELLOW}${s_fechar} - ${s_mot}${C_RESET}"
                echo -e "  Status Firewall: ${C_WHITE}${s_fw}${C_RESET}"
                print_divider "-" "$C_GRAY"
                echo -e "${C_CYAN}O QUE VOCÊ DESEJA FAZER?${C_RESET}\n"
                echo -e "  ${C_RED}[1] Encerrar o processo (kill -9) - Libera a porta imediatamente${C_RESET}"
                echo -e "  ${C_YELLOW}[2] Bloquear a porta no Firewall (iptables) - SEM fechar app (Requer Root)${C_RESET}"
                echo -e "  ${C_GRAY}[0] Voltar ao menu principal${C_RESET}\n"

                read -r -p "Selecione a ação (1, 2 ou 0): " acao
                acao="$(echo "$acao" | tr -d '[:space:]')"

                if [ "$acao" = "1" ]; then
                    if [ "$s_pid" -le 0 ] 2>/dev/null; then
                        echo -e "\n${C_RED}ERRO: PID não identificado para esta porta (processo protegido pelo Android).${C_RESET}"
                        read -r -p "Pressione ENTER para voltar..."
                        continue
                    fi

                    if [ "$s_fechar" = "NUNCA" ]; then
                        echo -e "\n${C_RED}⚠️ BLOQUEIO DE SEGURANÇA: O processo '${s_proc}' (PID ${s_pid}) é vital para o Android!${C_RESET}"
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

                    if kill -9 "$s_pid" 2>/dev/null; then
                        write_audit_log "PROCESSO_ENCERRADO" "$s_porta" "$s_proto" "$s_pid" "$s_proc" "Encerrado com kill -9 pelo usuario"
                        echo -e "\n${C_GREEN}[OK] Processo '${s_proc}' (PID ${s_pid}) encerrado! Porta ${s_porta} liberada.${C_RESET}"
                        sleep 2
                    else
                        echo -e "\n${C_RED}Falha ao encerrar o processo ${s_pid}.${C_RESET}"
                        echo -e "${C_YELLOW}Dica: Processos do Android ou de outros apps requerem Root para serem encerrados.${C_RESET}"
                        read -r -p "Pressione ENTER para continuar..."
                    fi
                elif [ "$acao" = "2" ]; then
                    bloquear_porta_firewall "$s_porta" "$s_proto" "$s_pid" "$s_proc"
                fi
            else
                echo -e "${C_RED}Opção inválida.${C_RESET}"
                sleep 1
            fi
            ;;
    esac
done
