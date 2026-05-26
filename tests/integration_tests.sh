#!/usr/bin/env bash
# ============================================================
# [Gabriel Henrique Robette Ferri] Sprint 4
# Suite de testes de integracao do S.I.M. (WAF/IDS)
#
# Objetivo: validar o comportamento ponta-a-ponta entre WAF,
# blocklist, persistencia e rotas internas. Resolve a causa-raiz
# do bug da Sprint 3, onde modulos foram validados isoladamente.
#
# Uso:
#   1) Em um terminal:  npm start
#   2) Em outro:        bash tests/integration_tests.sh
# ============================================================

set -u

BASE_URL="${BASE_URL:-http://localhost:3000}"
PASS=0
FAIL=0
FAILED_TESTS=()

# Cores para a saida (desativadas se nao for TTY)
if [ -t 1 ]; then
    VERDE='\033[0;32m'
    VERMELHO='\033[0;31m'
    AMARELO='\033[1;33m'
    AZUL='\033[0;34m'
    RESET='\033[0m'
else
    VERDE=''; VERMELHO=''; AMARELO=''; AZUL=''; RESET=''
fi

cabecalho() {
    echo ""
    echo -e "${AZUL}==============================================================${RESET}"
    echo -e "${AZUL} $1${RESET}"
    echo -e "${AZUL}==============================================================${RESET}"
}

# Verifica se o codigo HTTP retornado pelo curl bate com o esperado
verificar_status() {
    local descricao="$1"
    local esperado="$2"
    local obtido="$3"

    if [ "$obtido" = "$esperado" ]; then
        echo -e "  ${VERDE}[OK]${RESET} $descricao (HTTP $obtido)"
        PASS=$((PASS + 1))
    else
        echo -e "  ${VERMELHO}[FALHOU]${RESET} $descricao (esperado $esperado, obtido $obtido)"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$descricao")
    fi
}

# Verifica se a saida do curl contem um trecho esperado
verificar_contem() {
    local descricao="$1"
    local trecho="$2"
    local saida="$3"

    if echo "$saida" | grep -q "$trecho"; then
        echo -e "  ${VERDE}[OK]${RESET} $descricao"
        PASS=$((PASS + 1))
    else
        echo -e "  ${VERMELHO}[FALHOU]${RESET} $descricao (nao contem '$trecho')"
        FAIL=$((FAIL + 1))
        FAILED_TESTS+=("$descricao")
    fi
}

# ============================================================
# Pre-condicao: o servidor precisa estar de pe
# ============================================================
cabecalho "Pre-condicao: servidor disponivel"
if ! curl -s --max-time 3 "$BASE_URL/api/health" > /dev/null; then
    echo -e "${VERMELHO}[!] Servidor nao respondeu em $BASE_URL.${RESET}"
    echo -e "${AMARELO}    Suba o servidor com 'npm start' antes de rodar a suite.${RESET}"
    exit 2
fi
echo -e "${VERDE}[+] Servidor respondendo em $BASE_URL${RESET}"

# Limpa o estado de logs antes de comecar para isolar a execucao
curl -s -X DELETE "$BASE_URL/api/forensic/logs" > /dev/null

# ============================================================
# 1. Rotas internas e health-check
#    (regressao do bug da Sprint 3: a blocklist nao pode
#     bloquear rotas internas do painel)
# ============================================================
cabecalho "1. Rotas internas e health-check"

status=$(curl -s -o /tmp/sim_health.json -w "%{http_code}" "$BASE_URL/api/health")
verificar_status "GET /api/health responde 200" "200" "$status"
verificar_contem "Health-check expoe campo 'status'" "status" "$(cat /tmp/sim_health.json)"
verificar_contem "Health-check expoe 'uptimeSegundos'" "uptimeSegundos" "$(cat /tmp/sim_health.json)"

status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/forensic/logs")
verificar_status "GET /api/forensic/logs responde 200 (rota interna nao bloqueada)" "200" "$status"

status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/forensic/stats")
verificar_status "GET /api/forensic/stats responde 200" "200" "$status"

status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/forensic/blocklist")
verificar_status "GET /api/forensic/blocklist responde 200" "200" "$status"

# ============================================================
# 2. Deteccao de ameacas pelo motor WAF
# ============================================================
cabecalho "2. Deteccao de ameacas (assinaturas)"

# SQL Injection
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"usuario":"admin\u0027 OR 1=1 --"}' \
    "$BASE_URL/api/auth")
verificar_status "SQLi bloqueada com 403" "403" "$status"

# XSS
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/files?nome=%3Cscript%3Ealert(1)%3C/script%3E")
verificar_status "XSS bloqueada com 403" "403" "$status"

# Path traversal / LFI
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/files?path=../../etc/passwd")
verificar_status "LFI bloqueada com 403" "403" "$status"

# Command injection / RCE
status=$(curl -s -o /dev/null -w "%{http_code}" \
    "$BASE_URL/api/files?cmd=;cat%20/etc/shadow")
verificar_status "RCE bloqueada com 403" "403" "$status"

# Requisicao legitima nao deve ser bloqueada
status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST -H "Content-Type: application/json" \
    -d '{"usuario":"perito","senha":"forensic"}' \
    "$BASE_URL/api/auth")
verificar_status "Requisicao legitima (POST /api/auth) passa com 200" "200" "$status"

# ============================================================
# 3. Persistencia e integridade dos logs
# ============================================================
cabecalho "3. Persistencia de logs forenses"

# Da tempo pra gravacao assincrona em disco ser agendada/concluida
sleep 2

logs=$(curl -s "$BASE_URL/api/forensic/logs")
verificar_contem "Logs contem registro de SQL Injection" "SQL Injection" "$logs"
verificar_contem "Logs contem registro de XSS" "Cross-Site Scripting" "$logs"
verificar_contem "Logs contem registro de LFI" "Path Traversal" "$logs"

if [ -f "data/forensic_logs.json" ]; then
    echo -e "  ${VERDE}[OK]${RESET} Arquivo data/forensic_logs.json existe em disco"
    PASS=$((PASS + 1))
else
    echo -e "  ${AMARELO}[AVISO]${RESET} data/forensic_logs.json nao encontrado (talvez o teste esteja sendo executado fora da raiz do projeto)"
fi

# ============================================================
# 4. Paginacao e busca server-side
#    (entrega nova da Sprint 4)
# ============================================================
cabecalho "4. Paginacao e busca server-side"

resp=$(curl -s "$BASE_URL/api/forensic/logs?page=1&pageSize=2")
verificar_contem "Resposta paginada inclui 'paginacao'" "paginacao" "$resp"
verificar_contem "Resposta paginada inclui 'registros'" "registros" "$resp"
verificar_contem "Paginacao respeita pageSize" "\"pageSize\":2" "$resp"

resp=$(curl -s "$BASE_URL/api/forensic/logs?q=sql")
verificar_contem "Busca por 'sql' retorna ao menos 1 SQL Injection" "SQL Injection" "$resp"

resp=$(curl -s "$BASE_URL/api/forensic/logs?gravidade=CRITICA")
verificar_contem "Filtro por gravidade=CRITICA funciona" "CRITICA" "$resp"

# ============================================================
# 5. Blocklist automatica (interacao com o WAF)
# ============================================================
cabecalho "5. Blocklist automatica de IPs"

# Limpa eventuais bloqueios anteriores
curl -s -X DELETE "$BASE_URL/api/forensic/blocklist/::ffff:127.0.0.1" > /dev/null
curl -s -X DELETE "$BASE_URL/api/forensic/blocklist/127.0.0.1" > /dev/null
curl -s -X DELETE "$BASE_URL/api/forensic/logs" > /dev/null

# Dispara 6 ataques para ultrapassar o limiar de 5 incidentes
for i in 1 2 3 4 5 6; do
    curl -s -o /dev/null "$BASE_URL/api/files?path=../../etc/passwd&n=$i"
done

sleep 1
blocklist=$(curl -s "$BASE_URL/api/forensic/blocklist")
verificar_contem "Blocklist passa a conter ao menos 1 IP apos reincidencia" "127.0.0.1" "$blocklist"

# Mesmo bloqueado, o painel forense continua acessivel (regressao do bug Sprint 3)
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/forensic/logs")
verificar_status "Painel forense continua acessivel mesmo com IP local na blocklist" "200" "$status"

status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/health")
verificar_status "Health-check continua acessivel mesmo com IP local na blocklist" "200" "$status"

# Limpa a blocklist apos o teste para nao afetar a proxima execucao
curl -s -X DELETE "$BASE_URL/api/forensic/blocklist/::ffff:127.0.0.1" > /dev/null
curl -s -X DELETE "$BASE_URL/api/forensic/blocklist/::1" > /dev/null
curl -s -X DELETE "$BASE_URL/api/forensic/blocklist/127.0.0.1" > /dev/null

# ============================================================
# 6. Exportacao CSV (entrega nova da Sprint 4)
# ============================================================
cabecalho "6. Exportacao em CSV"

status=$(curl -s -o /tmp/sim_export.csv -w "%{http_code}" "$BASE_URL/api/forensic/export?formato=csv")
verificar_status "GET /api/forensic/export?formato=csv responde 200" "200" "$status"
verificar_contem "Cabecalho CSV inclui 'id'" "id" "$(head -1 /tmp/sim_export.csv)"
verificar_contem "Cabecalho CSV inclui 'ameaca'" "ameaca" "$(head -1 /tmp/sim_export.csv)"

# Exportacao em JSON continua funcionando
status=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/forensic/export")
verificar_status "Exportacao padrao (JSON) continua funcionando" "200" "$status"

# ============================================================
# Resumo
# ============================================================
TOTAL=$((PASS + FAIL))
cabecalho "Resumo da suite de integracao"
echo -e "  Total de checks:  $TOTAL"
echo -e "  ${VERDE}Passaram:         $PASS${RESET}"
echo -e "  ${VERMELHO}Falharam:         $FAIL${RESET}"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo -e "${VERMELHO}Testes que falharam:${RESET}"
    for t in "${FAILED_TESTS[@]}"; do
        echo -e "  - $t"
    done
    exit 1
fi

echo ""
echo -e "${VERDE}[+] Todos os checks de integracao passaram.${RESET}"
exit 0