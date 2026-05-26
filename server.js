const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const fsp = require('fs').promises;

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());

// ============================================================
// [Alice Botton Dal Paz] Sprint 4
// Persistencia forense em disco com gravacao ASSINCRONA.
// Substitui o writeFileSync sincrono da Sprint 3 (que travava
// o event loop sob carga alta) por fs.promises.writeFile com
// serializacao por fila: enquanto uma gravacao esta em
// andamento, novas requisicoes sao agrupadas e gravadas em
// seguida, evitando race conditions no arquivo.
// ============================================================
const DATA_DIR = path.join(__dirname, 'data');
const LOG_FILE = path.join(DATA_DIR, 'forensic_logs.json');
const horaInicializacao = Date.now();

let logsForenses = [];

async function garantirDiretorioDados() {
    try {
        await fsp.mkdir(DATA_DIR, { recursive: true });
    } catch (e) {
        console.error('[!] Nao foi possivel criar o diretorio de dados:', e.message);
    }
}

async function carregarLogsDoDisco() {
    try {
        const conteudo = await fsp.readFile(LOG_FILE, 'utf-8');
        const dados = JSON.parse(conteudo);
        if (Array.isArray(dados)) {
            logsForenses = dados;
            console.log(`[+] ${logsForenses.length} registros forenses recuperados do disco.`);
        }
    } catch (e) {
        // Arquivo inexistente no primeiro start nao e erro real
        if (e.code !== 'ENOENT') {
            console.error('[!] Falha ao carregar logs persistidos:', e.message);
        }
        logsForenses = [];
    }
}

// Estado da fila de gravacao assincrona
let gravando = false;
let novaGravacaoPendente = false;

async function persistirLogs() {
    // Se ja existe uma gravacao em andamento, apenas marca que
    // outra precisa acontecer em seguida (coalesce). Evita
    // gravar N vezes seguidas quando chegam N requisicoes juntas.
    if (gravando) {
        novaGravacaoPendente = true;
        return;
    }
    gravando = true;
    try {
        do {
            novaGravacaoPendente = false;
            const snapshot = JSON.stringify(logsForenses);
            // Gravacao realmente assincrona: nao bloqueia o event loop
            await fsp.writeFile(LOG_FILE, snapshot, 'utf-8');
        } while (novaGravacaoPendente);
    } catch (e) {
        console.error('[!] Falha ao persistir logs em disco:', e.message);
    } finally {
        gravando = false;
    }
}

// Inicializa persistencia antes de aceitar trafego
(async () => {
    await garantirDiretorioDados();
    await carregarLogsDoDisco();
})();

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 10000;
const RATE_LIMIT_MAX = 20;

// ============================================================
// [Gabriel Henrique Robette Ferri] Blocklist automatica de IPs
// Um IP que acumula muitos incidentes graves passa a ser
// bloqueado preventivamente, antes mesmo da analise de payload.
// ============================================================
const contagemIncidentesPorIp = new Map();
const ipsBloqueados = new Map(); // ip -> { motivo, desde, expira }
const LIMITE_INCIDENTES_BLOCKLIST = 5;
const DURACAO_BLOCKLIST = 5 * 60 * 1000; // 5 minutos

function registrarIncidenteIp(ip) {
    const atual = contagemIncidentesPorIp.get(ip) || 0;
    const novoTotal = atual + 1;
    contagemIncidentesPorIp.set(ip, novoTotal);

    if (novoTotal >= LIMITE_INCIDENTES_BLOCKLIST && !ipsBloqueados.has(ip)) {
        ipsBloqueados.set(ip, {
            motivo: `Reincidencia: ${novoTotal} incidentes detectados`,
            desde: new Date().toISOString(),
            expira: Date.now() + DURACAO_BLOCKLIST
        });
        console.log(`[!] IP ${ip} adicionado a blocklist (${novoTotal} incidentes).`);
    }
}

function ipEstaBloqueado(ip) {
    const registro = ipsBloqueados.get(ip);
    if (!registro) return false;
    if (Date.now() > registro.expira) {
        ipsBloqueados.delete(ip);
        contagemIncidentesPorIp.delete(ip);
        return false;
    }
    return true;
}

setInterval(() => {
    const agora = Date.now();
    for (const [ip, registro] of ipsBloqueados) {
        if (agora > registro.expira) {
            ipsBloqueados.delete(ip);
            contagemIncidentesPorIp.delete(ip);
        }
    }
}, 60000);

function verificarRateLimit(ip) {
    const agora = Date.now();
    const registro = rateLimitMap.get(ip);

    if (!registro || (agora - registro.inicio) > RATE_LIMIT_WINDOW) {
        rateLimitMap.set(ip, { inicio: agora, contagem: 1 });
        return false;
    }

    registro.contagem++;
    return registro.contagem > RATE_LIMIT_MAX;
}

setInterval(() => {
    const agora = Date.now();
    for (const [ip, registro] of rateLimitMap) {
        if ((agora - registro.inicio) > RATE_LIMIT_WINDOW * 2) {
            rateLimitMap.delete(ip);
        }
    }
}, 30000);

app.use((req, res, next) => {
    const ipOrigem = req.ip || req.connection.remoteAddress;
    const metodo = req.method;
    const userAgent = req.get('User-Agent') || 'Desconhecido';
    const dataHora = new Date().toISOString();

    // [Bugfix Sprint 3] Rotas internas de monitoramento/forense nao
    // passam pelo WAF, evitando que a equipe de seguranca seja
    // bloqueada pela propria blocklist ao consultar o painel.
    const rotasIsentas = ['/api/health', '/api/forensic/'];
    if (rotasIsentas.some(rota => req.path.startsWith(rota)) || req.path === '/') {
        return next();
    }

    let urlAcessada = req.originalUrl;
    try {
        urlAcessada = decodeURIComponent(req.originalUrl);
    } catch (e) {}

    let corpoDaRequisicao = "";
    if (req.body && Object.keys(req.body).length > 0) {
        corpoDaRequisicao = JSON.stringify(req.body);
    }

    const referer = req.get('Referer') || '';
    const refererLimpo = referer.replace(/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/?/i, '');
    const payloadCompleto = `${urlAcessada} ${corpoDaRequisicao} ${userAgent} ${refererLimpo}`;

    const assinaturas = [
        { regex: /(UNION\s+(ALL\s+)?SELECT|SELECT\s+.*FROM|INSERT\s+INTO|DROP\s+TABLE|DELETE\s+FROM|UPDATE\s+.*SET|--|1=1|'(\s)*(OR|AND))/i, tipo: "SQL Injection (SQLi)", gravidade: "CRITICA", mitre: "T1190" },
        { regex: /(<script[\s>]|javascript:|onerror\s*=|onload\s*=|onclick\s*=|onmouseover\s*=|onfocus\s*=|<img\s+.*on\w+=|<svg\s+.*on\w+=|<iframe)/i, tipo: "Cross-Site Scripting (XSS)", gravidade: "ALTA", mitre: "T1059.007" },
        { regex: /(\.\.\/|\.\.\\|etc\/passwd|etc\/shadow|boot\.ini|win\.ini|proc\/self)/i, tipo: "Path Traversal / LFI", gravidade: "CRITICA", mitre: "T1083" },
        { regex: /(nmap|sqlmap|nikto|dirbuster|gobuster|wfuzz|burpsuite|metasploit|hydra|john)/i, tipo: "Ferramenta de Automacao/Scan", gravidade: "MEDIA", mitre: "T1595" },
        { regex: /(\.env|config\.php|config\.yml|id_rsa|\.git\/|wp-config|database\.yml|credentials)/i, tipo: "Acesso a Arquivos Sensiveis", gravidade: "ALTA", mitre: "T1552" },
        { regex: /(;|\&\&|\|\||`)(ls|cat|whoami|pwd|id|uname|curl|wget|nc |bash|sh |python|perl|ruby)/i, tipo: "Command Injection (RCE)", gravidade: "CRITICA", mitre: "T1059" },
        { regex: /(gopher:\/\/|dict:\/\/|file:\/\/|ldap:\/\/|ftp:\/\/127|http:\/\/169\.254|http:\/\/localhost|http:\/\/127\.0\.0\.1|http:\/\/0\.0\.0\.0)/i, tipo: "Server-Side Request Forgery (SSRF)", gravidade: "CRITICA", mitre: "T1210" },
        { regex: /(<!ENTITY|<!DOCTYPE\s+\w+\s+SYSTEM|<\?xml.*ENTITY)/i, tipo: "XML External Entity (XXE)", gravidade: "CRITICA", mitre: "T1059" },
        { regex: /(\%00|\\x00|\\u0000|%0d%0a|%0D%0A|\r\n.*HTTP\/)/i, tipo: "Null Byte / HTTP Smuggling", gravidade: "ALTA", mitre: "T1190" },
        { regex: /(base64_decode|eval\s*\(|exec\s*\(|system\s*\(|passthru|shell_exec|phpinfo|assert\s*\()/i, tipo: "Execucao de Codigo (Code Injection)", gravidade: "CRITICA", mitre: "T1059" },
    ];

    let ameacaDetectada = null;

    // [Gabriel] IP ja na blocklist: barra imediatamente
    if (ipEstaBloqueado(ipOrigem)) {
        ameacaDetectada = { tipo: "IP na Blocklist (Reincidente)", gravidade: "CRITICA", mitre: "T1595" };
    }

    if (!ameacaDetectada && verificarRateLimit(ipOrigem)) {
        ameacaDetectada = { tipo: "Brute Force / Rate Limit Excedido", gravidade: "ALTA", mitre: "T1110" };
    }

    if (!ameacaDetectada) {
        for (let assinatura of assinaturas) {
            if (assinatura.regex.test(payloadCompleto)) {
                ameacaDetectada = assinatura;
                break;
            }
        }
    }

    if (ameacaDetectada) {
        const logEntry = {
            id: Date.now(),
            timestamp: dataHora,
            ip: ipOrigem,
            metodo: metodo,
            alvo: req.originalUrl,
            ameaca: ameacaDetectada.tipo,
            gravidade: ameacaDetectada.gravidade,
            mitre: ameacaDetectada.mitre || "N/A",
            userAgent: userAgent.substring(0, 100),
            payload: payloadCompleto.substring(0, 200)
        };

        logsForenses.unshift(logEntry);

        if (logsForenses.length > 500) {
            logsForenses = logsForenses.slice(0, 500);
        }

        // [Gabriel] contabiliza incidente para a blocklist automatica
        registrarIncidenteIp(ipOrigem);

        // [Alice] persiste os logs em disco (agora assincrono)
        persistirLogs();

        return res.status(403).json({
            erro: "Acesso bloqueado por politica de seguranca.",
            codigo_incidente: logEntry.id
        });
    }

    next();
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// ============================================================
// [Gabriel Henrique Robette Ferri] Sprint 4
// Paginacao + busca + filtro SERVER-SIDE em /api/forensic/logs
//
// Substitui o "retorna a lista inteira" da Sprint 3, que nao
// escalava bem com centenas de logs. Mantida compatibilidade
// retro: sem query params, devolve os mesmos campos antigos
// (apenas o array de registros), para nao quebrar a UI atual.
//
// Query params suportados:
//   ?page=N&pageSize=M    -> ativa modo paginado
//   ?q=texto              -> busca em ameaca/ip/alvo/payload
//   ?gravidade=CRITICA    -> filtra por gravidade
// ============================================================
app.get('/api/forensic/logs', (req, res) => {
    const { page, pageSize, q, gravidade } = req.query;

    // Modo legado: nenhum parametro -> devolve array bruto
    // (compatibilidade com o frontend atual da Sprint 3)
    if (!page && !pageSize && !q && !gravidade) {
        return res.json(logsForenses);
    }

    let filtrados = logsForenses;

    if (gravidade) {
        const g = String(gravidade).toUpperCase();
        filtrados = filtrados.filter(l => l.gravidade === g);
    }

    if (q) {
        const termo = String(q).toLowerCase();
        filtrados = filtrados.filter(l =>
            (l.ameaca || '').toLowerCase().includes(termo) ||
            (l.ip || '').toLowerCase().includes(termo) ||
            (l.alvo || '').toLowerCase().includes(termo) ||
            (l.payload || '').toLowerCase().includes(termo)
        );
    }

    const totalFiltrado = filtrados.length;
    const pageNum = Math.max(1, parseInt(page, 10) || 1);
    const pageSizeNum = Math.min(100, Math.max(1, parseInt(pageSize, 10) || 20));
    const inicio = (pageNum - 1) * pageSizeNum;
    const registros = filtrados.slice(inicio, inicio + pageSizeNum);
    const totalPaginas = Math.max(1, Math.ceil(totalFiltrado / pageSizeNum));

    return res.json({
        paginacao: {
            page: pageNum,
            pageSize: pageSizeNum,
            totalRegistros: totalFiltrado,
            totalPaginas
        },
        filtros: { q: q || null, gravidade: gravidade || null },
        registros
    });
});

app.get('/api/forensic/stats', (req, res) => {
    const total = logsForenses.length;
    const criticas = logsForenses.filter(l => l.gravidade === 'CRITICA').length;
    const altas = logsForenses.filter(l => l.gravidade === 'ALTA').length;
    const medias = logsForenses.filter(l => l.gravidade === 'MEDIA').length;

    const porTipo = {};
    logsForenses.forEach(l => {
        porTipo[l.ameaca] = (porTipo[l.ameaca] || 0) + 1;
    });

    const ipsUnicos = new Set(logsForenses.map(l => l.ip)).size;

    const agora = Date.now();
    const ultimas24h = logsForenses.filter(l => (agora - new Date(l.timestamp).getTime()) < 86400000).length;

    // [Anthony Guilherme Cazuni da Silva] Ranking de IPs ofensores
    // para alimentar o painel de inteligencia do frontend.
    const contagemIp = {};
    logsForenses.forEach(l => {
        contagemIp[l.ip] = (contagemIp[l.ip] || 0) + 1;
    });
    const topIps = Object.entries(contagemIp)
        .map(([ip, qtd]) => ({ ip, qtd }))
        .sort((a, b) => b.qtd - a.qtd)
        .slice(0, 5);

    return res.json({ total, criticas, altas, medias, ipsUnicos, ultimas24h, porTipo, topIps });
});

// ============================================================
// [Anthony Guilherme Cazuni da Silva] Sprint 4
// Exportacao em CSV alem do JSON ja existente.
// O perito pode abrir o relatorio direto no Excel/LibreOffice.
//
// Query params:
//   ?formato=csv  -> exporta CSV (default continua JSON)
// ============================================================
function escaparCampoCsv(valor) {
    if (valor === null || valor === undefined) return '';
    const s = String(valor);
    // RFC 4180: campo com aspas, virgula ou quebra de linha precisa
    // ser envelopado em aspas, e aspas duplas viram aspas duplas duplas
    if (/[",\r\n]/.test(s)) {
        return '"' + s.replace(/"/g, '""') + '"';
    }
    return s;
}

function logsParaCsv(logs) {
    const colunas = ['id', 'timestamp', 'ip', 'metodo', 'alvo', 'ameaca', 'gravidade', 'mitre', 'userAgent', 'payload'];
    const linhas = [colunas.join(',')];
    for (const log of logs) {
        const linha = colunas.map(c => escaparCampoCsv(log[c])).join(',');
        linhas.push(linha);
    }
    // \r\n entre linhas conforme RFC 4180
    return linhas.join('\r\n');
}

app.get('/api/forensic/export', (req, res) => {
    const formato = String(req.query.formato || 'json').toLowerCase();

    if (formato === 'csv') {
        const csv = logsParaCsv(logsForenses);
        res.setHeader('Content-Disposition', 'attachment; filename=sim_forensic_logs.csv');
        res.setHeader('Content-Type', 'text/csv; charset=utf-8');
        // BOM UTF-8: faz o Excel abrir acentos corretamente
        return res.send('\uFEFF' + csv);
    }

    res.setHeader('Content-Disposition', 'attachment; filename=sim_forensic_logs.json');
    res.setHeader('Content-Type', 'application/json');
    return res.json({
        exportadoEm: new Date().toISOString(),
        totalRegistros: logsForenses.length,
        registros: logsForenses
    });
});

app.delete('/api/forensic/logs', (req, res) => {
    const total = logsForenses.length;
    logsForenses = [];
    persistirLogs(); // [Alice] reflete a limpeza no disco
    return res.json({ mensagem: `${total} registros removidos.` });
});

// ============================================================
// [Alice Botton Dal Paz] Health-check do servico
// Permite monitorar disponibilidade, uptime e estado da
// persistencia de logs.
// ============================================================
app.get('/api/health', (req, res) => {
    const uptimeSegundos = Math.floor((Date.now() - horaInicializacao) / 1000);
    return res.json({
        status: 'online',
        servico: 'S.I.M. WAF/IDS',
        uptimeSegundos,
        totalLogs: logsForenses.length,
        persistenciaAtiva: fs.existsSync(DATA_DIR),
        timestamp: new Date().toISOString()
    });
});

// ============================================================
// [Gabriel Henrique Robette Ferri] Gestao da blocklist
// Consulta os IPs atualmente bloqueados e permite remover
// manualmente um IP da lista (desbloqueio).
// ============================================================
app.get('/api/forensic/blocklist', (req, res) => {
    const lista = [];
    for (const [ip, registro] of ipsBloqueados) {
        lista.push({
            ip,
            motivo: registro.motivo,
            desde: registro.desde,
            expiraEm: Math.max(0, Math.floor((registro.expira - Date.now()) / 1000))
        });
    }
    return res.json({ total: lista.length, bloqueados: lista });
});

app.delete('/api/forensic/blocklist/:ip', (req, res) => {
    const ip = req.params.ip;
    if (ipsBloqueados.has(ip)) {
        ipsBloqueados.delete(ip);
        contagemIncidentesPorIp.delete(ip);
        return res.json({ mensagem: `IP ${ip} removido da blocklist.` });
    }
    return res.status(404).json({ erro: `IP ${ip} nao esta na blocklist.` });
});

app.post('/api/auth', (req, res) => {
    res.status(200).json({ message: "Login simulado efetuado." });
});
app.get('/api/files', (req, res) => {
    res.status(200).json({ message: "Acesso a sistema de arquivos simulado." });
});
app.get('/api/admin', (req, res) => {
    res.status(200).json({ message: "Painel administrativo simulado." });
});
app.post('/api/upload', (req, res) => {
    res.status(200).json({ message: "Upload simulado efetuado." });
});

app.listen(port, () => {
    console.log(`[+] S.I.M. - Sistema de Inteligencia e Monitoramento`);
    console.log(`[+] Motor WAF/IDS ativo na porta ${port}`);
    console.log(`[+] ${10} assinaturas de ameacas carregadas`);
    console.log(`[+] Rate Limiting: ${RATE_LIMIT_MAX} req/${RATE_LIMIT_WINDOW/1000}s por IP`);
    console.log(`[+] Blocklist automatica: ${LIMITE_INCIDENTES_BLOCKLIST} incidentes -> bloqueio de ${DURACAO_BLOCKLIST/60000}min`);
    console.log(`[+] Persistencia de logs (assincrona): ${LOG_FILE}`);
    console.log(`[+] Acesse http://localhost:3000 para abrir o painel.`);
});