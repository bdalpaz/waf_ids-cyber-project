const express = require('express');
const cors = require('cors');
const path = require('path');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());

let logsForenses = [];

const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 10000;
const RATE_LIMIT_MAX = 20;

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

    if (verificarRateLimit(ipOrigem)) {
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

app.get('/api/forensic/logs', (req, res) => {
    return res.json(logsForenses);
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

    return res.json({ total, criticas, altas, medias, ipsUnicos, ultimas24h, porTipo });
});

app.get('/api/forensic/export', (req, res) => {
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
    return res.json({ mensagem: `${total} registros removidos.` });
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
    console.log(`[+] Acesse http://localhost:3000 para abrir o painel.`);
});
