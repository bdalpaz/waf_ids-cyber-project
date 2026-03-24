const express = require('express');
const cors = require('cors'); 
const path = require('path');

const app = express();
const port = 3000;

app.use(express.json()); 
app.use(cors()); 

// Banco de evidências em memória
let logsForenses = [];

// Middleware IDS: Interceptador de Tráfego e Análise de Assinaturas
app.use((req, res, next) => {
    const ipOrigem = req.ip || req.connection.remoteAddress;
    const metodo = req.method;
    const userAgent = req.get('User-Agent') || 'Desconhecido';
    const dataHora = new Date().toISOString();
    
    // Decodifica a URL para evitar ofuscação
    let urlAcessada = req.originalUrl;
    try {
        urlAcessada = decodeURIComponent(req.originalUrl);
    } catch (e) {}

    // Captura o corpo da requisição
    let corpoDaRequisicao = "";
    if (req.body && Object.keys(req.body).length > 0) {
        corpoDaRequisicao = JSON.stringify(req.body); 
    }

    // Monta o payload completo
    const payloadCompleto = `${urlAcessada} ${corpoDaRequisicao} ${userAgent}`;
    
    // Regras de detecção
    const assinaturas = [
        { regex: /(UNION|SELECT|INSERT|DROP|--|1=1)/i, tipo: "SQL Injection (SQLi)", gravidade: "CRÍTICA" },
        { regex: /(<script>|javascript:|onerror=)/i, tipo: "Cross-Site Scripting (XSS)", gravidade: "ALTA" },
        { regex: /(\.\.\/|\.\.\\|etc\/passwd|boot\.ini)/i, tipo: "Path Traversal / LFI", gravidade: "CRÍTICA" },
        { regex: /(nmap|sqlmap|nikto|curl|wget)/i, tipo: "Ferramenta de Automação/Scan", gravidade: "MÉDIA" },
        { regex: /(\.env|config\.php|id_rsa)/i, tipo: "Acesso a Arquivos Sensíveis", gravidade: "ALTA" },
        { regex: /(;|\&\&|\|\||`)(ls|cat|whoami|pwd|id)/i, tipo: "Command Injection (RCE)", gravidade: "CRÍTICA" }
    ];

    let ameacaDetectada = null;

    // Varredura
    for (let assinatura of assinaturas) {
        if (assinatura.regex.test(payloadCompleto)) {
            ameacaDetectada = assinatura;
            break;
        }
    }

    // Registro da evidência
    if (ameacaDetectada) {
        const logEntry = {
            id: Date.now(), // Identificador único da evidência
            timestamp: dataHora,
            ip: ipOrigem,
            metodo: metodo,
            alvo: req.originalUrl,
            ameaca: ameacaDetectada.tipo,
            gravidade: ameacaDetectada.gravidade,
            payload: payloadCompleto.substring(0, 150) + "..." // Truncado para visualização no painel
        };
        
        logsForenses.unshift(logEntry);

        // Bloqueio silencioso para não vazar informações ao atacante
        return res.status(403).json({ 
            erro: "Acesso bloqueado por política de segurança.",
            codigo_incidente: logEntry.id 
        });
    }

    next();
});

// Rotas 
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// API para o Painel consumir as evidências
app.get('/api/forensic/logs', (req, res) => {
    return res.json(logsForenses);
});

// Endpoints Honeypot 
app.post('/api/auth', (req, res) => {
    res.status(200).json({ message: "Login simulado efetuado." });
});
app.get('/api/files', (req, res) => {
    res.status(200).json({ message: "Acesso a sistema de arquivos simulado." });
});

app.listen(port, () => {
  console.log(`[+] Sistema de Análise de Tráfego ativo na porta ${port}`);
  console.log(`[+] Módulo de Inspeção Profunda (DPI) inicializado.`);
  console.log(`[+] Acesse http://localhost:3000 para abrir o painel.`);
});