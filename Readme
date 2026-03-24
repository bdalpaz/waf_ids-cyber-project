# Documentação: S.I.M. (Sistema de Inteligência e Monitorização)

## 1. Visão Geral do Projeto
O **S.I.M.** é um simulador interativo de um Centro de Operações de Segurança (SOC), desenvolvido com foco em Perícia Computacional e Segurança Ofensiva. A ferramenta atua simultaneamente como um Sistema de Deteção de Intrusões (IDS) e uma Firewall de Aplicações Web (WAF), permitindo intercetar, analisar e catalogar anomalias no tráfego de rede em tempo real.

O projeto foi concebido como um ambiente de laboratório fechado (*Home Lab*), integrando um módulo de simulação de ameaças (Red Team) e um painel de monitorização forense (Blue Team) numa única interface.

## 2. Arquitetura do Sistema
O sistema baseia-se numa arquitetura cliente-servidor simplificada, dividida em dois ficheiros principais:

* **Backend / Motor de Análise (`server.js`):** Desenvolvido em Node.js com o framework Express. Atua como o sensor do IDS. Utiliza um *middleware* global para realizar Inspeção Profunda de Pacotes (DPI - *Deep Packet Inspection*) em todos os pedidos HTTP recebidos, comparando os *payloads* com assinaturas de ataques conhecidos antes de permitir o acesso às rotas da aplicação.
* **Frontend / Painel de Inteligência (`index.html`):** Desenvolvido em HTML5, Vanilla JavaScript e estilizado com Bootstrap 5. Utiliza uma paleta de cores escuras ("Slate") característica de ferramentas de infraestrutura corporativas. A interface consome a API do backend de forma assíncrona para exibir as evidências.

## 3. Matriz de Deteção de Ameaças
O motor de análise possui assinaturas baseadas em Expressões Regulares (Regex) capazes de identificar e bloquear os seguintes vetores:

| Vetor de Ataque | Padrão Detetado (Exemplos) | Nível de Risco |
| :--- | :--- | :--- |
| **SQL Injection (SQLi)** | `UNION`, `SELECT`, `OR 1=1` | CRÍTICO |
| **Cross-Site Scripting (XSS)** | `<script>`, `onerror=` | ALTO |
| **Local File Inclusion (LFI)** | `../../`, `/etc/passwd` | CRÍTICO |
| **Remote Code Execution (RCE)** | `; cat`, `&& whoami` | CRÍTICO |
| **Acesso a Ficheiros Sensíveis** | `.env`, `config.php`, `id_rsa` | ALTO |
| **Reconhecimento / Scanners** | `Nmap`, `sqlmap`, `curl` | MÉDIO |

## 4. Funcionalidades Principais

### 4.1. Módulo de Simulação (Honeypot)
O painel inclui um gerador de tráfego integrado. O utilizador pode selecionar um vetor de ataque e disparar um *payload* malicioso formatado contra as próprias rotas isco do servidor (`/api/auth` e `/api/files`). Isto permite testar o motor do IDS de forma segura e controlada.

### 4.2. Registo e Formatação Forense
Sempre que uma anomalia é detetada, o motor interrompe a ligação (Retorna HTTP 403 Forbidden) e gera um registo forense contendo:
* Timestamp exato do evento.
* Endereço IP de origem.
* Método e Alvo solicitado (URL).
* Reconstrução do *Payload* (URL + Body + User-Agent).

No ecrã, o identificador único do incidente (gerado com base nos milissegundos do servidor) é convertido automaticamente para formato **Hexadecimal**, simulando a aparência de um *Hash* de evidência pericial. O *payload* capturado é encapsulado e neutralizado (`escapeHTML`) para evitar execuções acidentais no navegador do perito.

### 4.3. Monitorização em Tempo Real
O painel frontal faz *polling* automático (pedidos em segundo plano) à rota `/api/forensic/logs` a cada 3 segundos. Isto garante que a equipa de segurança veja os novos incidentes a surgir na grelha sem necessidade de recarregar a página manualmente.

## 5. Instalação e Execução

### Pré-requisitos
* [Node.js](https://nodejs.org/) instalado no sistema local.

### Passo a Passo
1. Abra o terminal (linha de comandos) e navegue até à pasta raiz do projeto.
2. Instale as dependências necessárias (Express e CORS) executando o comando:
   ```bash
   npm install express cors