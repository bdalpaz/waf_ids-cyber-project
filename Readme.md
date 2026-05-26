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
   npm install express cors   ```
3. Inicie o servidor:
   ```bash
   npm start
   ```
4. Acesse `http://localhost:3000` no navegador.

## 6. Funcionalidades da Sprint 3

A Sprint 3 ("Persistência, Inteligência e Bloqueio Ativo") agregou três
módulos ao sistema:

### 6.1. Persistência Forense em Disco
Os logs deixaram de ser voláteis. As evidências são gravadas em
`data/forensic_logs.json` e recarregadas automaticamente quando o servidor
reinicia, garantindo a cadeia de custódia das evidências. Inclui também o
endpoint `GET /api/health` para monitoramento de disponibilidade e uptime.

### 6.2. Blocklist Automática de IPs
IPs que acumulam 5 ou mais incidentes são adicionados a uma blocklist e
passam a ser barrados preventivamente por 5 minutos, antes mesmo da análise
de payload. A lista pode ser consultada via `GET /api/forensic/blocklist` e
um IP pode ser liberado manualmente via `DELETE /api/forensic/blocklist/:ip`.

### 6.3. Painel de Inteligência
Nova seção no frontend que apresenta a distribuição de ataques por tipo
(gráfico de barras) e o ranking dos cinco IPs mais ofensores, consumindo
dados agregados do endpoint `GET /api/forensic/stats`.

## 7. Funcionalidades da Sprint 4

A Sprint 4 ("Endurecimento, Testes e Pagamento de Débito Técnico")
focou em eliminar os débitos técnicos da Sprint 3 e em aumentar a
robustez do motor WAF/IDS, com base nos indicadores da sprint anterior
(taxa de retrabalho de 33%, bug crítico de blocklist descoberto tarde).

### 7.1. Persistência Assíncrona (Alice)
A gravação dos logs forenses migrou de `fs.writeFileSync` (síncrono,
bloqueava o event loop sob carga) para `fs.promises.writeFile`.
A implementação usa uma fila com *coalesce*: enquanto uma gravação
está em andamento, gravações subsequentes são agrupadas, evitando
*race conditions* sobre o arquivo `data/forensic_logs.json`. Esse
item paga o débito técnico registrado na retrospectiva da Sprint 3.

### 7.2. Paginação e Busca Server-Side (Gabriel)
A rota `GET /api/forensic/logs` ganhou parâmetros de query:

| Parâmetro | Efeito |
| :--- | :--- |
| `page=N` | Página solicitada (1-indexada) |
| `pageSize=M` | Tamanho da página (1–100, default 20) |
| `q=texto` | Busca em `ameaca`, `ip`, `alvo` e `payload` |
| `gravidade=CRITICA` | Filtra por nível de severidade |

Quando nenhum parâmetro é passado, a rota mantém o comportamento
antigo (array bruto), garantindo compatibilidade retroativa com o
frontend da Sprint 3.

### 7.3. Exportação em CSV (Anthony)
A rota `GET /api/forensic/export?formato=csv` exporta os logs em
formato CSV (RFC 4180), com cabeçalho UTF-8 (BOM) para abrir
corretamente no Excel e LibreOffice. O painel ganhou um botão
"Exportar CSV" ao lado do já existente "Exportar JSON".

### 7.4. Suíte de Testes de Integração (Gabriel)
O diretório `tests/` passa a conter o script `integration_tests.sh`,
que valida ponta a ponta:

* rotas internas (`/api/health`, `/api/forensic/*`) continuam acessíveis;
* detecção de SQLi, XSS, LFI e RCE retorna HTTP 403;
* requisição legítima continua respondendo 200;
* persistência grava no disco;
* paginação, busca e filtro server-side respondem corretamente;
* blocklist é acionada após reincidência e **não** bloqueia o painel;
* exportação em CSV e JSON funcionam.

Para executar:

```bash
# Terminal 1
npm start

# Terminal 2
bash tests/integration_tests.sh
```

O script deve ser rodado antes de cada `merge` (ação combinada na
retrospectiva).

## 8. Definition of Done (DoD)

Critério comum acordado pela equipe para considerar uma tarefa
encerrada. Vale para qualquer feature, *bugfix* ou refatoração.

Uma tarefa só pode ser marcada como "concluída" quando **todos** os
itens abaixo são verdadeiros:

1. **Funcionalidade implementada** conforme o item priorizado no
   *planning*.
2. **Testada manualmente** com `curl` cobrindo o caminho feliz e ao
   menos um caso de erro.
3. **Integrada no script `tests/integration_tests.sh`**, e o script
   completo passa sem falhas (`exit 0`).
4. **Sem regressão**: as rotas internas (`/api/health`, painel
   forense) continuam acessíveis mesmo com a feature ativa.
5. **Sem débito técnico oculto**: se algo ficou aquém do ideal
   (por exemplo, uma gravação síncrona), isso é registrado
   explicitamente na retrospectiva, e não escondido no código.
6. **Comentada no código** com tag do responsável (`[Nome]`) e
   referência à sprint, para preservar a rastreabilidade.
7. **Documentada no README** (esta seção 7 ou a 8) quando expõe
   API/endpoint novo, parâmetro novo ou comando novo.
8. **Code review informal** feito por outro membro do trio antes do
   `merge` na `main`.

Esse DoD foi criado em resposta à causa-raiz identificada na
retrospectiva da Sprint 3: "cada desenvolvedor encerrava a tarefa com
critérios diferentes de qualidade".