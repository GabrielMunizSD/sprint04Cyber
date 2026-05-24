# 🏨 Totem Concierge — Aplicação Flask Segura

Projeto desenvolvido para a disciplina de Segurança em Sistemas Embarcados.  
Implementa os controles de segurança exigidos no **Entregável 3**.

---

## 📁 Estrutura do Projeto

```
totem-flask/
├── app.py                  # Aplicação principal Flask
├── requirements.txt        # Dependências Python
├── .env.example            # Modelo do arquivo de credenciais (versionado)
├── .env                    # Credenciais reais (NÃO versionado — está no .gitignore)
├── .gitignore
├── logs/
│   └── totem.log           # Gerado automaticamente em tempo de execução
└── templates/
    ├── base.html           # Layout base
    ├── totem.html          # Tela pública do totem
    ├── login.html          # Página de login administrativo
    ├── admin.html          # Painel administrativo (restrito)
    └── logs.html           # Visualizador de logs (restrito)
```

---

## ⚙️ Como executar

### 1. Instalar dependências
```bash
pip install -r requirements.txt
```

### 2. Configurar credenciais
```bash
# Copie o modelo e edite com suas credenciais reais
cp .env.example .env
nano .env
```

Conteúdo do `.env`:
```
SECRET_KEY=gere-uma-chave-com-python-secrets
ADMIN_USER=admin
ADMIN_PASS=SuaSenhaForte
IDLE_TIMEOUT=10
```

> 💡 Para gerar uma SECRET_KEY segura:  
> `python -c "import secrets; print(secrets.token_hex(32))"`

### 3. Rodar a aplicação
```bash
python app.py
```

Acesse em: `http://localhost:5000`

---

## 🔒 Controles de Segurança Implementados

### 1. Controle de Acesso (duas áreas)

| Rota | Nível | Descrição |
|---|---|---|
| `/` | 🌐 Público | Tela do totem — visível a qualquer pessoa |
| `/login` | 🌐 Público | Formulário de autenticação |
| `/admin` | 🔐 Admin | Painel de controle (exige login) |
| `/admin/led` | 🔐 Admin | Acionamento do LED (exige login) |
| `/admin/logs` | 🔐 Admin | Visualização de logs (exige login) |
| `/api/presenca` | 🌐 Público | Endpoint do sensor de proximidade |

Implementado com o decorador `@login_required` e `Flask sessions`.

---

### 2. Proteção de Credenciais

- Credenciais armazenadas no arquivo `.env` (fora do código-fonte)
- `.env` listado no `.gitignore` — **nunca enviado ao repositório**
- O arquivo `.env.example` (sem dados reais) é versionado como referência
- A aplicação lê os segredos via `python-dotenv` (`os.getenv(...)`)

---

### 3. Proteção da Aplicação Web

- **Debug desativado:** `app.config["DEBUG"] = False`
- **Validação de entradas:** campos obrigatórios, limite de tamanho (80/128 chars), verificação de tipo
- **Logs de eventos** gravados em `logs/totem.log`:

| Evento | Nível |
|---|---|
| Login bem-sucedido | INFO |
| Login com credenciais erradas | WARNING |
| Tentativa de acesso com entrada inválida | WARNING |
| Acesso negado à área admin (sem login) | WARNING |
| LED acionado | INFO |
| Logs acessados | INFO |
| Sessão de visitante iniciada/encerrada | INFO |

---

### 4. Controle Temporal da Sessão

- Quando o sensor de proximidade detecta presença → `/api/presenca` é chamado com `{"presente": true}` → sessão do visitante iniciada
- Um timer regressivo na tela conta os segundos restantes (configurável via `IDLE_TIMEOUT` no `.env`)
- Após `IDLE_TIMEOUT` segundos sem presença → `/api/presenca` com `{"presente": false}` → sessão encerrada e totem retorna ao modo inicial
- Em produção no Raspberry Pi, substituir os botões de simulação pela leitura real do sensor GPIO

---

## 🎥 Roteiro para o vídeo (até 5 min)

1. Mostrar a **tela pública** do totem (`/`)
2. Tentar acessar `/admin` sem login → mostrar redirecionamento e log gerado
3. Fazer **login com senha errada** → mostrar mensagem de erro e log
4. Fazer **login correto** → entrar no painel admin
5. **Acionar o LED** → mostrar log registrado
6. Acessar **`/admin/logs`** → mostrar todos os eventos gerados
7. Demonstrar o **controle de sessão** (sensor de proximidade simulado)

---

## 📦 Dependências

```
flask==3.1.1
python-dotenv==1.0.1
```
