import os
import time
import sqlite3
import secrets
import threading
import logging
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, flash, g
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# ── Tenta importar RPi.GPIO ───────────────────────────────────────────────────
try:
    import RPi.GPIO as GPIO
    RASPBERRY = True
except ImportError:
    RASPBERRY = False

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", secrets.token_hex(32))

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIGURAÇÕES
# ══════════════════════════════════════════════════════════════════════════════
app.config["DEBUG"]                          = False
app.config["PERMANENT_SESSION_LIFETIME"]     = timedelta(minutes=30)

# ── Cookies de sessão seguros (Hardening #1) ──────────────────────────────────
app.config["SESSION_COOKIE_HTTPONLY"]  = True   # JS não acessa o cookie
app.config["SESSION_COOKIE_SECURE"]   = True    # cookie só em HTTPS
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # proteção contra CSRF básica

ADMIN_USER   = os.getenv("ADMIN_USER",   "admin")
ADMIN_PASS   = os.getenv("ADMIN_PASS",   "admin123")
IDLE_TIMEOUT = int(os.getenv("IDLE_TIMEOUT", "10"))
PINO_PIR     = int(os.getenv("PINO_PIR",  "17"))
PINO_LED     = int(os.getenv("PINO_LED",  "22"))
DB_PATH      = os.getenv("DB_PATH", "totem.db")

# ── Estado global do sensor ───────────────────────────────────────────────────
estado = {"presente": False, "sessao_ativa": False, "ultima_presenca": None}
estado_lock = threading.Lock()

# ── Logging ───────────────────────────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("logs/totem.log"), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# ══════════════════════════════════════════════════════════════════════════════
#  RATE LIMITER  (Entregável 4 — proteção contra abuso)
# ══════════════════════════════════════════════════════════════════════════════
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[],          # sem limite global — aplicamos por rota
    storage_uri="memory://",
)

# ══════════════════════════════════════════════════════════════════════════════
#  BANCO DE DADOS SQLite  (Entregável 4 — consultas parametrizadas)
# ══════════════════════════════════════════════════════════════════════════════

def get_db():
    """Retorna conexão com o banco; cria se não existir."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    """Cria as tabelas se ainda não existirem."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS eventos (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                momento   TEXT    NOT NULL,
                nivel     TEXT    NOT NULL,
                evento    TEXT    NOT NULL,
                ip        TEXT,
                detalhes  TEXT
            );

            CREATE TABLE IF NOT EXISTS usuarios_admin (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT NOT NULL UNIQUE,
                senha TEXT NOT NULL
            );
        """)
        # Insere usuário padrão se tabela vazia
        cur = conn.execute("SELECT COUNT(*) FROM usuarios_admin")
        if cur.fetchone()[0] == 0:
            conn.execute(
                # ── consulta PARAMETRIZADA (previne SQL Injection) ──────────
                "INSERT INTO usuarios_admin (login, senha) VALUES (?, ?)",
                (os.getenv("ADMIN_USER", "admin"), os.getenv("ADMIN_PASS", "admin123"))
            )
        conn.commit()

def db_registrar_evento(nivel, evento, ip=None, detalhes=None):
    """Salva evento no banco usando consulta parametrizada."""
    try:
        db = get_db()
        db.execute(
            # ── consulta PARAMETRIZADA — valores nunca concatenados na string ─
            "INSERT INTO eventos (momento, nivel, evento, ip, detalhes) VALUES (?, ?, ?, ?, ?)",
            (datetime.utcnow().isoformat(), nivel, evento, ip, detalhes)
        )
        db.commit()
    except Exception as e:
        logger.error("Erro ao salvar evento no banco: %s", e)

def db_buscar_usuario(login):
    """
    Busca usuário por login com consulta parametrizada.
    NUNCA concatenar: f"SELECT * FROM usuarios WHERE login = '{login}'"
    Isso evita SQL Injection como: login = ' OR '1'='1
    """
    db = get_db()
    return db.execute(
        # ── consulta PARAMETRIZADA ────────────────────────────────────────────
        "SELECT * FROM usuarios_admin WHERE login = ?",
        (login,)
    ).fetchone()

def db_listar_eventos(limite=50):
    """Lista os últimos N eventos do banco."""
    db = get_db()
    return db.execute(
        "SELECT * FROM eventos ORDER BY id DESC LIMIT ?",
        (limite,)
    ).fetchall()

# ══════════════════════════════════════════════════════════════════════════════
#  CABEÇALHOS DE SEGURANÇA  (Hardening #2)
# ══════════════════════════════════════════════════════════════════════════════

@app.after_request
def aplicar_cabecalhos_seguranca(response):
    """
    Adiciona cabeçalhos HTTP de segurança em todas as respostas.
    Esses cabeçalhos protegem contra clickjacking, MIME sniffing,
    XSS e exposição de informações do servidor.
    """
    # Impede que a página seja carregada em iframe (anti-clickjacking)
    response.headers["X-Frame-Options"] = "DENY"

    # Impede que o browser "adivinhe" o tipo de conteúdo
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Habilita filtro XSS do browser (legado, mas ainda útil)
    response.headers["X-XSS-Protection"] = "1; mode=block"

    # Política de conteúdo — bloqueia recursos externos não autorizados
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'"
    )

    # Remove header que expõe que é Flask/Werkzeug (Hardening #3)
    response.headers.pop("Server", None)
    response.headers["Server"] = "Totem/1.0"

    # Força HTTPS em conexões futuras (só funciona com HTTPS ativo)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response

# ══════════════════════════════════════════════════════════════════════════════
#  GPIO
# ══════════════════════════════════════════════════════════════════════════════

def gpio_setup():
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(PINO_PIR, GPIO.IN)
    GPIO.setup(PINO_LED, GPIO.OUT)
    GPIO.output(PINO_LED, GPIO.LOW)
    logger.info("GPIO configurado  PIR=GPIO%d  LED=GPIO%d", PINO_PIR, PINO_LED)

def pir_loop():
    while True:
        leitura = bool(GPIO.input(PINO_PIR)) if RASPBERRY else False
        with estado_lock:
            agora = datetime.utcnow()
            if leitura:
                estado["presente"] = True
                estado["ultima_presenca"] = agora
                if not estado["sessao_ativa"]:
                    estado["sessao_ativa"] = True
                    logger.info("SESSÃO INICIADA  sensor=PIR GPIO%d", PINO_PIR)
            else:
                estado["presente"] = False
                if estado["sessao_ativa"] and estado["ultima_presenca"]:
                    ausente = (agora - estado["ultima_presenca"]).total_seconds()
                    if ausente >= IDLE_TIMEOUT:
                        estado["sessao_ativa"] = False
                        estado["ultima_presenca"] = None
                        logger.info("SESSÃO ENCERRADA  motivo=ausencia  tempo=%.0fs", ausente)
        time.sleep(0.3)

def piscar_led(duracao=2):
    def _run():
        if RASPBERRY:
            GPIO.output(PINO_LED, GPIO.HIGH)
            time.sleep(duracao)
            GPIO.output(PINO_LED, GPIO.LOW)
        else:
            logger.info("LED simulado  duracao=%ds", duracao)
    threading.Thread(target=_run, daemon=True).start()

# ══════════════════════════════════════════════════════════════════════════════
#  DECORADOR
# ══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            ip = request.remote_addr
            logger.warning("ACESSO NEGADO  rota=%-20s ip=%s", request.path, ip)
            db_registrar_evento("WARNING", "ACESSO NEGADO", ip, request.path)
            flash("Faça login para acessar esta área.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ══════════════════════════════════════════════════════════════════════════════
#  ROTAS PÚBLICAS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/")
def totem():
    return render_template("totem.html", idle_timeout=IDLE_TIMEOUT)

@app.route("/api/estado")
def api_estado():
    with estado_lock:
        presente     = estado["presente"]
        sessao_ativa = estado["sessao_ativa"]
        ultima       = estado["ultima_presenca"]
    segundos_restantes = IDLE_TIMEOUT
    if sessao_ativa and ultima:
        decorrido = (datetime.utcnow() - ultima).total_seconds()
        segundos_restantes = max(0, IDLE_TIMEOUT - int(decorrido))
    return jsonify({
        "presente": presente,
        "sessao_ativa": sessao_ativa,
        "segundos_restantes": segundos_restantes,
        "idle_timeout": IDLE_TIMEOUT,
    })

@app.route("/api/presenca", methods=["POST"])
def presenca():
    data      = request.get_json(silent=True) or {}
    detectado = bool(data.get("presente", False))
    with estado_lock:
        estado["presente"] = detectado
        if detectado:
            estado["ultima_presenca"] = datetime.utcnow()
            if not estado["sessao_ativa"]:
                estado["sessao_ativa"] = True
                logger.info("SESSÃO INICIADA  sensor=simulado ip=%s", request.remote_addr)
        else:
            estado["sessao_ativa"]    = False
            estado["ultima_presenca"] = None
            logger.info("SESSÃO ENCERRADA  sensor=simulado ip=%s", request.remote_addr)
    return jsonify({"status": "ok", "sessao_ativa": estado["sessao_ativa"]})

# ══════════════════════════════════════════════════════════════════════════════
#  AUTENTICAÇÃO  (com rate limit — Entregável 4)
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")   # ← Rate limit: máx 5 tentativas/min por IP
def login():
    if request.method == "POST":
        usuario = request.form.get("usuario", "").strip()
        senha   = request.form.get("senha",   "").strip()
        ip      = request.remote_addr

        # ── Validação de entradas ─────────────────────────────────────────────
        erros = []
        if not usuario:         erros.append("Campo usuário obrigatório.")
        if not senha:           erros.append("Campo senha obrigatório.")
        if len(usuario) > 80:  erros.append("Usuário inválido.")
        if len(senha)   > 128: erros.append("Senha inválida.")

        if erros:
            for e in erros: flash(e, "error")
            logger.warning("TENTATIVA LOGIN  resultado=entrada_invalida  ip=%s", ip)
            db_registrar_evento("WARNING", "LOGIN ENTRADA INVALIDA", ip)
            return render_template("login.html")

        # ── Verificação via banco com consulta parametrizada ──────────────────
        usuario_db = db_buscar_usuario(usuario)

        if usuario_db and usuario_db["senha"] == senha:
            session["admin_logged_in"] = True
            session["admin_user"]      = usuario
            session.permanent          = True
            logger.info("LOGIN OK  usuario=%s  ip=%s", usuario, ip)
            db_registrar_evento("INFO", "LOGIN OK", ip, usuario)
            return redirect(url_for("admin"))
        else:
            logger.warning("LOGIN FALHOU  usuario=%s  ip=%s", usuario, ip)
            db_registrar_evento("WARNING", "LOGIN FALHOU", ip, usuario)
            flash("Usuário ou senha incorretos.", "error")
            return render_template("login.html")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    usuario = session.get("admin_user", "admin")
    logger.info("LOGOUT  usuario=%s  ip=%s", usuario, request.remote_addr)
    db_registrar_evento("INFO", "LOGOUT", request.remote_addr, usuario)
    session.clear()
    return redirect(url_for("totem"))

# Handler para quando o rate limit é atingido
@app.errorhandler(429)
def rate_limit_excedido(e):
    ip = request.remote_addr
    logger.warning("RATE LIMIT ATINGIDO  rota=%s  ip=%s", request.path, ip)
    db_registrar_evento("WARNING", "RATE LIMIT ATINGIDO", ip, request.path)
    flash("Muitas tentativas. Aguarde 1 minuto antes de tentar novamente.", "error")
    return render_template("login.html"), 429

# ══════════════════════════════════════════════════════════════════════════════
#  ÁREA ADMINISTRATIVA
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/admin")
@login_required
def admin():
    return render_template("admin.html", raspberry=RASPBERRY, pino_pir=PINO_PIR, pino_led=PINO_LED)

@app.route("/admin/led", methods=["POST"])
@login_required
def acionar_led():
    cor = request.form.get("cor", "led").strip()[:20]
    piscar_led(duracao=2)
    usuario = session.get("admin_user", "admin")
    logger.info("LED ACIONADO  cor=%s  pino=GPIO%d  usuario=%s  ip=%s",
                cor, PINO_LED, usuario, request.remote_addr)
    db_registrar_evento("INFO", "LED ACIONADO", request.remote_addr,
                        f"cor={cor} pino=GPIO{PINO_LED}")
    flash(f"✅ LED {cor} acionado! (GPIO {PINO_LED} por 2s)", "success")
    return redirect(url_for("admin"))

@app.route("/admin/logs")
@login_required
def ver_logs():
    db_registrar_evento("INFO", "LOGS ACESSADOS", request.remote_addr)
    # Logs do arquivo
    try:
        with open("logs/totem.log", "r") as f:
            linhas_arquivo = f.readlines()[-30:]
    except FileNotFoundError:
        linhas_arquivo = []
    # Logs do banco (mais recentes)
    eventos_db = db_listar_eventos(50)
    return render_template("logs.html", linhas=linhas_arquivo, eventos=eventos_db)

# ══════════════════════════════════════════════════════════════════════════════
#  INICIALIZAÇÃO
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()
    logger.info("Banco de dados inicializado: %s", DB_PATH)

    if RASPBERRY:
        gpio_setup()
        threading.Thread(target=pir_loop, daemon=True).start()
        logger.info("Thread PIR iniciada  GPIO%d", PINO_PIR)
    else:
        logger.info("Modo simulado — use os botões na tela do totem")

    # ── HTTPS com certificado auto-assinado (Entregável 4) ───────────────────
    cert_path = os.getenv("SSL_CERT", "certs/cert.pem")
    key_path  = os.getenv("SSL_KEY",  "certs/key.pem")

    if os.path.exists(cert_path) and os.path.exists(key_path):
        ssl_context = (cert_path, key_path)
        logger.info("HTTPS ativo — certificado: %s", cert_path)
    else:
        ssl_context = "adhoc"   # gera certificado temporário automático
        logger.info("HTTPS ativo — certificado adhoc (temporário)")

    try:
        app.run(host="0.0.0.0", port=5000, debug=False, ssl_context=ssl_context)
    finally:
        if RASPBERRY:
            GPIO.cleanup()
            logger.info("GPIO liberado")
