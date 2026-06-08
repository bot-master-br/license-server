"""
server.py — Servidor de Licenças do Bot_Master
================================================
Backend Flask para validação de licenças com:
  - Validação de chave + binding de máquina
  - Banco SQLite local (sem dependências externas)
  - Painel admin simples via terminal (manage.py)
  - Proteção contra uso simultâneo em múltiplas máquinas

Como rodar localmente para testar:
    pip install flask
    python server.py

Como rodar em produção (Railway/Render):
    Variável de ambiente: ADMIN_SECRET=sua_senha_aqui
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, jsonify, request, abort

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Senha do painel admin — mude via variável de ambiente ADMIN_SECRET
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "troque_esta_senha_admin_123")

# Caminho do banco de dados SQLite
DB_PATH = Path(__file__).parent / "licenses.db"

# Versão mínima do bot aceita (opcional — para forçar update)
MIN_BOT_VERSION = "1.0.0"


# ---------------------------------------------------------------------------
# Banco de dados
# ---------------------------------------------------------------------------

def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Cria as tabelas se não existirem."""
    with get_db() as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS licenses (
                key         TEXT PRIMARY KEY,
                player_name TEXT NOT NULL,
                machine_id  TEXT DEFAULT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                active      INTEGER NOT NULL DEFAULT 1,
                notes       TEXT DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS validations (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key         TEXT NOT NULL,
                machine_id  TEXT,
                ip          TEXT,
                result      TEXT,
                reason      TEXT,
                validated_at TEXT NOT NULL
            );
        """)
    print(f"[DB] Banco iniciado em: {DB_PATH}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _log_validation(key: str, machine_id: str, ip: str, result: str, reason: str):
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO validations (key, machine_id, ip, result, reason, validated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, machine_id, ip, result, reason, _now_iso())
            )
    except Exception as e:
        print(f"[LOG] Erro ao registrar validação: {e}")


def _require_admin(f):
    """Decorator que exige o header X-Admin-Secret."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("X-Admin-Secret", "")
        if not hmac.compare_digest(token, ADMIN_SECRET):
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Rota principal — validação de licença (chamada pelo bot)
# ---------------------------------------------------------------------------

@app.route("/api/license/validate", methods=["POST"])
def validate():
    """
    Corpo esperado (JSON):
        { "key": "BM-XXXXXXXX", "machine_id": "abc123..." }

    Retorno:
        { "valid": true/false, "reason": "...", "expires_at": "...", "player": "..." }
    """
    data = request.get_json(silent=True) or {}
    key        = str(data.get("key", "")).strip()
    machine_id = str(data.get("machine_id", "")).strip()
    ip         = request.remote_addr or "unknown"

    if not key or not machine_id:
        _log_validation(key, machine_id, ip, "INVALID", "Dados incompletos")
        return jsonify({"valid": False, "reason": "Dados incompletos na requisição."})

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM licenses WHERE key = ?", (key,)
        ).fetchone()

    # ── Chave não existe ───────────────────────────────────────────────────
    if not row:
        _log_validation(key, machine_id, ip, "NOT_FOUND", "Chave não encontrada")
        return jsonify({"valid": False, "reason": "Chave de licença não encontrada."})

    # ── Licença desativada manualmente ────────────────────────────────────
    if not row["active"]:
        _log_validation(key, machine_id, ip, "DISABLED", "Licença desativada")
        return jsonify({"valid": False, "reason": "Esta licença foi desativada."})

    # ── Verificação de expiração ───────────────────────────────────────────
    try:
        expires_at = datetime.fromisoformat(row["expires_at"])
        if datetime.now() > expires_at:
            _log_validation(key, machine_id, ip, "EXPIRED", "Licença expirada")
            expired_on = expires_at.strftime("%d/%m/%Y")
            return jsonify({
                "valid": False,
                "reason": f"Licença expirada em {expired_on}. Renove com o desenvolvedor."
            })
    except Exception:
        _log_validation(key, machine_id, ip, "ERROR", "Data de expiração inválida")
        return jsonify({"valid": False, "reason": "Erro interno na licença."})

    # ── Binding de máquina ────────────────────────────────────────────────
    registered_machine = row["machine_id"]

    if registered_machine and registered_machine != machine_id:
        # Máquina diferente da registrada
        _log_validation(key, machine_id, ip, "WRONG_MACHINE",
                        f"Esperado: {registered_machine[:8]}... | Recebido: {machine_id[:8]}...")
        return jsonify({
            "valid": False,
            "reason": (
                "Esta licença já está vinculada a outro computador. "
                "Contate o desenvolvedor para transferir."
            )
        })

    # ── Primeiro uso — vincula a máquina ──────────────────────────────────
    if not registered_machine:
        with get_db() as db:
            db.execute(
                "UPDATE licenses SET machine_id = ? WHERE key = ?",
                (machine_id, key)
            )
        print(f"[BIND] Chave {key} vinculada à máquina {machine_id[:12]}...")

    # ── Sucesso ────────────────────────────────────────────────────────────
    _log_validation(key, machine_id, ip, "OK", "Válida")
    return jsonify({
        "valid":      True,
        "reason":     "Licença válida.",
        "expires_at": row["expires_at"],
        "player":     row["player_name"],
    })


# ---------------------------------------------------------------------------
# Rotas de Admin — protegidas por X-Admin-Secret
# ---------------------------------------------------------------------------

@app.route("/manage/licenses", methods=["GET"])
@_require_admin
def list_licenses():
    """Lista todas as licenças."""
    with get_db() as db:
        rows = db.execute(
            "SELECT key, player_name, machine_id, created_at, expires_at, active, notes "
            "FROM licenses ORDER BY created_at DESC"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/manage/licenses", methods=["POST"])
@_require_admin
def create_license():
    """
    Cria uma nova licença.
    Body: { "player_name": "Fulano", "months": 1, "notes": "..." }
    """
    data = request.get_json(silent=True) or {}
    player_name = str(data.get("player_name", "")).strip()
    months      = float(data.get("months", 1))
    days        = int(data.get("days", 0))
    notes       = str(data.get("notes", "")).strip()

    if not player_name:
        return jsonify({"error": "player_name é obrigatório"}), 400

    # Calcula dias totais — aceita dias direto ou meses
    total_days = days if days > 0 else int(round(30 * months))
    if total_days < 1:
        return jsonify({"error": "período deve ser >= 1 dia"}), 400

    key        = f"BM-{secrets.token_hex(4).upper()}-{secrets.token_hex(4).upper()}"
    now        = datetime.now()
    expires_at = (now + timedelta(days=total_days)).isoformat(timespec="seconds")

    with get_db() as db:
        db.execute(
            "INSERT INTO licenses (key, player_name, created_at, expires_at, active, notes) "
            "VALUES (?, ?, ?, ?, 1, ?)",
            (key, player_name, now.isoformat(timespec="seconds"), expires_at, notes)
        )

    print(f"[CRIADA] {key} | {player_name} | {total_days}d | expira em {expires_at}")
    return jsonify({
        "key":        key,
        "player_name": player_name,
        "expires_at": expires_at,
        "days":       total_days,
    }), 201


@app.route("/manage/licenses/<key>/deactivate", methods=["POST"])
@_require_admin
def deactivate_license(key: str):
    """Desativa uma licença sem deletar."""
    with get_db() as db:
        db.execute("UPDATE licenses SET active = 0 WHERE key = ?", (key,))
    print(f"[DESATIVADA] {key}")
    return jsonify({"ok": True, "key": key})


@app.route("/manage/licenses/<key>/reactivate", methods=["POST"])
@_require_admin
def reactivate_license(key: str):
    """Reativa uma licença desativada."""
    with get_db() as db:
        db.execute("UPDATE licenses SET active = 1 WHERE key = ?", (key,))
    print(f"[REATIVADA] {key}")
    return jsonify({"ok": True, "key": key})


@app.route("/manage/licenses/<key>/reset-machine", methods=["POST"])
@_require_admin
def reset_machine(key: str):
    """Remove o binding de máquina (permite ativar em outra máquina)."""
    with get_db() as db:
        db.execute("UPDATE licenses SET machine_id = NULL WHERE key = ?", (key,))
    print(f"[RESET MACHINE] {key}")
    return jsonify({"ok": True, "key": key})


@app.route("/manage/licenses/<key>/renew", methods=["POST"])
@_require_admin
def renew_license(key: str):
    """
    Renova uma licença adicionando meses a partir de hoje (ou da expiração atual, se no futuro).
    Body: { "months": 1 }
    """
    data   = request.get_json(silent=True) or {}
    months = int(data.get("months", 1))

    with get_db() as db:
        row = db.execute("SELECT expires_at FROM licenses WHERE key = ?", (key,)).fetchone()
        if not row:
            return jsonify({"error": "Chave não encontrada"}), 404

        try:
            current_expiry = datetime.fromisoformat(row["expires_at"])
            # Renova a partir da expiração atual se ainda no futuro, senão a partir de hoje
            base = max(current_expiry, datetime.now())
        except Exception:
            base = datetime.now()

        new_expiry = (base + timedelta(days=30 * months)).isoformat(timespec="seconds")
        db.execute("UPDATE licenses SET expires_at = ?, active = 1 WHERE key = ?", (new_expiry, key))

    print(f"[RENOVADA] {key} → {new_expiry}")
    return jsonify({"ok": True, "key": key, "new_expires_at": new_expiry})


@app.route("/manage/validations", methods=["GET"])
@_require_admin
def list_validations():
    """Retorna as últimas 200 validações (log de acesso)."""
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM validations ORDER BY validated_at DESC LIMIT 200"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/manage/stats", methods=["GET"])
@_require_admin
def stats():
    """Resumo rápido do servidor."""
    with get_db() as db:
        total   = db.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
        active  = db.execute("SELECT COUNT(*) FROM licenses WHERE active=1").fetchone()[0]
        expired = db.execute(
            "SELECT COUNT(*) FROM licenses WHERE active=1 AND expires_at < ?",
            (_now_iso(),)
        ).fetchone()[0]
        today_ok = db.execute(
            "SELECT COUNT(*) FROM validations WHERE result='OK' AND validated_at >= ?",
            (datetime.now().strftime("%Y-%m-%d"),)
        ).fetchone()[0]

    return jsonify({
        "total_licenses":  total,
        "active_licenses": active,
        "expired_licenses": expired,
        "validations_today_ok": today_ok,
    })


# ---------------------------------------------------------------------------
# Health check (Railway/Render usam isso para saber se o app está no ar)
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ts": _now_iso()})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    print(f"[BotMaster License Server] Rodando na porta {port}")
    app.run(host="0.0.0.0", port=port, debug=debug)
