"""BankStack - simple online banking app (Flask + SQLite)."""
import os, sys, secrets, sqlite3, threading, webbrowser
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)
from jinja2 import DictLoader
from werkzeug.security import check_password_hash, generate_password_hash

# The database file lives next to bank.py locally. On Render, set DB_PATH to a
# mounted persistent-disk path so account data survives deploys.
BASE = os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "bankstack.db"))

MAX_FAILS = 3                 # wrong PINs before a customer is locked
DAILY_LIMIT = 100000          # $1,000.00 per day, stored in cents
IDLE_SECONDS = 90             # auto sign-out after inactivity

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
app.permanent_session_lifetime = timedelta(seconds=IDLE_SECONDS)


# ---------------------------------------------------------------- database
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL,
            pin_hash TEXT NOT NULL, balance INTEGER NOT NULL DEFAULT 0,
            fails INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0,
            must_change INTEGER NOT NULL DEFAULT 1, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL,
            type TEXT NOT NULL, amount INTEGER NOT NULL,
            balance_after INTEGER NOT NULL, ref TEXT NOT NULL, ts TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,
            user_id TEXT, event TEXT NOT NULL, detail TEXT);
    """)
    if not conn.execute("SELECT 1 FROM users WHERE id='admin'").fetchone():
        conn.execute("INSERT INTO users VALUES (?,?,?,?,0,0,0,0,?)",
                     ("admin", "Administrator", "admin", generate_password_hash("2468"), now()))
    conn.commit()
    conn.close()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log(user_id, event, detail=""):
    db().execute("INSERT INTO logs (ts,user_id,event,detail) VALUES (?,?,?,?)",
                 (now(), user_id, event, detail))


# ----------------------------------------------------------------- helpers
def parse_amount(text):
    """Return cents. Positive, at most two decimal places."""
    try:
        amount = Decimal(text.strip())
    except (InvalidOperation, AttributeError):
        raise ValueError("Enter a valid number.")
    if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
        raise ValueError("Enter a positive amount with at most two decimal places.")
    return int(amount * 100)


def check_new_pin(pin):
    if not (pin.isdigit() and len(pin) == 4):
        return "PIN must be exactly 4 digits."
    if len(set(pin)) == 1 or pin in ("1234", "4321", "0123"):
        return "That PIN is too easy to guess."
    return ""


def verify_pin(user, pin):
    """Check a PIN, count failures, and lock customers after too many."""
    conn = db()
    if check_password_hash(user["pin_hash"], pin):
        conn.execute("UPDATE users SET fails=0 WHERE id=?", (user["id"],))
        return True
    fails = user["fails"] + 1
    lock = 1 if (fails >= MAX_FAILS and user["role"] != "admin") else 0
    conn.execute("UPDATE users SET fails=?, locked=? WHERE id=?",
                 (0 if user["role"] == "admin" and fails >= MAX_FAILS else fails, lock, user["id"]))
    log(user["id"], "BAD_PIN", "Incorrect PIN entered")
    if lock:
        log(user["id"], "LOCKED", "Too many wrong PIN attempts")
    return False


def current_user():
    uid = session.get("uid")
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None


def login_required(role=None):
    def wrap(fn):
        @wraps(fn)
        def inner(*a, **kw):
            user = current_user()
            if not user:
                flash("Please sign in (your session may have timed out).", "err")
                return redirect(url_for("login"))
            if user["must_change"] and request.endpoint != "change_pin":
                return redirect(url_for("change_pin"))
            if role and user["role"] != role:
                return redirect(url_for("home"))
            return fn(user, *a, **kw)
        return inner
    return wrap


@app.context_processor
def inject_user():
    return {"user": current_user()}


app.jinja_env.filters["money"] = lambda c: f"${c / 100:,.2f}"


# ------------------------------------------------------------------ routes
@app.route("/")
def home():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return redirect(url_for("admin" if user["role"] == "admin" else "dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        uid = request.form.get("id", "").strip()
        pin = request.form.get("pin", "")
        user = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not user:
            flash("Invalid account number or PIN.", "err")
        elif user["locked"]:
            flash("This account is locked. Please contact an administrator.", "err")
        elif verify_pin(user, pin):
            session.clear()
            session.permanent = True
            session["uid"] = user["id"]
            log(user["id"], "LOGIN", "Signed in")
            db().commit()
            return redirect(url_for("home"))
        else:
            db().commit()
            left = MAX_FAILS - (user["fails"] + 1)
            flash("Invalid account number or PIN." + (f" {left} attempt(s) left." if left > 0 and user["role"] != "admin" else ""), "err")
        db().commit()
    return render_template("login.html")


@app.route("/logout")
def logout():
    if session.get("uid"):
        log(session["uid"], "LOGOUT", "Signed out")
        db().commit()
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-pin", methods=["GET", "POST"])
@login_required()
def change_pin(user):
    if request.method == "POST":
        old, new, confirm = (request.form.get(k, "") for k in ("old", "new", "confirm"))
        error = check_new_pin(new) or ("New PINs do not match." if new != confirm else "") \
            or ("New PIN must be different from the current PIN." if new == old else "")
        if error:
            flash(error, "err")
        elif not verify_pin(user, old):
            db().commit()
            flash("Current PIN is incorrect.", "err")
            if db().execute("SELECT locked FROM users WHERE id=?", (user["id"],)).fetchone()[0]:
                return redirect(url_for("logout"))
        else:
            db().execute("UPDATE users SET pin_hash=?, must_change=0 WHERE id=?",
                         (generate_password_hash(new), user["id"]))
            log(user["id"], "PIN_CHANGE", "PIN updated")
            db().commit()
            flash("PIN changed successfully.", "ok")
            return redirect(url_for("home"))
    return render_template("pin.html", forced=user["must_change"])


@app.route("/dashboard")
@login_required("customer")
def dashboard(user):
    rows = db().execute("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    return render_template("customer.html", rows=rows)


@app.route("/transact", methods=["POST"])
@login_required("customer")
def transact(user):
    kind = "DEPOSIT" if request.form.get("type") == "DEPOSIT" else "WITHDRAW"
    try:
        amount = parse_amount(request.form.get("amount", ""))
        if not verify_pin(user, request.form.get("pin", "")):   # PIN needed for every transaction
            db().commit()
            if db().execute("SELECT locked FROM users WHERE id=?", (user["id"],)).fetchone()[0]:
                flash("Account locked after too many wrong PINs.", "err")
                return redirect(url_for("logout"))
            raise ValueError("Incorrect PIN.")
        if kind == "WITHDRAW":
            if amount > user["balance"]:
                raise ValueError("Insufficient funds.")
            used = db().execute("SELECT COALESCE(SUM(amount),0) FROM transactions WHERE user_id=? "
                                "AND type='WITHDRAW' AND ts LIKE ?",
                                (user["id"], datetime.now().strftime("%Y-%m-%d") + "%")).fetchone()[0]
            if used + amount > DAILY_LIMIT:
                raise ValueError(f"Daily withdrawal limit of ${DAILY_LIMIT/100:,.2f} exceeded.")
        balance = user["balance"] + (amount if kind == "DEPOSIT" else -amount)
        ref = "BS-" + datetime.now().strftime("%y%m%d%H%M%S") + str(secrets.randbelow(90) + 10)
        db().execute("UPDATE users SET balance=? WHERE id=?", (balance, user["id"]))
        db().execute("INSERT INTO transactions (user_id,type,amount,balance_after,ref,ts) VALUES (?,?,?,?,?,?)",
                     (user["id"], kind, amount, balance, ref, now()))
        log(user["id"], kind, f"${amount/100:,.2f} ref {ref}")
        db().commit()
        flash(f"Receipt {ref}: {'Deposited' if kind == 'DEPOSIT' else 'Withdrew'} "
              f"${amount/100:,.2f}. New balance ${balance/100:,.2f}. PIN verified.", "ok")
    except ValueError as error:
        db().commit()
        flash(str(error), "err")
    return redirect(url_for("dashboard"))


@app.route("/admin")
@login_required("admin")
def admin(user):
    customers = db().execute("SELECT * FROM users WHERE role='customer' ORDER BY created DESC").fetchall()
    logs = db().execute("SELECT * FROM logs ORDER BY id DESC LIMIT 25").fetchall()
    return render_template("admin.html", customers=customers, logs=logs)


@app.route("/admin/create", methods=["POST"])
@login_required("admin")
def create_customer(user):
    name = request.form.get("name", "").strip()
    try:
        if not name:
            raise ValueError("Customer name cannot be empty.")
        opening = parse_amount(request.form["opening"]) if request.form.get("opening", "").strip() else 0
    except ValueError as error:
        flash(str(error), "err")
        return redirect(url_for("admin"))
    while True:
        uid = "".join(str(secrets.randbelow(10)) for _ in range(8))
        if not db().execute("SELECT 1 FROM users WHERE id=?", (uid,)).fetchone():
            break
    pin = "".join(str(secrets.randbelow(10)) for _ in range(4))   # default PIN
    db().execute("INSERT INTO users VALUES (?,?,?,?,?,0,0,1,?)",
                 (uid, name, "customer", generate_password_hash(pin), opening, now()))
    if opening:
        db().execute("INSERT INTO transactions (user_id,type,amount,balance_after,ref,ts) VALUES (?,?,?,?,?,?)",
                     (uid, "DEPOSIT", opening, opening, "BS-OPENING", now()))
    log("admin", "CREATE_CUSTOMER", f"{name} ({uid})")
    db().commit()
    flash(f"Created {name}. Account number: {uid}  |  Default PIN: {pin} (shown once; customer must change it).", "ok")
    return redirect(url_for("admin"))


@app.route("/admin/<uid>/<action>", methods=["POST"])
@login_required("admin")
def admin_action(user, uid, action):
    if action == "reset":
        pin = "".join(str(secrets.randbelow(10)) for _ in range(4))
        db().execute("UPDATE users SET pin_hash=?, must_change=1, locked=0, fails=0 WHERE id=? AND role='customer'",
                     (generate_password_hash(pin), uid))
        flash(f"New default PIN for {uid}: {pin}", "ok")
    elif action in ("lock", "unlock"):
        db().execute("UPDATE users SET locked=?, fails=0 WHERE id=? AND role='customer'",
                     (1 if action == "lock" else 0, uid))
    log("admin", action.upper(), uid)
    db().commit()
    return redirect(url_for("admin"))


# --------------------------------------------------------------- templates
app.jinja_loader = DictLoader({
"base.html": """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BankStack – Banking, Stacked</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🏦</text></svg>">
<style>
body{margin:0;font-family:system-ui,sans-serif;background:#f3f6f5;color:#14231f}
header{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;padding:14px 20px;background:#115e59;color:#fff}
header h1{margin:0;font-size:1.3rem} header a{color:#fff;margin-left:10px}
main{max-width:960px;margin:0 auto;padding:16px}
.card{background:#fff;border:1px solid #dbe5e2;border-radius:12px;padding:16px;margin-bottom:16px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
label{display:block;font-size:.85rem;color:#5d6f69;margin:10px 0 4px}
input{width:100%;box-sizing:border-box;padding:10px;border:1px solid #cdd9d6;border-radius:8px;font-size:1rem}
button{background:#0f766e;color:#fff;border:0;border-radius:8px;padding:10px 16px;font-weight:600;cursor:pointer;margin-top:12px}
button.sm{padding:4px 10px;margin:0;font-size:.8rem}
.msg{padding:10px 12px;border-radius:8px;margin-bottom:12px;border:1px solid}
.err{color:#b42318;border-color:#b42318;background:#fff}.ok{color:#067647;border-color:#067647;background:#fff}
.bal{font-size:2.1rem;font-weight:700}.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.9rem}th,td{text-align:left;padding:7px 6px;border-bottom:1px solid #e3ebe9;white-space:nowrap}
.login{max-width:380px;margin:40px auto}
</style></head><body>
<header><h1>🏦 BankStack</h1>
{% if user %}<span>{{ user['name'] }} ({{ user['role'] }}) <a href="{{ url_for('logout') }}">Sign out</a></span>{% endif %}</header>
<main>{% for cat, m in get_flashed_messages(with_categories=true) %}<div class="msg {{ cat }}">{{ m }}</div>{% endfor %}
{% block body %}{% endblock %}</main></body></html>""",

"login.html": """{% extends 'base.html' %}{% block body %}
<form class="card login" method="post"><h2>Sign in</h2>
<label>Account number or username</label><input name="id" required autofocus>
<label>PIN</label><input name="pin" type="password" maxlength="4" inputmode="numeric" required>
<button>Sign in</button>
<p style="font-size:.85rem;color:#5d6f69">Demo admin: <b>admin</b> / PIN <b>2468</b></p></form>{% endblock %}""",

"pin.html": """{% extends 'base.html' %}{% block body %}
<form class="card login" method="post"><h2>{{ 'Set your own PIN' if forced else 'Change PIN' }}</h2>
{% if forced %}<p>You signed in with a default PIN. Please choose a new one.</p>{% endif %}
<label>Current PIN</label><input name="old" type="password" maxlength="4" inputmode="numeric" required>
<label>New PIN (4 digits)</label><input name="new" type="password" maxlength="4" inputmode="numeric" required>
<label>Confirm new PIN</label><input name="confirm" type="password" maxlength="4" inputmode="numeric" required>
<button>Save PIN</button></form>{% endblock %}""",

"customer.html": """{% extends 'base.html' %}{% block body %}
<div class="card"><div>Account {{ user['id'] }}</div><div class="bal">{{ user['balance']|money }}</div>
<a href="{{ url_for('change_pin') }}">Change PIN</a></div>
<div class="grid">
{% for t, title in [('DEPOSIT','Deposit'),('WITHDRAW','Withdraw')] %}
<form class="card" method="post" action="{{ url_for('transact') }}"><h2>{{ title }}</h2>
<input type="hidden" name="type" value="{{ t }}">
<label>Amount (USD)</label><input name="amount" inputmode="decimal" placeholder="0.00" required>
<label>Confirm with your PIN</label><input name="pin" type="password" maxlength="4" inputmode="numeric" required>
<button>{{ title }}</button></form>{% endfor %}</div>
<div class="card"><h2>Transaction history</h2><div class="wrap"><table>
<tr><th>Date</th><th>Type</th><th>Amount</th><th>Balance</th><th>Ref</th></tr>
{% for r in rows %}<tr><td>{{ r['ts'] }}</td><td>{{ r['type'] }}</td><td>{{ r['amount']|money }}</td><td>{{ r['balance_after']|money }}</td><td>{{ r['ref'] }}</td></tr>
{% else %}<tr><td colspan="5">No transactions yet.</td></tr>{% endfor %}</table></div></div>{% endblock %}""",

"admin.html": """{% extends 'base.html' %}{% block body %}
<form class="card" method="post" action="{{ url_for('create_customer') }}"><h2>Create customer</h2>
<label>Full name</label><input name="name" required>
<label>Opening deposit (optional)</label><input name="opening" inputmode="decimal" placeholder="0.00">
<button>Create account</button></form>
<div class="card"><h2>Customers</h2><div class="wrap"><table>
<tr><th>Account</th><th>Name</th><th>Balance</th><th>Status</th><th>Actions</th></tr>
{% for c in customers %}<tr><td>{{ c['id'] }}</td><td>{{ c['name'] }}</td><td>{{ c['balance']|money }}</td>
<td>{{ 'Locked' if c['locked'] else ('Default PIN' if c['must_change'] else 'Active') }}</td>
<td><form method="post" action="{{ url_for('admin_action', uid=c['id'], action='reset') }}" style="display:inline"><button class="sm">Reset PIN</button></form>
<form method="post" action="{{ url_for('admin_action', uid=c['id'], action='unlock' if c['locked'] else 'lock') }}" style="display:inline"><button class="sm">{{ 'Unlock' if c['locked'] else 'Lock' }}</button></form></td></tr>
{% else %}<tr><td colspan="5">No customers yet.</td></tr>{% endfor %}</table></div></div>
<div class="card"><h2>Security &amp; activity log</h2><div class="wrap"><table>
<tr><th>Time</th><th>User</th><th>Event</th><th>Details</th></tr>
{% for l in logs %}<tr><td>{{ l['ts'] }}</td><td>{{ l['user_id'] }}</td><td>{{ l['event'] }}</td><td>{{ l['detail'] }}</td></tr>{% endfor %}
</table></div></div>{% endblock %}""",
})

init_db()

if __name__ == "__main__":
    if getattr(sys, "frozen", False):          # running as .exe: open the browser automatically
        threading.Timer(1.0, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
    app.run(host=os.environ.get("HOST", "127.0.0.1"),
            port=int(os.environ.get("PORT", "5000")))