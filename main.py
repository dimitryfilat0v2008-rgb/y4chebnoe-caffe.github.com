# -*- coding: utf-8 -*-
import os
import sqlite3
import hashlib
import secrets
from datetime import datetime, date
from functools import wraps
from flask import Flask, render_template_string, request, redirect, url_for, flash, session

SITE_NAME = "Учебное кафе"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cafe.db")

app = Flask(__name__)
app.secret_key = "uchebnoe-cafe-secret-key-2026"


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "username TEXT NOT NULL UNIQUE,"
        "password_hash TEXT NOT NULL,"
        "salt TEXT NOT NULL,"
        "full_name TEXT NOT NULL,"
        "role TEXT NOT NULL DEFAULT 'user',"
        "created_at TEXT NOT NULL)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS menu_items ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "name TEXT NOT NULL,"
        "price REAL NOT NULL CHECK (price > 0))"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS orders ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "user_id INTEGER NOT NULL,"
        "created_at TEXT NOT NULL,"
        "status TEXT NOT NULL,"
        "total REAL NOT NULL DEFAULT 0,"
        "FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)"
    )
    cur.execute(
        "CREATE TABLE IF NOT EXISTS order_lines ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "order_id INTEGER NOT NULL,"
        "menu_item_id INTEGER NOT NULL,"
        "quantity INTEGER NOT NULL CHECK (quantity >= 1),"
        "FOREIGN KEY (order_id) REFERENCES orders(id) ON DELETE CASCADE,"
        "FOREIGN KEY (menu_item_id) REFERENCES menu_items(id))"
    )
    conn.commit()
    conn.close()


def seed_menu():
    conn = get_connection()
    count = conn.execute("SELECT COUNT(*) AS c FROM menu_items").fetchone()["c"]
    if count == 0:
        dishes = [
            ("Чай чёрный", 50),
            ("Чай зелёный", 50),
            ("Кофе американо", 120),
            ("Кофе капучино", 150),
            ("Кофе латте", 160),
            ("Какао", 130),
            ("Булочка с корицей", 80),
            ("Круассан", 100),
            ("Пирожное эклер", 120),
            ("Сэндвич с курицей", 180),
            ("Сэндвич с сыром", 160),
            ("Салат Цезарь", 220),
            ("Салат овощной", 150),
            ("Суп дня", 180),
            ("Борщ", 200),
            ("Пельмени", 250),
            ("Пицца Маргарита", 350),
            ("Пицца Пепперони", 400),
            ("Паста карбонара", 320),
            ("Картофель фри", 120),
        ]
        for name, price in dishes:
            conn.execute("INSERT INTO menu_items (name, price) VALUES (?, ?)", (name, price))
        conn.commit()
    conn.close()


init_db()
seed_menu()


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return h, salt


def check_password(password, salt, password_hash):
    h, _ = hash_password(password, salt)
    return h == password_hash


def get_user_by_username(username):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def create_user(username, password, full_name):
    pwd_hash, salt = hash_password(password)
    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        role = "admin" if count == 0 else "user"
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, role, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, full_name, role,
             datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "Пользователь с таким логином уже существует"
    finally:
        conn.close()


def validate_registration(username, password, password2, full_name):
    if not username or len(username.strip()) < 3:
        return False, "Логин должен содержать минимум 3 символа"
    if len(username.strip()) > 30:
        return False, "Логин слишком длинный (до 30 символов)"
    if not username.replace("_", "").replace("-", "").isalnum():
        return False, "Логин: только буквы, цифры, дефис, подчёркивание"
    if not full_name or not full_name.strip():
        return False, "Введите ваше имя"
    if len(password) < 6:
        return False, "Пароль должен содержать минимум 6 символов"
    if password != password2:
        return False, "Пароли не совпадают"
    return True, None


def validate_login(username, password):
    user = get_user_by_username(username)
    if not user:
        return None, "Неверный логин или пароль"
    if not check_password(password, user["salt"], user["password_hash"]):
        return None, "Неверный логин или пароль"
    return user, None


def current_user():
    if not session.get("user_id"):
        return None
    return get_user_by_id(session["user_id"])


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Войдите в систему, чтобы продолжить", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            flash("Войдите как администратор", "error")
            return redirect(url_for("login"))
        user = get_user_by_id(session["user_id"])
        if not user or user["role"] != "admin":
            flash("Доступ только для администратора", "error")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapper


def get_all_menu_items():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM menu_items ORDER BY name").fetchall()
    conn.close()
    return rows


def add_menu_item(name, price):
    conn = get_connection()
    conn.execute("INSERT INTO menu_items (name, price) VALUES (?, ?)", (name, price))
    conn.commit()
    conn.close()


def delete_menu_item(item_id):
    conn = get_connection()
    used = conn.execute(
        "SELECT COUNT(*) AS c FROM order_lines WHERE menu_item_id = ?", (item_id,)
    ).fetchone()["c"]
    if used > 0:
        conn.close()
        return False, "Позиция используется в заказах"
    conn.execute("DELETE FROM menu_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    return True, None


def validate_menu_item(name, price):
    if not name or not name.strip():
        return False, "Введите название позиции", None
    try:
        price_value = float(price)
    except (TypeError, ValueError):
        return False, "Цена должна быть числом", None
    if price_value <= 0:
        return False, "Цена должна быть положительной", None
    return True, None, {"name": name.strip(), "price": price_value}


def get_orders(user=None, search=None, status=None):
    conn = get_connection()
    query = "SELECT * FROM orders WHERE 1=1"
    params = []
    if user is not None:
        query += " AND user_id = ?"
        params.append(user["id"])
    if search:
        query += " AND (CAST(id AS TEXT) LIKE ? OR created_at LIKE ?)"
        params.extend(["%" + search + "%", "%" + search + "%"])
    if status and status != "все":
        query += " AND status = ?"
        params.append(status)
    query += " ORDER BY id DESC"
    rows = conn.execute(query, params).fetchall()
    conn.close()
    return rows


def get_order(order_id):
    conn = get_connection()
    order = conn.execute(
        "SELECT o.*, u.full_name AS user_name, u.username "
        "FROM orders o JOIN users u ON u.id = o.user_id "
        "WHERE o.id = ?", (order_id,)
    ).fetchone()
    if not order:
        conn.close()
        return None, []
    lines = conn.execute(
        "SELECT ol.id, ol.quantity, m.name, m.price, "
        "(m.price * ol.quantity) AS line_total "
        "FROM order_lines ol JOIN menu_items m ON m.id = ol.menu_item_id "
        "WHERE ol.order_id = ?", (order_id,)
    ).fetchall()
    conn.close()
    return order, lines


def create_order(user_id, created_at, status, lines):
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO orders (user_id, created_at, status, total) VALUES (?, ?, ?, 0)",
        (user_id, created_at, status),
    )
    order_id = cur.lastrowid
    total = 0.0
    for line in lines:
        item = cur.execute(
            "SELECT price FROM menu_items WHERE id = ?", (line["menu_item_id"],)
        ).fetchone()
        if item is None:
            conn.rollback()
            conn.close()
            return None, "Позиция не найдена"
        total += item["price"] * line["quantity"]
        cur.execute(
            "INSERT INTO order_lines (order_id, menu_item_id, quantity) VALUES (?, ?, ?)",
            (order_id, line["menu_item_id"], line["quantity"]),
        )
    cur.execute("UPDATE orders SET total = ? WHERE id = ?", (total, order_id))
    conn.commit()
    conn.close()
    return order_id, None


def update_order_status(order_id, status):
    conn = get_connection()
    conn.execute("UPDATE orders SET status = ? WHERE id = ?", (status, order_id))
    conn.commit()
    conn.close()


def delete_order(order_id):
    conn = get_connection()
    conn.execute("DELETE FROM orders WHERE id = ?", (order_id,))
    conn.commit()
    conn.close()


def validate_quantity(quantity):
    try:
        q = int(quantity)
    except (TypeError, ValueError):
        return False, "Количество должно быть целым числом", None
    if q < 1:
        return False, "Количество не меньше 1", None
    return True, None, q


def validate_status(status):
    if status not in ("новый", "выполнен", "отменён"):
        return False, "Недопустимый статус", None
    return True, None, status


def get_summary(date_str, user=None):
    conn = get_connection()
    query = ("SELECT status, COUNT(*) AS cnt, COALESCE(SUM(total), 0) AS amount "
             "FROM orders WHERE date(created_at) = date(?)")
    params = [date_str]
    if user is not None:
        query += " AND user_id = ?"
        params.append(user["id"])
    query += " GROUP BY status"
    rows = conn.execute(query, params).fetchall()
    result = {"новый": 0, "выполнен": 0, "отменён": 0, "выручка": 0.0, "всего": 0}
    for row in rows:
        result[row["status"]] = row["cnt"]
        result["всего"] += row["cnt"]
        if row["status"] == "выполнен":
            result["выручка"] = row["amount"]
    conn.close()
    return result


PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{{ title }}</title>
<style>
* { box-sizing: border-box; }
body { font-family: Arial, sans-serif; margin: 0; background: #f5f5f5; color: #222; }
header { background: #8B4513; color: #fff; padding: 15px 25px; }
header h1 { margin: 0 0 10px; font-size: 22px; }
nav { display: flex; flex-wrap: wrap; gap: 15px; align-items: center; }
nav a { color: #f5deb3; text-decoration: none; }
nav a:hover { text-decoration: underline; color: #fff; }
nav .right { margin-left: auto; }
main { padding: 20px 25px; max-width: 1000px; margin: 0 auto; }
table { border-collapse: collapse; width: 100%; background: #fff; margin-top: 15px; }
th, td { border: 1px solid #ddd; padding: 8px 10px; text-align: left; }
th { background: #f5deb3; }
.toolbar { display: flex; gap: 10px; flex-wrap: wrap; align-items: center; margin-top: 10px; }
input, select, button { padding: 6px 10px; font-size: 14px; }
button, .btn { background: #8B4513; color: #fff; border: none; cursor: pointer; border-radius: 4px; padding: 6px 12px; text-decoration: none; display: inline-block; }
button:hover, .btn:hover { background: #6b3410; }
.btn-green { background: #27ae60; }
.btn-green:hover { background: #1e8449; }
.link-danger { background: none; color: #c0392b; border: none; cursor: pointer; padding: 0; text-decoration: underline; }
.flash { padding: 10px; border-radius: 4px; margin-bottom: 15px; }
.flash.success { background: #d4efdf; color: #1e8449; }
.flash.error { background: #fadbd8; color: #922b21; }
.form-box { background: #fff; padding: 20px; border-radius: 6px; max-width: 400px; margin: 30px auto; }
.form-box label { display: block; margin-top: 10px; font-weight: bold; }
.form-box input { width: 100%; padding: 8px; margin-top: 5px; }
.form-box button { width: 100%; margin-top: 15px; padding: 10px; }
footer { text-align: center; padding: 15px; color: #777; font-size: 13px; }
@media (max-width: 600px) { header { padding: 12px 15px; } main { padding: 12px 15px; } }
</style>
</head>
<body>
<header>
    <h1>Учебное кафе</h1>
    <nav>
        {% if user %}
            <a href="/">Заказы</a>
            <a href="/order/new">Новый заказ</a>
            <a href="/menu">Меню</a>
            <a href="/summary">Сводка</a>
            {% if user.role == 'admin' %}
                <a href="/admin/orders">Все заказы</a>
            {% endif %}
        {% endif %}
        <span class="right">
            {% if user %}
                {{ user.full_name }} ({{ user.username }})
                <a href="/logout">Выйти</a>
            {% else %}
                <a href="/login">Войти</a>
                <a href="/register">Регистрация</a>
            {% endif %}
        </span>
    </nav>
</header>
<main>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% for category, message in messages %}
    <div class="flash {{ category }}">{{ message }}</div>
  {% endfor %}
{% endwith %}
{{ content|safe }}
</main>
<footer>{{ site_name }} · Учебный проект</footer>
</body>
</html>
"""


def render(content, title=None):
    return render_template_string(
        PAGE,
        title=title or SITE_NAME,
        site_name=SITE_NAME,
        content=content,
        user=current_user(),
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        full_name = request.form.get("full_name", "").strip()

        ok, error = validate_registration(username, password, password2, full_name)
        if not ok:
            flash(error, "error")
            return redirect(url_for("register"))

        ok, error = create_user(username, password, full_name)
        if not ok:
            flash(error, "error")
            return redirect(url_for("register"))

        flash("Регистрация успешна! Теперь войдите.", "success")
        return redirect(url_for("login"))

    content = (
        "<div class='form-box'>"
        "<h2>Регистрация</h2>"
        "<form method='post'>"
        "<label>Логин</label>"
        "<input name='username' required minlength='3' maxlength='30' placeholder='ivan'>"
        "<label>Ваше имя</label>"
        "<input name='full_name' required maxlength='100' placeholder='Иван Иванов'>"
        "<label>Пароль</label>"
        "<input type='password' name='password' required minlength='6' placeholder='минимум 6 символов'>"
        "<label>Повторите пароль</label>"
        "<input type='password' name='password2' required minlength='6'>"
        "<button type='submit'>Зарегистрироваться</button>"
        "</form>"
        "<p style='text-align:center;margin-top:15px'>"
        "Уже есть аккаунт? <a href='/login'>Войти</a></p>"
        "</div>"
    )
    return render(content, title="Регистрация — " + SITE_NAME)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        user, error = validate_login(username, password)
        if error:
            flash(error, "error")
            return redirect(url_for("login"))
        session["user_id"] = user["id"]
        flash("Добро пожаловать, " + user["full_name"] + "!", "success")
        return redirect(url_for("index"))

    content = (
        "<div class='form-box'>"
        "<h2>Вход</h2>"
        "<form method='post'>"
        "<label>Логин</label>"
        "<input name='username' required>"
        "<label>Пароль</label>"
        "<input type='password' name='password' required>"
        "<button type='submit'>Войти</button>"
        "</form>"
        "<p style='text-align:center;margin-top:15px'>"
        "Нет аккаунта? <a href='/register'>Зарегистрироваться</a></p>"
        "</div>"
    )
    return render(content, title="Вход — " + SITE_NAME)


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из системы", "success")
    return redirect(url_for("index"))


@app.route("/")
@login_required
def index():
    user = current_user()
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "все")
    orders = get_orders(user=user, search=search or None, status=status)

    rows = ""
    for o in orders:
        rows += "<tr>"
        rows += "<td>" + str(o["id"]) + "</td>"
        rows += "<td>" + o["created_at"] + "</td>"
        rows += "<td>" + ("%.2f" % o["total"]) + " руб.</td>"
        rows += "<td>" + o["status"] + "</td>"
        rows += "<td><a href='/order/" + str(o["id"]) + "'>Открыть</a> "
        rows += "<form method='post' action='/order/" + str(o["id"]) + "/delete' "
        rows += "onsubmit=\"return confirm('Удалить заказ?');\" style='display:inline'>"
        rows += "<button type='submit' class='link-danger'>Удалить</button></form></td>"
        rows += "</tr>"
    if not rows:
        rows = "<tr><td colspan='5'>У вас пока нет заказов</td></tr>"

    opts = ""
    for v, l in [("все", "Все"), ("новый", "Новый"),
                 ("выполнен", "Выполнен"), ("отменён", "Отменён")]:
        sel = " selected" if status == v else ""
        opts += "<option value='" + v + "'" + sel + ">" + l + "</option>"

    content = (
        "<h2>Мои заказы</h2>"
        "<form method='get' class='toolbar'>"
        "<input name='search' placeholder='Поиск' value='" + search + "'>"
        "<select name='status'>" + opts + "</select>"
        "<button type='submit'>Найти</button>"
        "<a href='/order/new' class='btn btn-green'>Новый заказ</a>"
        "</form>"
        "<table><thead><tr><th>№</th><th>Дата</th><th>Сумма</th>"
        "<th>Статус</th><th>Действия</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>"
    )
    return render(content, title="Мои заказы — " + SITE_NAME)


@app.route("/order/new", methods=["GET", "POST"])
@login_required
def new_order():
    user = current_user()
    items = get_all_menu_items()

    if request.method == "POST":
        status = request.form.get("status", "новый")
        ok, error, status = validate_status(status)
        if not ok:
            flash(error, "error")
            return redirect(url_for("new_order"))

        lines = []
        for item in items:
            raw = request.form.get("qty_" + str(item["id"]), "").strip()
            if raw in ("", "0"):
                continue
            ok, error, qty = validate_quantity(raw)
            if not ok:
                flash(item["name"] + ": " + error, "error")
                return redirect(url_for("new_order"))
            lines.append({"menu_item_id": item["id"], "quantity": qty})

        if not lines:
            flash("Добавьте хотя бы одну позицию", "error")
            return redirect(url_for("new_order"))

        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        oid, error = create_order(user["id"], created_at, status, lines)
        if error:
            flash(error, "error")
            return redirect(url_for("new_order"))
        flash("Заказ №" + str(oid) + " создан", "success")
        return redirect(url_for("index"))

    rows = ""
    for item in items:
        rows += "<tr>"
        rows += "<td>" + item["name"] + "</td>"
        rows += "<td>" + ("%.2f" % item["price"]) + " руб.</td>"
        rows += "<td><input type='number' name='qty_" + str(item["id"]) + "' min='0' value='0'></td>"
        rows += "</tr>"
    if not rows:
        rows = "<tr><td colspan='3'>Меню пустое</td></tr>"

    content = (
        "<h2>Новый заказ</h2>"
        "<form method='post'>"
        "<table><thead><tr><th>Позиция</th><th>Цена</th><th>Кол-во</th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>"
        "<label>Статус:</label>"
        "<select name='status'>"
        "<option value='новый'>Новый</option>"
        "<option value='выполнен'>Выполнен</option>"
        "</select>"
        "<button type='submit'>Сохранить</button>"
        "<a href='/' class='btn'>Отмена</a>"
        "</form>"
    )
    return render(content, title="Новый заказ — " + SITE_NAME)


@app.route("/order/<int:oid>")
@login_required
def view_order(oid):
    user = current_user()
    order, lines = get_order(oid)
    if not order:
        flash("Заказ не найден", "error")
        return redirect(url_for("index"))
    if order["user_id"] != user["id"] and user["role"] != "admin":
        flash("Это не ваш заказ", "error")
        return redirect(url_for("index"))

    rows = ""
    for l in lines:
        rows += "<tr>"
        rows += "<td>" + l["name"] + "</td>"
        rows += "<td>" + ("%.2f" % l["price"]) + " руб.</td>"
        rows += "<td>" + str(l["quantity"]) + "</td>"
        rows += "<td>" + ("%.2f" % l["line_total"]) + " руб.</td>"
        rows += "</tr>"

    opts = ""
    for v in ("новый", "выполнен", "отменён"):
        sel = " selected" if order["status"] == v else ""
        opts += "<option value='" + v + "'" + sel + ">" + v.capitalize() + "</option>"

    owner_info = ""
    if user["role"] == "admin":
        owner_info = "<p>Клиент: " + order["user_name"] + " (" + order["username"] + ")</p>"

    content = (
        "<h2>Заказ №" + str(order["id"]) + "</h2>" + owner_info +
        "<p>Дата: " + order["created_at"] + "</p>"
        "<table><thead><tr><th>Позиция</th><th>Цена</th><th>Кол-во</th>"
        "<th>Стоимость</th></tr></thead><tbody>" + rows + "</tbody></table>"
        "<p><strong>Итого: " + ("%.2f" % order["total"]) + " руб.</strong></p>"
        "<form method='post' action='/order/" + str(order["id"]) + "/status'>"
        "<label>Статус:</label>"
        "<select name='status'>" + opts + "</select>"
        "<button type='submit'>Сохранить</button>"
        "</form>"
    )
    return render(content, title="Заказ №" + str(oid) + " — " + SITE_NAME)


@app.route("/order/<int:oid>/status", methods=["POST"])
@login_required
def change_status(oid):
    user = current_user()
    order, _ = get_order(oid)
    if not order:
        flash("Заказ не найден", "error")
        return redirect(url_for("index"))
    if order["user_id"] != user["id"] and user["role"] != "admin":
        flash("Нет доступа", "error")
        return redirect(url_for("index"))

    status = request.form.get("status", "")
    ok, error, status = validate_status(status)
    if ok:
        update_order_status(oid, status)
        flash("Статус обновлён", "success")
    else:
        flash(error, "error")
    return redirect(url_for("view_order", oid=oid))


@app.route("/order/<int:oid>/delete", methods=["POST"])
@login_required
def remove_order(oid):
    user = current_user()
    order, _ = get_order(oid)
    if not order:
        flash("Заказ не найден", "error")
        return redirect(url_for("index"))
    if order["user_id"] != user["id"] and user["role"] != "admin":
        flash("Нет доступа", "error")
        return redirect(url_for("index"))

    delete_order(oid)
    flash("Заказ №" + str(oid) + " удалён", "success")
    return redirect(url_for("index"))


@app.route("/menu", methods=["GET", "POST"])
@login_required
def menu():
    user = current_user()
    if request.method == "POST":
        if user["role"] != "admin":
            flash("Только администратор может менять меню", "error")
            return redirect(url_for("menu"))
        name = request.form.get("name", "")
        price = request.form.get("price", "")
        ok, error, data = validate_menu_item(name, price)
        if ok:
            add_menu_item(data["name"], data["price"])
            flash("Позиция добавлена", "success")
        else:
            flash(error, "error")
        return redirect(url_for("menu"))

    items = get_all_menu_items()
    rows = ""
    for i in items:
        delete_cell = ""
        if user["role"] == "admin":
            delete_cell = "<td><a href='/menu/" + str(i["id"]) + "/delete'>Удалить</a></td>"
        rows += "<tr><td>" + i["name"] + "</td>"
        rows += "<td>" + ("%.2f" % i["price"]) + " руб.</td>" + delete_cell + "</tr>"
    if not rows:
        rows = "<tr><td colspan='3'>Меню пустое</td></tr>"

    add_form = ""
    if user["role"] == "admin":
        add_form = (
            "<form method='post' class='toolbar'>"
            "<input name='name' placeholder='Название' required>"
            "<input name='price' type='number' step='0.01' min='0.01' placeholder='Цена' required>"
            "<button type='submit'>Добавить</button>"
            "</form>"
        )

    content = (
        "<h2>Меню учебного кафе</h2>" + add_form +
        "<table><thead><tr><th>Название</th><th>Цена</th><th></th></tr></thead>"
        "<tbody>" + rows + "</tbody></table>"
    )
    return render(content, title="Меню — " + SITE_NAME)


@app.route("/menu/<int:iid>/delete")
@admin_required
def remove_menu_item(iid):
    ok, error = delete_menu_item(iid)
    flash(error if not ok else "Позиция удалена", "error" if not ok else "success")
    return redirect(url_for("menu"))


@app.route("/summary")
@login_required
def summary():
    user = current_user()
    date_str = request.args.get("date", date.today().isoformat())
    data = get_summary(date_str, user=user)
    title = "Моя сводка" if user["role"] != "admin" else "Общая сводка"

    content = (
        "<h2>" + title + " за " + date_str + "</h2>"
        "<form method='get' class='toolbar'>"
        "<input type='date' name='date' value='" + date_str + "'>"
        "<button type='submit'>Показать</button>"
        "</form>"
        "<table>"
        "<tr><th>Всего заказов</th><td>" + str(data["всего"]) + "</td></tr>"
        "<tr><th>Новых</th><td>" + str(data["новый"]) + "</td></tr>"
        "<tr><th>Выполнено</th><td>" + str(data["выполнен"]) + "</td></tr>"
        "<tr><th>Отменено</th><td>" + str(data["отменён"]) + "</td></tr>"
        "<tr><th>Выручка</th><td>" + ("%.2f" % data["выручка"]) + " руб.</td></tr>"
        "</table>"
    )
    return render(content, title="Сводка — " + SITE_NAME)


@app.route("/admin/orders")
@admin_required
def admin_orders():
    search = request.args.get("search", "").strip()
    status = request.args.get("status", "все")
    orders = get_orders(user=None, search=search or None, status=status)

    rows = ""
    for o in orders:
        rows += "<tr>"
        rows += "<td>" + str(o["id"]) + "</td>"
        rows += "<td>" + o["created_at"] + "</td>"
        rows += "<td>" + ("%.2f" % o["total"]) + " руб.</td>"
        rows += "<td>" + o["status"] + "</td>"
        rows += "<td><a href='/order/" + str(o["id"]) + "'>Открыть</a></td>"
        rows += "</tr>"
    if not rows:
        rows = "<tr><td colspan='5'>Заказов нет</td></tr>"

    content = (
        "<h2>Все заказы</h2>"
        "<form method='get' class='toolbar'>"
        "<input name='search' placeholder='Поиск' value='" + search + "'>"
        "<select name='status'>"
        "<option value='все'>Все</option>"
        "<option value='новый'>Новый</option>"
        "<option value='выполнен'>Выполнен</option>"
        "<option value='отменён'>Отменён</option>"
        "</select>"
        "<button type='submit'>Найти</button>"
        "</form>"
        "<table><thead><tr><th>№</th><th>Дата</th><th>Сумма</th>"
        "<th>Статус</th><th></th></tr></thead><tbody>" + rows + "</tbody></table>"
    )
    return render(content, title="Все заказы — " + SITE_NAME)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    app.run(host="0.0.0.0", port=port)