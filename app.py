import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_portfolio = db.execute(
        "SELECT user_id, symbol, symbol_name, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) >= 1",
        session["user_id"]
    )

    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    user_cash = user_cash[0]["cash"]

    total_stock_value = 0
    for row in user_portfolio:
        symbol_data = lookup(row["symbol"])
        row["price"] = symbol_data["price"]
        row["total"] = symbol_data["price"] * row["total_shares"]
        total_stock_value += row["total"]

    user_portfolio = sorted(user_portfolio, key=lambda row: row["total"], reverse=True)

    wealth = user_cash + total_stock_value
    return render_template("index.html", user_cash=user_cash, user_portfolio=user_portfolio, wealth=wealth)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
            if shares <= 0:
                return apology("shares must be a positive whole number", 400)
        except ValueError:
            return apology("shares must be a positive whole number", 400)

        quoted = lookup(symbol)

        if not quoted:
            return apology("Invalid symbol", 400)

        user_cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        cash = user_cash[0]["cash"]
        cost = quoted["price"] * int(shares)

        if cost > cash:
            return apology("not enough cash", 400)
        else:
            db.execute(
                "INSERT INTO transactions (user_id, symbol, symbol_name, shares, price) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], quoted["symbol"], quoted["name"], int(shares), quoted["price"]
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                cash - cost, session["user_id"]
            )
            return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_portfolio = db.execute(
        "SELECT user_id, symbol, symbol_name, shares, price, time FROM transactions WHERE user_id = ?", session["user_id"]
    )

    for row in user_portfolio:
        if int(row["shares"]) > 0:
            row["trade"] = "Buy"
        if int(row["shares"]) < 0:
            row["trade"] = "Sell"
            row["shares"] = -int(row["shares"])

    return render_template("history.html", user_portfolio=user_portfolio)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    else:
        symbol = request.form.get("symbol")

        if symbol == "":
            return apology("Quote Empty", 400)

        quoted = lookup(symbol)

        if not quoted:
            return apology("Invalid symbol", 400)

        return render_template("quoted.html", symbol=quoted)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

    if username == "" or password == "" or confirmation == "":
        return apology("Please fill out register form", 400)

    if password == confirmation:
        try:
            hash = generate_password_hash(password, method='pbkdf2', salt_length=16)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
            return redirect("/")
        except:
            return apology("User Exist, 400")
    else:
        return apology("Password and confirm is not same", 400)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares_wts = request.form.get("shares")

        if symbol == "":
            return apology("Invalid symbol", 400)
        if int(shares_wts) <= 0 or not shares_wts.isdigit():
            return apology("shares must be positive and full number", 400)

        quoted = lookup(symbol)

        if not quoted:
            return apology("Invalid symbol", 400)

        symbol_wts = db.execute(
            "SELECT user_id, symbol, SUM(shares) AS total_share from transactions WHERE user_id = ? and symbol = ? GROUP BY symbol HAVING SUM(shares) > 0 ",
            session["user_id"], quoted['symbol']
        )

        if symbol_wts[0]["total_share"] < int(shares_wts):
            return apology("no enough shares to sale", 400)
        else:
            total_sale = quoted["price"] * int(shares_wts)

            user_cash = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
            cash = user_cash[0]["cash"] + total_sale

            db.execute(
                "INSERT INTO transactions (user_id, symbol, symbol_name, shares, price) VALUES (?, ?, ?, ?, ?)",
                session["user_id"], quoted["symbol"], quoted["name"], -int(shares_wts), quoted["price"]
            )
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                cash, session["user_id"]
            )
            return redirect("/")

    else:
        user_portfolio = db.execute(
            "SELECT user_id, symbol, symbol_name, SUM(shares) AS total_shares FROM transactions WHERE user_id = ? GROUP BY symbol HAVING SUM(shares) >= 1",
            session["user_id"]
        )

        for row in user_portfolio:
            row["sell_text"] = row["symbol"] + " - " + str(row["total_shares"]) + " shares"

        return render_template("sell.html", user_portfolio=user_portfolio)


@app.route("/setting", methods=["GET", "POST"])
@login_required
def setting():
    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if old_password == "" or new_password == "" or confirmation == "":
            return apology("Please fill out all field", 400)

        if new_password != confirmation:
            return apology("new password not match", 400)

        user_data = db.execute("SELECT id, hash FROM users WHERE id = ?", session["user_id"])

        if not check_password_hash(user_data[0]["hash"], old_password):
            return apology("Old password incorrect", 400)

        new_hash = generate_password_hash(new_password, method='pbkdf2', salt_length=16)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, session["user_id"])

        return redirect("/")

    else:
        return render_template("setting.html")
