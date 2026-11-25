import os
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash
from botocore.exceptions import ClientError

from db import users_table, dynamodb
from auth import login_required, role_required

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = None
        if email:
            try:
                user = users_table.get_item(Key={"email": email}).get("Item")
            except ClientError:
                app.logger.exception("User lookup failed")
                flash("Could not reach the database. Please try again.", "danger")
                return render_template("login.html")

        if (user and user.get("status") == "active"
                and check_password_hash(user.get("passwordHash", ""), password)):
            session.clear()
            session["user_id"] = user["email"]
            session["name"] = user.get("name", user["email"])
            session["role"] = user["role"]
            session["building_ids"] = list(user.get("buildingIds", []))
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@role_required("admin")
def admin_home():
    return render_template("admin_home.html")


@app.route("/health")
def health():
    count = dynamodb.Table("Categories").scan(Select="COUNT")["Count"]
    return jsonify(status="ok", categories=count)


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403