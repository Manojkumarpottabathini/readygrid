import os
import re
from datetime import datetime, timezone

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, abort)
from werkzeug.security import check_password_hash, generate_password_hash
from botocore.exceptions import ClientError

from db import users_table, buildings_table, dynamodb, scan_all
from auth import login_required, role_required

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

ROLES = ("admin", "manager", "coordinator", "inspector")
BUILDING_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{2,20}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def parse_floors(text):
    floors = []
    for part in text.split(","):
        part = part.strip()
        if part and part not in floors:
            floors.append(part)
    return floors


def active_coordinators():
    users = scan_all(users_table)
    found = [u for u in users
             if u.get("role") == "coordinator" and u.get("status") == "active"]
    return sorted(found, key=lambda u: u.get("name", ""))


# ------------------------------------------------------------------ login
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
    return render_template("dashbrd.html")


# ------------------------------------------------------------------ admin home
@app.route("/admin")
@role_required("admin")
def admin_home():
    return render_template(
        "admin_home.html",
        building_count=len(scan_all(buildings_table)),
        user_count=len(scan_all(users_table)),
    )


# ------------------------------------------------------------------ buildings
def read_building_form():
    keys = ("buildingId", "name", "address", "floors", "coordinatorId")
    return {k: request.form.get(k, "").strip() for k in keys}


def validate_building(form, coords, creating):
    if creating and not BUILDING_ID_PATTERN.match(form["buildingId"]):
        return "Building ID must be 2-20 letters, numbers or hyphens."
    if not form["name"]:
        return "Building name is required."
    if not parse_floors(form["floors"]):
        return "Enter at least one floor."
    if form["coordinatorId"] and form["coordinatorId"] not in {c["email"] for c in coords}:
        return "Choose a coordinator from the list, or leave it blank."
    return None


@app.route("/admin/buildings")
@role_required("admin")
def admin_buildings():
    buildings = sorted(scan_all(buildings_table), key=lambda b: b["buildingId"])
    names = {u["email"]: u.get("name", u["email"]) for u in scan_all(users_table)}
    return render_template("admin_buildings.html", buildings=buildings, names=names)


@app.route("/admin/buildings/new", methods=["GET", "POST"])
@role_required("admin")
def admin_building_new():
    coords = active_coordinators()
    form = {}
    if request.method == "POST":
        form = read_building_form()
        error = validate_building(form, coords, creating=True)
        if not error:
            try:
                buildings_table.put_item(
                    Item={
                        "buildingId": form["buildingId"],
                        "name": form["name"],
                        "address": form["address"],
                        "floors": parse_floors(form["floors"]),
                        "coordinatorId": form["coordinatorId"],
                        "createdAt": now_iso(),
                    },
                    ConditionExpression="attribute_not_exists(buildingId)",
                )
                flash(f"Building {form['buildingId']} added.", "success")
                return redirect(url_for("admin_buildings"))
            except ClientError as e:
                if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    error = "That Building ID already exists."
                else:
                    app.logger.exception("Building save failed")
                    error = "Could not save the building. Please try again."
        flash(error, "danger")
    return render_template("admin_building_form.html",
                           form=form, coordinators=coords, editing=False)


@app.route("/admin/buildings/<building_id>/edit", methods=["GET", "POST"])
@role_required("admin")
def admin_building_edit(building_id):
    building = buildings_table.get_item(Key={"buildingId": building_id}).get("Item")
    if not building:
        abort(404)
    coords = active_coordinators()

    if request.method == "POST":
        form = read_building_form()
        form["buildingId"] = building_id
        error = validate_building(form, coords, creating=False)
        if not error:
            try:
                buildings_table.update_item(
                    Key={"buildingId": building_id},
                    UpdateExpression=("SET #n = :n, #a = :a, #f = :f, "
                                      "#c = :c, #u = :u"),
                    ExpressionAttributeNames={
                        "#n": "name", "#a": "address", "#f": "floors",
                        "#c": "coordinatorId", "#u": "updatedAt",
                    },
                    ExpressionAttributeValues={
                        ":n": form["name"], ":a": form["address"],
                        ":f": parse_floors(form["floors"]),
                        ":c": form["coordinatorId"], ":u": now_iso(),
                    },
                )
                flash(f"Building {building_id} updated.", "success")
                return redirect(url_for("admin_buildings"))
            except ClientError:
                app.logger.exception("Building update failed")
                error = "Could not save the building. Please try again."
        flash(error, "danger")
    else:
        form = {
            "buildingId": building_id,
            "name": building.get("name", ""),
            "address": building.get("address", ""),
            "floors": ", ".join(building.get("floors", [])),
            "coordinatorId": building.get("coordinatorId", ""),
        }
    return render_template("admin_building_form.html",
                           form=form, coordinators=coords, editing=True)


# ------------------------------------------------------------------ users
@app.route("/admin/users")
@role_required("admin")
def admin_users():
    users = sorted(scan_all(users_table),
                   key=lambda u: (u.get("role", ""), u.get("name", "")))
    return render_template("admin_users.html", users=users)


@app.route("/admin/users/new", methods=["GET", "POST"])
@role_required("admin")
def admin_user_new():
    buildings = sorted(scan_all(buildings_table), key=lambda b: b["buildingId"])
    valid_ids = {b["buildingId"] for b in buildings}
    form = {}
    selected = []

    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("email", "name", "role")}
        form["email"] = form["email"].lower()
        selected = request.form.getlist("buildingIds")
        password = request.form.get("password", "")
        repeat = request.form.get("repeat", "")

        error = None
        if not EMAIL_PATTERN.match(form["email"]):
            error = "Enter a valid email address."
        elif not form["name"]:
            error = "Full name is required."
        elif form["role"] not in ROLES:
            error = "Choose a role."
        elif len(password) < 8 or password != repeat:
            error = "Passwords must match and be at least 8 characters."
        elif form["role"] != "admin" and not selected:
            error = "Choose at least one building for this user."
        elif any(b not in valid_ids for b in selected):
            error = "One of the selected buildings does not exist."

        if not error:
            try:
                users_table.put_item(
                    Item={
                        "email": form["email"],
                        "name": form["name"],
                        "role": form["role"],
                        "buildingIds": [] if form["role"] == "admin" else selected,
                        "passwordHash": generate_password_hash(password),
                        "status": "active",
                        "createdAt": now_iso(),
                    },
                    ConditionExpression="attribute_not_exists(email)",
                )
                flash(f"{form['role'].capitalize()} {form['email']} created.", "success")
                return redirect(url_for("admin_users"))
            except ClientError as e:
                if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                    error = "A user with that email already exists."
                else:
                    app.logger.exception("User save failed")
                    error = "Could not save the user. Please try again."
        flash(error, "danger")

    return render_template("admin_user_form.html", form=form, roles=ROLES,
                           buildings=buildings, selected=selected)


@app.route("/admin/users/<email>/toggle", methods=["POST"])
@role_required("admin")
@app.route("/admin/users/<email>/edit", methods=["GET", "POST"])
@role_required("admin")
def admin_user_edit(email):
    email = email.lower()
    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user:
        abort(404)

    buildings = sorted(scan_all(buildings_table), key=lambda b: b["buildingId"])
    valid_ids = {b["buildingId"] for b in buildings}

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        role = request.form.get("role", "").strip()
        selected = request.form.getlist("buildingIds")

        error = None
        if not name:
            error = "Full name is required."
        elif role not in ROLES:
            error = "Choose a role."
        elif email == session["user_id"] and role != "admin":
            error = "You cannot change your own role."
        elif role != "admin" and not selected:
            error = "Choose at least one building for this user."
        elif any(b not in valid_ids for b in selected):
            error = "One of the selected buildings does not exist."

        if not error:
            try:
                users_table.update_item(
                    Key={"email": email},
                    UpdateExpression="SET #n = :n, #r = :r, #b = :b, #u = :u",
                    ExpressionAttributeNames={
                        "#n": "name", "#r": "role",
                        "#b": "buildingIds", "#u": "updatedAt",
                    },
                    ExpressionAttributeValues={
                        ":n": name, ":r": role,
                        ":b": [] if role == "admin" else selected,
                        ":u": now_iso(),
                    },
                )
                flash(f"{email} updated.", "success")
                return redirect(url_for("admin_users"))
            except ClientError:
                app.logger.exception("User update failed")
                error = "Could not save the user. Please try again."
        flash(error, "danger")
        form = {"name": name, "role": role}
    else:
        form = {"name": user.get("name", ""), "role": user.get("role", "")}
        selected = list(user.get("buildingIds", []))

    return render_template("admin_user_edit.html", email=email, form=form,
                           roles=ROLES, buildings=buildings, selected=selected)
def admin_user_toggle(email):
    email = email.lower()
    if email == session["user_id"]:
        flash("You cannot deactivate your own account.", "warning")
        return redirect(url_for("admin_users"))

    user = users_table.get_item(Key={"email": email}).get("Item")
    if not user:
        abort(404)

    new_status = "inactive" if user.get("status") == "active" else "active"
    users_table.update_item(
        Key={"email": email},
        UpdateExpression="SET #s = :s",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":s": new_status},
    )
    flash(f"{email} is now {new_status}.", "success")
    return redirect(url_for("admin_users"))


# ------------------------------------------------------------------ misc
@app.route("/health")
def health():
    count = dynamodb.Table("Categories").scan(Select="COUNT")["Count"]
    return jsonify(status="ok", categories=count)


@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404