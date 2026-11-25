import getpass
from datetime import datetime, timezone

from botocore.exceptions import ClientError
from werkzeug.security import generate_password_hash

from db import users_table

ROLES = ("admin", "manager", "coordinator", "inspector")

email = input("Email: ").strip().lower()
name = input("Full name: ").strip()
role = input(f"Role {ROLES}: ").strip().lower()
buildings = input("Building IDs, comma separated (blank for none): ").strip()
password = getpass.getpass("Password (at least 8 characters): ")
repeat = getpass.getpass("Repeat password: ")

if not email or not name:
    raise SystemExit("Email and name are required.")
if role not in ROLES:
    raise SystemExit(f"Role must be one of {ROLES}.")
if len(password) < 8 or password != repeat:
    raise SystemExit("Passwords must match and be at least 8 characters.")

building_ids = [b.strip() for b in buildings.split(",") if b.strip()]

try:
    users_table.put_item(
        Item={
            "email": email,
            "name": name,
            "role": role,
            "buildingIds": building_ids,
            "passwordHash": generate_password_hash(password),
            "status": "active",
            "createdAt": datetime.now(timezone.utc).isoformat(),
        },
        ConditionExpression="attribute_not_exists(email)",
    )
    print(f"Created {role} user {email}")
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        raise SystemExit("That email already exists. Use another email or delete the old item in DynamoDB.")
    raise