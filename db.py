import os
import boto3

REGION = os.environ.get("AWS_REGION", "ap-south-1")
dynamodb = boto3.resource("dynamodb", region_name=REGION)

users_table = dynamodb.Table("Users")
buildings_table = dynamodb.Table("Buildings")
categories_table = dynamodb.Table("Categories")
checklist_table = dynamodb.Table("ChecklistItems")


def scan_all(table):
    """Return every item in a table, following DynamoDB's paging."""
    items = []
    kwargs = {}
    while True:
        resp = table.scan(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]


def query_all(table, **kwargs):
    """Run a query and follow DynamoDB's paging until every item is returned."""
    items = []
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            return items
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]