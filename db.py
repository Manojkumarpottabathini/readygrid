import os
import boto3

REGION = os.environ.get("AWS_REGION", "ap-south-1")
dynamodb = boto3.resource("dynamodb", region_name=REGION)

users_table = dynamodb.Table("Users")