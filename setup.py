# setup.py

import os
import json
import time
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    AWS_REGION, INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME,
    ECR_REPOSITORY_NAME, LAMBDA_ROLE_NAME, STUDENT_DATA_FILE
)
# Import AWS credentials
from key import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Set AWS credentials for boto3 clients
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY

# Initialize AWS clients
s3_client = boto3_client('s3', region_name=AWS_REGION)
dynamodb_client = boto3_client('dynamodb', region_name=AWS_REGION)
iam_client = boto3_client('iam', region_name=AWS_REGION)
ecr_client = boto3_client('ecr', region_name=AWS_REGION)

def create_s3_bucket(bucket_name):
    """
    Creates an S3 bucket if it doesn't exist.
    """
    print(f"Attempting to create S3 bucket: {bucket_name}")
    try:
        s3_client.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={'LocationConstraint': AWS_REGION})
        print(f"Bucket '{bucket_name}' created successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'BucketAlreadyOwnedByYou':
            print(f"Bucket '{bucket_name}' already exists and is owned by you.")
        elif e.response['Error']['Code'] == 'BucketAlreadyExists':
            print(f"Bucket '{bucket_name}' already exists.")
        else:
            print(f"Error creating bucket '{bucket_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while creating bucket '{bucket_name}': {e}")
        raise

def create_dynamodb_table(table_name):
    """
    Creates a DynamoDB table if it doesn't exist.
    """
    print(f"Attempting to create DynamoDB table: {table_name}")
    try:
        dynamodb_client.create_table(
            TableName=table_name,
            KeySchema=[
                {
                    'AttributeName': 'name',
                    'KeyType': 'HASH'  # Partition key
                }
            ],
            AttributeDefinitions=[
                {
                    'AttributeName': 'name',
                    'AttributeType': 'S'
                }
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 5,
                'WriteCapacityUnits': 5
            }
        )
        print(f"Waiting for table '{table_name}' to become active...")
        waiter = dynamodb_client.get_waiter('table_exists')
        waiter.wait(TableName=table_name)
        print(f"Table '{table_name}' created and active.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceInUseException':
            print(f"Table '{table_name}' already exists.")
        else:
            print(f"Error creating table '{table_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while creating table '{table_name}': {e}")
        raise

def load_student_data_to_dynamodb(table_name, data_file):
    """
    Loads student data from a JSON file into DynamoDB.
    """
    print(f"Loading student data from '{data_file}' to table '{table_name}'...")
    try:
        with open(data_file, 'r') as f:
            students = json.load(f)

        for student in students:
            item = {
                'name': {'S': student['name']},
                'major': {'S': student['major']},
                'year': {'S': student['year']}
            }
            dynamodb_client.put_item(TableName=table_name, Item=item)
        print(f"Successfully loaded {len(students)} students into '{table_name}'.")
    except FileNotFoundError:
        print(f"Error: Data file '{data_file}' not found.")
        raise
    except Exception as e:
        print(f"Error loading data to DynamoDB: {e}")
        raise

def create_iam_role():
    """
    Creates an IAM role for the Lambda function with necessary permissions.
    """
    print(f"Creating IAM role: {LAMBDA_ROLE_NAME}")
    assume_role_policy_document = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Service": "lambda.amazonaws.com"
                },
                "Action": "sts:AssumeRole"
            }
        ]
    }
    try:
        response = iam_client.create_role(
            RoleName=LAMBDA_ROLE_NAME,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy_document),
            Description='IAM role for Lambda function to access S3 and DynamoDB'
        )
        role_arn = response['Role']['Arn']
        print(f"Role '{LAMBDA_ROLE_NAME}' created with ARN: {role_arn}")

        # Attach policies
        iam_client.attach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        )
        print("Attached AWSLambdaBasicExecutionRole.")

        iam_client.attach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess' # For S3 read/write
        )
        print("Attached AmazonS3FullAccess.")

        iam_client.attach_role_policy(
            RoleName=LAMBDA_ROLE_NAME,
            PolicyArn='arn:aws:iam::aws:policy/AmazonDynamoDBFullAccess' # For DynamoDB read
        )
        print("Attached AmazonDynamoDBFullAccess.")

        # Give AWS some time to propagate the role and policies
        time.sleep(10)
        return role_arn
    except ClientError as e:
        if e.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f"Role '{LAMBDA_ROLE_NAME}' already exists. Retrieving ARN.")
            role_arn = iam_client.get_role(RoleName=LAMBDA_ROLE_NAME)['Role']['Arn']
            return role_arn
        else:
            print(f"Error creating IAM role: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while creating IAM role: {e}")
        raise

def create_ecr_repository():
    """
    Creates an ECR repository if it doesn't exist.
    """
    print(f"Creating ECR repository: {ECR_REPOSITORY_NAME}")
    try:
        response = ecr_client.create_repository(repositoryName=ECR_REPOSITORY_NAME)
        repo_uri = response['repository']['repositoryUri']
        print(f"ECR repository '{ECR_REPOSITORY_NAME}' created with URI: {repo_uri}")
        return repo_uri
    except ClientError as e:
        if e.response['Error']['Code'] == 'RepositoryAlreadyExistsException':
            print(f"ECR repository '{ECR_REPOSITORY_NAME}' already exists. Retrieving URI.")
            repo_uri = ecr_client.describe_repositories(repositoryNames=[ECR_REPOSITORY_NAME])['repositories'][0]['repositoryUri']
            return repo_uri
        else:
            print(f"Error creating ECR repository: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while creating ECR repository: {e}")
        raise

def main():
    """
    Main function to set up core AWS resources (S3, DynamoDB, IAM, ECR).
    """
    print("--- Starting Core AWS Resource Setup ---")

    # Create S3 Buckets
    create_s3_bucket(INPUT_BUCKET_NAME)
    create_s3_bucket(OUTPUT_BUCKET_NAME)

    # Create DynamoDB Table and Load Data
    create_dynamodb_table(DYNAMODB_TABLE_NAME)
    load_student_data_to_dynamodb(DYNAMODB_TABLE_NAME, STUDENT_DATA_FILE)

    # Create IAM Role
    create_iam_role() # Role ARN is not returned as Lambda creation is moved

    # Create ECR Repository
    create_ecr_repository() # Repo URI is not returned as Docker build/push is moved

    print("\n--- Core AWS Resource Setup Completed Successfully ---")
    print("Next: Test handler.py on EC2, then run build_and_push_image.py to deploy Lambda.")

if __name__ == "__main__":
    main()
