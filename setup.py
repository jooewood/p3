# setup.py

import os
import json
import subprocess
import time
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    AWS_REGION, INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME,
    LAMBDA_FUNCTION_NAME, LAMBDA_HANDLER, LAMBDA_TIMEOUT, LAMBDA_MEMORY,
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
lambda_client = boto3_client('lambda', region_name=AWS_REGION)

def create_s3_bucket(bucket_name):
    """
    Creates an S3 bucket if it doesn't exist.
    如果S3桶不存在，则创建它。
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
    如果DynamoDB表不存在，则创建它。
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
    将学生数据从JSON文件加载到DynamoDB中。
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
    为Lambda函数创建具有必要权限的IAM角色。
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
    如果ECR仓库不存在，则创建它。
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


def build_and_push_docker_image(repo_uri):
    """
    Builds the Docker image and pushes it to ECR.
    构建Docker镜像并将其推送到ECR。
    """
    print("\n--- Building and Pushing Docker Image ---")
    image_tag = f"{repo_uri}:latest"

    # 1. Login to ECR
    print("Logging in to ECR...")
    try:
        # Get ECR login command
        cmd = ["aws", "ecr", "get-login-password", "--region", AWS_REGION]
        login_password = subprocess.check_output(cmd).decode('utf-8').strip()

        # Execute docker login
        login_cmd = f"docker login --username AWS --password-stdin {repo_uri.split('/')[0]}"
        process = subprocess.Popen(login_cmd.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(input=login_password.encode())
        if process.returncode != 0:
            raise Exception(f"Docker login failed: {stderr.decode()}")
        print("Docker login successful.")
    except Exception as e:
        print(f"Error logging into ECR: {e}")
        raise

    # 2. Build Docker image
    print(f"Building Docker image: {image_tag}")
    try:
        subprocess.run(["docker", "build", "-t", image_tag, "."], check=True)
        print("Docker image built successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Docker build failed: {e}")
        raise

    # 3. Push Docker image to ECR
    print(f"Pushing Docker image to ECR: {image_tag}")
    try:
        subprocess.run(["docker", "push", image_tag], check=True)
        print("Docker image pushed to ECR successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Docker push failed: {e}")
        raise

    return image_tag

def create_lambda_function(image_uri, role_arn):
    """
    Creates the AWS Lambda function.
    创建AWS Lambda函数。
    """
    print(f"\nCreating Lambda function: {LAMBDA_FUNCTION_NAME}")
    try:
        response = lambda_client.create_function(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Role=role_arn,
            Code={
                'ImageUri': image_uri
            },
            PackageType='Image',
            Handler=LAMBDA_HANDLER,
            Runtime='python3.8', # This is a placeholder, runtime for image is not directly set here
            Timeout=LAMBDA_TIMEOUT,
            MemorySize=LAMBDA_MEMORY,
            Environment={
                'Variables': {
                    'INPUT_BUCKET_NAME': INPUT_BUCKET_NAME,
                    'OUTPUT_BUCKET_NAME': OUTPUT_BUCKET_NAME,
                    'DYNAMODB_TABLE_NAME': DYNAMODB_TABLE_NAME
                }
            }
        )
        print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' created successfully.")
        return response['FunctionArn']
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceConflictException':
            print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' already exists. Updating it.")
            response = lambda_client.update_function_code(
                FunctionName=LAMBDA_FUNCTION_NAME,
                ImageUri=image_uri
            )
            lambda_client.update_function_configuration(
                FunctionName=LAMBDA_FUNCTION_NAME,
                Role=role_arn,
                Timeout=LAMBDA_TIMEOUT,
                MemorySize=LAMBDA_MEMORY,
                Environment={
                    'Variables': {
                        'INPUT_BUCKET_NAME': INPUT_BUCKET_NAME,
                        'OUTPUT_BUCKET_NAME': OUTPUT_BUCKET_NAME,
                        'DYNAMODB_TABLE_NAME': DYNAMODB_TABLE_NAME
                    }
                }
            )
            print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' updated successfully.")
            return response['FunctionArn']
        else:
            print(f"Error creating/updating Lambda function: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while creating/updating Lambda function: {e}")
        raise

def configure_s3_trigger(function_arn, bucket_name):
    """
    Configures an S3 trigger for the Lambda function.
    为Lambda函数配置S3触发器。
    """
    print(f"\nConfiguring S3 trigger for bucket '{bucket_name}' to Lambda function '{LAMBDA_FUNCTION_NAME}'")
    try:
        # Add permission for S3 to invoke Lambda
        # Check if permission already exists to avoid duplicates
        try:
            lambda_client.get_policy(FunctionName=LAMBDA_FUNCTION_NAME)
            print("Lambda policy already exists. Checking for S3 permission.")
            # If policy exists, try to remove existing permission to re-add
            # This is a workaround for idempotent permission updates
            try:
                # List all statements and find the one related to S3 trigger
                policy = json.loads(lambda_client.get_policy(FunctionName=LAMBDA_FUNCTION_NAME)['Policy'])
                for statement in policy['Statement']:
                    if 'Condition' in statement and 'ArnLike' in statement['Condition']['AWS:SourceArn']:
                        if f"arn:aws:s3:::{bucket_name}" in statement['Condition']['ArnLike']['AWS:SourceArn']:
                            sid = statement['Sid']
                            print(f"Removing existing S3 trigger permission with Sid: {sid}")
                            lambda_client.remove_permission(
                                FunctionName=LAMBDA_FUNCTION_NAME,
                                StatementId=sid
                            )
                            print(f"Removed old permission for {bucket_name}.")
                            break
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print("Lambda policy not found, will add permission.")
                else:
                    print(f"Error checking/removing existing Lambda policy: {e}")

        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print("Lambda policy does not exist, will create new permission.")
            else:
                print(f"Error getting Lambda policy: {e}")

        # Add the new permission
        lambda_client.add_permission(
            FunctionName=LAMBDA_FUNCTION_NAME,
            StatementId=f'S3InvokePermission-{int(time.time())}', # Unique ID
            Action='lambda:InvokeFunction',
            Principal='s3.amazonaws.com',
            SourceArn=f'arn:aws:s3:::{bucket_name}',
            SourceAccount=iam_client.get_user()['User']['Arn'].split(':')[4] # Get current AWS account ID
        )
        print("Permission added for S3 to invoke Lambda.")

        # Configure S3 bucket notification
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'LambdaFunctionConfigurations': [
                    {
                        'LambdaFunctionArn': function_arn,
                        'Events': ['s3:ObjectCreated:*'],
                        'Filter': {
                            'Key': {
                                'FilterRules': [
                                    {'Name': 'suffix', 'Value': '.mp4'},
                                    {'Name': 'suffix', 'Value': '.MP4'}
                                ]
                            }
                        }
                    }
                ]
            }
        )
        print(f"S3 bucket '{bucket_name}' configured to trigger Lambda on new .mp4 objects.")
    except Exception as e:
        print(f"Error configuring S3 trigger: {e}")
        raise

def main():
    """
    Main function to set up all AWS resources.
    设置所有AWS资源的主函数。
    """
    print("--- Starting AWS Resource Setup ---")

    # Create S3 Buckets
    create_s3_bucket(INPUT_BUCKET_NAME)
    create_s3_bucket(OUTPUT_BUCKET_NAME)

    # Create DynamoDB Table and Load Data
    create_dynamodb_table(DYNAMODB_TABLE_NAME)
    load_student_data_to_dynamodb(DYNAMODB_TABLE_NAME, STUDENT_DATA_FILE)

    # Create IAM Role
    role_arn = create_iam_role()

    # Create ECR Repository
    repo_uri = create_ecr_repository()

    # Build and Push Docker Image
    image_uri = build_and_push_docker_image(repo_uri)

    # Create Lambda Function
    function_arn = create_lambda_function(image_uri, role_arn)

    # Configure S3 Trigger
    configure_s3_trigger(function_arn, INPUT_BUCKET_NAME)

    print("\n--- AWS Resource Setup Completed Successfully ---")
    print(f"Lambda Function ARN: {function_arn}")
    print(f"ECR Image URI: {image_uri}")
    print(f"IAM Role ARN: {role_arn}")

if __name__ == "__main__":
    main()
