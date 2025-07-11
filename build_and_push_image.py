# build_and_push_image.py

import os
import json
import subprocess
import time
import sys # Import sys for command-line arguments
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    AWS_REGION, INPUT_BUCKET_NAME, LAMBDA_FUNCTION_NAME, LAMBDA_HANDLER,
    LAMBDA_TIMEOUT, LAMBDA_MEMORY, ECR_REPOSITORY_NAME, LAMBDA_ROLE_NAME,
    OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME
)
# Import AWS credentials
from key import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Set AWS credentials for boto3 clients
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY

iam_client = boto3_client('iam', region_name=AWS_REGION)
ecr_client = boto3_client('ecr', region_name=AWS_REGION)
lambda_client = boto3_client('lambda', region_name=AWS_REGION)
s3_client = boto3_client('s3', region_name=AWS_REGION)

def get_ecr_repository_uri():
    """
    Retrieves the ECR repository URI. Assumes the repository already exists.
    """
    print(f"Retrieving ECR repository URI for: {ECR_REPOSITORY_NAME}")
    try:
        response = ecr_client.describe_repositories(repositoryNames=[ECR_REPOSITORY_NAME])
        repo_uri = response['repositories'][0]['repositoryUri']
        print(f"Found ECR repository URI: {repo_uri}")
        return repo_uri
    except ClientError as e:
        if e.response['Error']['Code'] == 'RepositoryNotFoundException':
            print(f"Error: ECR repository '{ECR_REPOSITORY_NAME}' not found. Please run setup.py first.")
            raise
        else:
            print(f"Error retrieving ECR repository URI: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while retrieving ECR repository URI: {e}")
        raise

def build_and_push_docker_image(repo_uri):
    """
    Builds the Docker image and pushes it to ECR.
    """
    print("\n--- Building and Pushing Docker Image ---")
    image_tag = f"{repo_uri}:latest"

    # 1. Login to ECR
    print("Logging in to ECR...")
    try:
        cmd = ["aws", "ecr", "get-login-password", "--region", AWS_REGION]
        login_password = subprocess.check_output(cmd).decode('utf-8').strip()

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

def get_iam_role_arn():
    """
    Retrieves the IAM role ARN. Assumes the role already exists.
    """
    print(f"Retrieving IAM role ARN for: {LAMBDA_ROLE_NAME}")
    try:
        response = iam_client.get_role(RoleName=LAMBDA_ROLE_NAME)
        role_arn = response['Role']['Arn']
        print(f"Found IAM role ARN: {role_arn}")
        return role_arn
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"Error: IAM role '{LAMBDA_ROLE_NAME}' not found. Please run setup.py first.")
            raise
        else:
            print(f"Error retrieving IAM role ARN: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while retrieving IAM role ARN: {e}")
        raise

def create_or_update_lambda_function(image_uri, role_arn):
    """
    Creates or updates the AWS Lambda function.
    """
    print(f"\nCreating or updating Lambda function: {LAMBDA_FUNCTION_NAME}")
    try:
        response = lambda_client.create_function(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Role=role_arn,
            Code={
                'ImageUri': image_uri
            },
            PackageType='Image',
            # Removed 'Handler' parameter as it's not supported for container images
            # Removed 'Runtime' parameter as it's not supported for container images
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
                # Removed 'Handler' parameter for consistency
                # Removed 'Runtime' parameter for consistency
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
    """
    print(f"\nConfiguring S3 trigger for bucket '{bucket_name}' to Lambda function '{LAMBDA_FUNCTION_NAME}'")
    try:
        # Add permission for S3 to invoke Lambda
        try:
            lambda_client.get_policy(FunctionName=LAMBDA_FUNCTION_NAME)
            print("Lambda policy already exists. Checking for S3 permission.")
            try:
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
    Main function to build/push Docker image and deploy/update Lambda function.
    Accepts 'skip_docker_build_push' argument to skip Docker operations.
    """
    # Parse command-line arguments
    args = {}
    for arg in sys.argv[1:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            args[key] = value

    skip_docker_build_push = args.get('skip_docker_build_push', 'False').lower() == 'true'

    print("--- Starting Docker Image Build/Push and Lambda Deployment ---")
    if skip_docker_build_push:
        print("Skipping Docker image build and push as 'skip_docker_build_push' is True.")
    else:
        print("Proceeding with Docker image build and push.")

    # Get ECR Repository URI (assumes it's created by setup.py)
    repo_uri = get_ecr_repository_uri()

    # Build and Push Docker Image (conditional)
    if not skip_docker_build_push:
        image_uri = build_and_push_docker_image(repo_uri)
    else:
        # If skipping build/push, assume the image is already at the latest tag in ECR
        image_uri = f"{repo_uri}:latest"
        print(f"Assuming image URI: {image_uri} (from ECR repository URI and 'latest' tag).")


    # Get IAM Role ARN (assumes it's created by setup.py)
    role_arn = get_iam_role_arn()

    # Create or Update Lambda Function
    function_arn = create_or_update_lambda_function(image_uri, role_arn)

    # Configure S3 Trigger
    configure_s3_trigger(function_arn, INPUT_BUCKET_NAME)

    print("\n--- Docker Image Build/Push and Lambda Deployment Completed Successfully ---")
    print(f"Lambda Function ARN: {function_arn}")
    print(f"ECR Image URI: {image_uri}")
    print(f"IAM Role ARN: {role_arn}")

if __name__ == "__main__":
    main()
