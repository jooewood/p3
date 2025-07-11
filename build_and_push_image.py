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
    function_exists = False
    try:
        # Check if function already exists
        lambda_client.get_function_configuration(FunctionName=LAMBDA_FUNCTION_NAME)
        function_exists = True
        print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' already exists.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            function_exists = False
            print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' does not exist. Creating new function.")
        else:
            print(f"Error checking Lambda function existence: {e}")
            raise

    if function_exists:
        # If function exists, wait for any previous updates to complete
        print(f"Waiting for any ongoing update for '{LAMBDA_FUNCTION_NAME}' to complete before proceeding...")
        waiter = lambda_client.get_waiter('function_updated')
        try:
            waiter.wait(FunctionName=LAMBDA_FUNCTION_NAME)
            print(f"Previous update for '{LAMBDA_FUNCTION_NAME}' has completed. Proceeding with updates.")
        except Exception as e:
            # If waiter fails, it might be due to a stuck state or other issues.
            # We can still attempt to update, but log the warning.
            print(f"Warning: Waiter for function_updated failed. May proceed with update if function is not stuck. Error: {e}")

        # Fetch current configuration AFTER waiting, and safely access keys
        try:
            current_config = lambda_client.get_function_configuration(FunctionName=LAMBDA_FUNCTION_NAME)
            current_code_info = current_config.get('Code', {})
            current_image_uri = current_code_info.get('ImageUri') # Safely get ImageUri
            current_timeout = current_config.get('Timeout')
            current_memory = current_config.get('MemorySize')
            current_role_arn = current_config.get('Role')
            current_env_vars = current_config.get('Environment', {}).get('Variables', {})

            if not current_image_uri:
                print(f"Warning: Could not retrieve current_image_uri for '{LAMBDA_FUNCTION_NAME}'. This might indicate an incomplete function state. Forcing code update.")
                # If image URI is missing, force an update to ensure it's set
                current_image_uri = "FORCE_UPDATE" # Use a dummy value to trigger update
        except ClientError as e:
            print(f"Error retrieving current function configuration: {e}")
            raise

        # Check if code update is needed
        if current_image_uri != image_uri:
            print(f"Updating Lambda function code for '{LAMBDA_FUNCTION_NAME}' with new image URI: {image_uri}")
            lambda_client.update_function_code(
                FunctionName=LAMBDA_FUNCTION_NAME,
                ImageUri=image_uri
            )
            print(f"Waiting for code update for '{LAMBDA_FUNCTION_NAME}' to complete...")
            waiter.wait(FunctionName=LAMBDA_FUNCTION_NAME) # Wait for code update to finish
            print(f"Code update for '{LAMBDA_FUNCTION_NAME}' has completed.")
        else:
            print(f"Lambda function code for '{LAMBDA_FUNCTION_NAME}' is already up to date.")

        # Check if configuration update is needed
        # Create a dictionary for desired environment variables
        desired_env_vars = {
            'INPUT_BUCKET_NAME': INPUT_BUCKET_NAME,
            'OUTPUT_BUCKET_NAME': OUTPUT_BUCKET_NAME,
            'DYNAMODB_TABLE_NAME': DYNAMODB_TABLE_NAME
        }

        if (current_timeout != LAMBDA_TIMEOUT or
            current_memory != LAMBDA_MEMORY or
            current_role_arn != role_arn or
            current_env_vars != desired_env_vars):
            print(f"Updating Lambda function configuration for '{LAMBDA_FUNCTION_NAME}'...")
            lambda_client.update_function_configuration(
                FunctionName=LAMBDA_FUNCTION_NAME,
                Role=role_arn,
                Timeout=LAMBDA_TIMEOUT,
                MemorySize=LAMBDA_MEMORY,
                Environment={
                    'Variables': desired_env_vars
                }
            )
            print(f"Waiting for configuration update for '{LAMBDA_FUNCTION_NAME}' to complete...")
            waiter.wait(FunctionName=LAMBDA_FUNCTION_NAME) # Wait for config update to finish
            print(f"Configuration update for '{LAMBDA_FUNCTION_NAME}' has completed.")
        else:
            print(f"Lambda function configuration for '{LAMBDA_FUNCTION_NAME}' is already up to date.")

        print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' updated successfully.")
        return lambda_client.get_function_configuration(FunctionName=LAMBDA_FUNCTION_NAME)['FunctionArn']

    else: # Function does not exist, create it
        response = lambda_client.create_function(
            FunctionName=LAMBDA_FUNCTION_NAME,
            Role=role_arn,
            Code={
                'ImageUri': image_uri
            },
            PackageType='Image',
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
        # After creation, wait for it to be active
        print(f"Waiting for Lambda function '{LAMBDA_FUNCTION_NAME}' to become active...")
        waiter = lambda_client.get_waiter('function_active')
        waiter.wait(FunctionName=LAMBDA_FUNCTION_NAME)
        print(f"Lambda function '{LAMBDA_FUNCTION_NAME}' is now active.")
        return response['FunctionArn']

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
                    # Safely get 'Condition' and then 'AWS:SourceArn'
                    condition = statement.get('Condition', {})
                    arn_like_condition = condition.get('ArnLike', {})
                    source_arn = arn_like_condition.get('AWS:SourceArn')

                    if source_arn and f"arn:aws:s3:::{bucket_name}" in source_arn:
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
                                    # Combined suffix rules into a single .mp4 filter
                                    {'Name': 'suffix', 'Value': '.mp4'}
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
