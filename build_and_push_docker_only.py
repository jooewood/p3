# build_and_push_docker_only.py

import os
import json
import subprocess
import time
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    AWS_REGION, ECR_REPOSITORY_NAME
)
# Import AWS credentials
from key import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Set AWS credentials for boto3 clients
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY

ecr_client = boto3_client('ecr', region_name=AWS_REGION)

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
            print(f"Error: ECR repository '{ECR_REPOSITORY_NAME}' not found. Please run setup.py first to create it.")
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

def main():
    """
    Main function to build and push the Docker image to ECR.
    """
    print("--- Starting Docker Image Build and Push to ECR ---")

    # Get ECR Repository URI (assumes it's created by setup.py)
    repo_uri = get_ecr_repository_uri()

    # Build and Push Docker Image
    build_and_push_docker_image(repo_uri)

    print("\n--- Docker Image Build and Push to ECR Completed Successfully ---")
    print(f"ECR Image URI: {repo_uri}:latest")

if __name__ == "__main__":
    main()
