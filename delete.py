# cleanup.py

import os
import json
import time
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    AWS_REGION, INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME,
    LAMBDA_FUNCTION_NAME, ECR_REPOSITORY_NAME, LAMBDA_ROLE_NAME
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

def clear_s3_bucket_contents(bucket_name):
    """
    Clears all objects from an S3 bucket.
    清空S3桶中的所有对象。
    """
    print(f"Clearing contents of S3 bucket: {bucket_name}")
    try:
        response = s3_client.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            objects_to_delete = [{'Key': obj['Key']} for obj in response['Contents']]
            s3_client.delete_objects(Bucket=bucket_name, Delete={'Objects': objects_to_delete})
            print(f"Cleared {len(objects_to_delete)} objects from '{bucket_name}'.")
        else:
            print(f"Bucket '{bucket_name}' is already empty.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"Bucket '{bucket_name}' does not exist, nothing to clear.")
        else:
            print(f"Error clearing bucket '{bucket_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while clearing bucket '{bucket_name}': {e}")
        raise

def delete_s3_bucket(bucket_name):
    """
    Deletes an S3 bucket after emptying its contents.
    清空S3桶内容后删除S3桶。
    """
    print(f"Attempting to delete S3 bucket: {bucket_name}")
    try:
        # First, delete all objects in the bucket
        clear_s3_bucket_contents(bucket_name)
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"Bucket '{bucket_name}' deleted successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"Bucket '{bucket_name}' does not exist.")
        else:
            print(f"Error deleting bucket '{bucket_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while deleting bucket '{bucket_name}': {e}")
        raise

def delete_dynamodb_table(table_name):
    """
    Deletes a DynamoDB table.
    删除DynamoDB表。
    """
    print(f"Attempting to delete DynamoDB table: {table_name}")
    try:
        dynamodb_client.delete_table(TableName=table_name)
        print(f"Waiting for table '{table_name}' to be deleted...")
        waiter = dynamodb_client.get_waiter('table_not_exists')
        waiter.wait(TableName=table_name)
        print(f"Table '{table_name}' deleted successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Table '{table_name}' does not exist.")
        else:
            print(f"Error deleting table '{table_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while deleting table '{table_name}': {e}")
        raise

def remove_s3_trigger(bucket_name):
    """
    Removes the S3 trigger configuration from the bucket and associated Lambda permission.
    从S3桶中移除S3触发器配置及相关的Lambda权限。
    """
    print(f"Attempting to remove S3 trigger from bucket: {bucket_name}")
    try:
        # Get current notification configuration
        response = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
        
        # Filter out the Lambda function configuration for our function
        new_lambda_configs = []
        if 'LambdaFunctionConfigurations' in response:
            for config in response['LambdaFunctionConfigurations']:
                if LAMBDA_FUNCTION_NAME not in config.get('LambdaFunctionArn', ''):
                    new_lambda_configs.append(config)
        
        # Update the notification configuration
        s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                'LambdaFunctionConfigurations': new_lambda_configs
            }
        )
        print(f"S3 trigger removed from bucket '{bucket_name}'.")
        
        # Optionally, remove the Lambda permission as well
        try:
            # List all statements and find the one related to S3 trigger
            policy = json.loads(lambda_client.get_policy(FunctionName=LAMBDA_FUNCTION_NAME)['Policy'])
            for statement in policy['Statement']:
                if 'Condition' in statement and 'ArnLike' in statement['Condition']['AWS:SourceArn']:
                    if f"arn:aws:s3:::{bucket_name}" in statement['Condition']['ArnLike']['AWS:SourceArn']:
                        sid = statement['Sid']
                        print(f"Removing Lambda permission for S3 trigger with Sid: {sid}")
                        lambda_client.remove_permission(
                            FunctionName=LAMBDA_FUNCTION_NAME,
                            StatementId=sid
                        )
                        print(f"Removed Lambda permission for {bucket_name}.")
                        break
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                print("Lambda policy or S3 trigger permission not found.")
            else:
                print(f"Error removing Lambda permission: {e}")

    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchBucket':
            print(f"Bucket '{bucket_name}' does not exist, no trigger to remove.")
        else:
            print(f"Error removing S3 trigger from bucket '{bucket_name}': {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while removing S3 trigger: {e}")
        raise

def delete_lambda_function(function_name):
    """
    Deletes the AWS Lambda function.
    删除AWS Lambda函数。
    """
    print(f"Attempting to delete Lambda function: {function_name}")
    try:
        lambda_client.delete_function(FunctionName=function_name)
        print(f"Lambda function '{function_name}' deleted successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            print(f"Lambda function '{function_name}' does not exist.")
        else:
            print(f"Error deleting Lambda function: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while deleting Lambda function: {e}")
        raise

def delete_ecr_repository(repo_name):
    """
    Deletes an ECR repository.
    删除ECR仓库。
    """
    print(f"Attempting to delete ECR repository: {repo_name}")
    try:
        ecr_client.delete_repository(repositoryName=repo_name, force=True)
        print(f"ECR repository '{repo_name}' deleted successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'RepositoryNotFoundException':
            print(f"ECR repository '{repo_name}' does not exist.")
        else:
            print(f"Error deleting ECR repository: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while deleting ECR repository: {e}")
        raise

def delete_iam_role(role_name):
    """
    Deletes the IAM role and its attached policies.
    删除IAM角色及其附加策略。
    """
    print(f"Attempting to delete IAM role: {role_name}")
    try:
        # Detach policies first
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
        for policy in attached_policies:
            iam_client.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
            print(f"Detached policy: {policy['PolicyName']}")

        iam_client.delete_role(RoleName=role_name)
        print(f"IAM role '{role_name}' deleted successfully.")
    except ClientError as e:
        if e.response['Error']['Code'] == 'NoSuchEntity':
            print(f"IAM role '{role_name}' does not exist.")
        else:
            print(f"Error deleting IAM role: {e}")
            raise
    except Exception as e:
        print(f"An unexpected error occurred while deleting IAM role: {e}")
        raise

def main():
    """
    Main function to clean up all AWS resources.
    清理所有AWS资源的主函数。
    """
    print("--- Starting AWS Resource Cleanup ---")

    # Remove S3 Trigger
    try:
        remove_s3_trigger(INPUT_BUCKET_NAME)
    except Exception as e:
        print(f"Warning: Could not remove S3 trigger during cleanup: {e}")

    # Delete Lambda Function
    try:
        delete_lambda_function(LAMBDA_FUNCTION_NAME)
    except Exception as e:
        print(f"Warning: Could not delete Lambda function during cleanup: {e}")

    # Delete ECR Repository
    try:
        delete_ecr_repository(ECR_REPOSITORY_NAME)
    except Exception as e:
        print(f"Warning: Could not delete ECR repository during cleanup: {e}")

    # Delete IAM Role (wait for Lambda to be deleted first)
    # Give AWS some time for Lambda deletion to propagate before deleting role
    time.sleep(10)
    try:
        delete_iam_role(LAMBDA_ROLE_NAME)
    except Exception as e:
        print(f"Warning: Could not delete IAM role during cleanup: {e}")

    # Delete S3 Buckets
    try:
        delete_s3_bucket(INPUT_BUCKET_NAME)
    except Exception as e:
        print(f"Warning: Could not delete input S3 bucket during cleanup: {e}")
    try:
        delete_s3_bucket(OUTPUT_BUCKET_NAME)
    except Exception as e:
        print(f"Warning: Could not delete output S3 bucket during cleanup: {e}")

    # Delete DynamoDB Table
    try:
        delete_dynamodb_table(DYNAMODB_TABLE_NAME)
    except Exception as e:
        print(f"Warning: Could not delete DynamoDB table during cleanup: {e}")

    print("\n--- AWS Resource Cleanup Completed ---")

if __name__ == "__main__":
    main()
