# clear_content_only.py

import os
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, AWS_REGION
# Import AWS credentials
from key import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Set AWS credentials for boto3 clients
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY

s3_client = boto3_client('s3', region_name=AWS_REGION)

def clear_s3_bucket_contents(bucket_name):
    """
    Clears all objects from an S3 bucket.
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

def main():
    """
    Main function to clear contents of input and output S3 buckets.
    """
    print("--- Starting S3 Bucket Content Clear ---")
    clear_s3_bucket_contents(INPUT_BUCKET_NAME)
    clear_s3_bucket_contents(OUTPUT_BUCKET_NAME)
    print("--- S3 Bucket Content Clear Completed ---")

if __name__ == "__main__":
    main()
