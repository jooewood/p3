# workload.py

import os
import sys
import json
import time
import csv
from boto3 import client as boto3_client
from botocore.exceptions import ClientError

# Import configuration
from config import (
    INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, TEST_CASES_DIR,
    DYNAMODB_TABLE_NAME, AWS_REGION, STUDENT_DATA_FILE, CSV_HEADERS
)
# Import AWS credentials
from key import AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

# Set AWS credentials for boto3 clients
os.environ['AWS_ACCESS_KEY_ID'] = AWS_ACCESS_KEY_ID
os.environ['AWS_SECRET_ACCESS_KEY'] = AWS_SECRET_ACCESS_KEY

s3_client = boto3_client('s3', region_name=AWS_REGION)
dynamodb_client = boto3_client('dynamodb', region_name=AWS_REGION)

def upload_to_input_bucket_s3(path, name):
    """
    Uploads a file to the S3 input bucket.
    """
    print(f"Uploading {name} from {path} to input bucket '{INPUT_BUCKET_NAME}'...")
    try:
        s3_client.upload_file(os.path.join(path, name), INPUT_BUCKET_NAME, name)
        print(f"Uploaded {name} successfully.")
    except Exception as e:
        print(f"Error uploading {name} to S3: {e}")
        raise

def upload_files(test_case_name):
    """
    Uploads all video files from a specified test case directory to the input S3 bucket.
    """
    test_dir = os.path.join(TEST_CASES_DIR, test_case_name)
    if not os.path.isdir(test_dir):
        print(f"Error: Test case directory '{test_dir}' not found.")
        return

    print(f"\nUploading files for test case: {test_case_name}")
    for filename in os.listdir(test_dir):
        if filename.lower().endswith(".mp4"):
            upload_to_input_bucket_s3(test_dir, filename)
    print(f"Finished uploading files for test case: {test_case_name}")

def verify_output(test_case_name, mapping_file_path):
    """
    Verifies the output in the S3 output bucket against expected mappings loaded from a plain text file.
    """
    print(f"\nVerifying output for test case: {test_case_name}")

    # Load the expected mapping from the provided plain text file
    expected_mapping = {}
    try:
        with open(mapping_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    video_name, data = line.split(':', 1)
                    major, year = data.split(',', 1)
                    expected_mapping[video_name.strip()] = {"major": major.strip(), "year": year.strip()}
                except ValueError:
                    print(f"Warning: Skipping malformed line in mapping file: {line}")
        print(f"Loaded expected mapping from: {mapping_file_path}")
    except FileNotFoundError:
        print(f"Error: Mapping file '{mapping_file_path}' not found. Cannot verify output.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred while loading mapping file: {e}")
        return False

    # Get list of objects in the output bucket
    try:
        response = s3_client.list_objects_v2(Bucket=OUTPUT_BUCKET_NAME)
        output_files = [obj['Key'] for obj in response.get('Contents', [])]
    except ClientError as e:
        print(f"Error listing objects in output bucket: {e}")
        return False

    all_passed = True
    for output_file in output_files:
        video_name_without_ext = os.path.splitext(output_file)[0]
        original_video_name = video_name_without_ext + ".mp4" # Reconstruct original video name

        if original_video_name in expected_mapping:
            expected_major = expected_mapping[original_video_name]["major"]
            expected_year = expected_mapping[original_video_name]["year"]

            print(f"Verifying {output_file} (from {original_video_name})...")
            try:
                # Download and read the CSV content
                local_output_path = os.path.join("/tmp", output_file)
                s3_client.download_file(OUTPUT_BUCKET_NAME, output_file, local_output_path)

                with open(local_output_path, 'r', newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    header = next(reader) # Skip header
                    data_row = next(reader) # Get data row

                    # Assuming CSV format: name,major,year
                    actual_name = data_row[0]
                    actual_major = data_row[1]
                    actual_year = data_row[2]

                    # Load student_data to make verification more accurate
                    with open(STUDENT_DATA_FILE, 'r') as f:
                        all_students_data = json.load(f)
                    
                    found_student = None
                    for student in all_students_data:
                        if student['name'] == actual_name:
                            found_student = student
                            break
                    
                    if found_student:
                        if found_student['major'] == expected_major and found_student['year'] == expected_year:
                            print(f"  PASS: {output_file} - Recognized '{actual_name}' with correct major '{actual_major}' and year '{actual_year}'.")
                        else:
                            print(f"  FAIL: {output_file} - Recognized '{actual_name}' but expected major '{expected_major}' and year '{expected_year}', got '{actual_major}' and '{actual_year}'.")
                            all_passed = False
                    else:
                        print(f"  FAIL: {output_file} - Recognized name '{actual_name}' not found in student_data.json.")
                        all_passed = False

                os.remove(local_output_path) # Clean up local file

            except Exception as e:
                print(f"  ERROR: Could not read or verify {output_file}: {e}")
                all_passed = False
        else:
            print(f"  WARNING: Output file {output_file} does not have an explicit expected mapping.")

    if all_passed:
        print("\nAll verified outputs passed!")
    else:
        print("\nSome output verifications failed.")
    return all_passed

def main_workload_generator():
    """
    Main function to run the workload generator.
    """
    
    # Parse command-line arguments
    args = {}
    for arg in sys.argv[1:]:
        if '=' in arg:
            key, value = arg.split('=', 1)
            args[key] = value

    input_bucket_arg = args.get('input')
    output_bucket_arg = args.get('output')
    test_file_arg = args.get('test_file')
    mode_arg = args.get('mode', 'run') # 'run' is the only supported mode now

    if input_bucket_arg:
        global INPUT_BUCKET_NAME
        INPUT_BUCKET_NAME = input_bucket_arg
    if output_bucket_arg:
        global OUTPUT_BUCKET_NAME
        OUTPUT_BUCKET_NAME = output_bucket_arg

    print(f"Running workload in mode: {mode_arg}")
    print(f"Using Input Bucket: {INPUT_BUCKET_NAME}")
    print(f"Using Output Bucket: {OUTPUT_BUCKET_NAME}")
    print(f"Using DynamoDB Table: {DYNAMODB_TABLE_NAME}")

    # Define the hardcoded mapping file path
    # Assumes 'mapping.txt' is in the same directory as workload.py
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    mapping_file_path = os.path.join(current_script_dir, 'mapping.txt')

    if mode_arg == 'run':
        if not test_file_arg:
            print("Error: 'test_file' argument is required for 'run' mode (e.g., test_cases/test_case_2).")
            sys.exit(1)
        
        test_case_path_parts = test_file_arg.split('/')
        if len(test_case_path_parts) > 1 and test_case_path_parts[-2] == "test_cases":
            test_case_name = test_case_path_parts[-1] # e.g., "test_case_2"
        else:
            test_case_name = test_file_arg.split('/')[-1] # Fallback
        
        print(f"\n--- Running Workload for Test Case: {test_case_name} ---")

        upload_files(test_case_name)
        
        print("\n--- Waiting for Lambda processing to complete (approx. 60-120 seconds per video) ---")
        # A more robust solution would poll S3 for output files or use SQS/SNS for completion
        # For simplicity, we'll wait a fixed amount of time. Adjust as needed.
        time.sleep(10) # Wait for each video to process
        
        verify_output(test_case_name, mapping_file_path) # Pass hardcoded mapping file path
        print(f"\n--- Workload for Test Case: {test_case_name} Completed ---")
    else:
        print("Invalid mode. Only 'run' mode is supported.")
        print("Example for 'run': python workload.py mode=run test_file=test_cases/test_case_2")


if __name__ == "__main__":
    main_workload_generator()
