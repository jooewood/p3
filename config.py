# config.py

# AWS Region
AWS_REGION = 'ap-northeast-2' # You can change this to your desired region

# S3 Bucket Names
INPUT_BUCKET_NAME = 'zhoudixin-input-bucket-546proj2' # IMPORTANT: Replace with a unique bucket name
OUTPUT_BUCKET_NAME = 'zhoudixin-output-bucket-546proj2output' # IMPORTANT: Replace with a unique bucket name

# DynamoDB Table Name
DYNAMODB_TABLE_NAME = 'StudentAcademicInfo'

# Lambda Function Configuration
LAMBDA_FUNCTION_NAME = 'FaceRecognitionClassroomAssistant'
LAMBDA_HANDLER = 'handler.face_recognition_handler'
LAMBDA_TIMEOUT = 300 # seconds
LAMBDA_MEMORY = 3008 # MB (e.g., 3008 MB for 2 vCPU equivalent)
ECR_REPOSITORY_NAME = 'face-recognition-lambda-repo'
LAMBDA_ROLE_NAME = 'LambdaFaceRecognitionRole'

# Local paths
TEST_CASES_DIR = "test_cases/"
ENCODING_FILE_NAME = "encoding" # Name of the face encoding file
STUDENT_DATA_FILE = "student_data.json"

# Output CSV headers
CSV_HEADERS = ["name", "major", "year"]

# IMPORTANT: Ensure your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set in key.py
# and that your AWS user has the necessary permissions for S3, Lambda, DynamoDB, ECR, and IAM.
