# handler.py

import os
import json
import pickle
import csv
import face_recognition
from boto3 import client as boto3_client

# Import configuration from config.py
from config import INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME, ENCODING_FILE_NAME, CSV_HEADERS, AWS_REGION

# Initialize S3 and DynamoDB clients
s3_client = boto3_client('s3', region_name=AWS_REGION)
dynamodb_client = boto3_client('dynamodb', region_name=AWS_REGION)

# Function to read the 'encoding' file
def open_encoding(filename):
    """
    Loads the face encodings and names from a pickle file.
    """
    try:
        with open(filename, "rb") as file:
            data = pickle.load(file)
        return data
    except FileNotFoundError:
        print(f"Error: Encoding file '{filename}' not found.")
        return None
    except Exception as e:
        print(f"Error loading encoding file: {e}")
        return None

def get_student_info_from_dynamodb(student_name):
    """
    Retrieves student academic information from DynamoDB.
    """
    print(f"Querying DynamoDB for student: {student_name}")
    try:
        response = dynamodb_client.get_item(
            TableName=DYNAMODB_TABLE_NAME,
            Key={
                'name': {'S': student_name}
            }
        )
        item = response.get('Item')
        if item:
            # Convert DynamoDB item format to a regular dictionary
            student_info = {
                'name': item.get('name', {}).get('S'),
                'major': item.get('major', {}).get('S'),
                'year': item.get('year', {}).get('S')
            }
            print(f"Found student info: {student_info}")
            return student_info
        else:
            print(f"Student '{student_name}' not found in DynamoDB.")
            return None
    except Exception as e:
        print(f"Error querying DynamoDB: {e}")
        return None

def face_recognition_handler(event, context):
    """
    AWS Lambda handler function for face recognition and student info retrieval.
    Triggered by S3 object creation event.
    """
    print("Lambda function invoked.")

    # 1. Get video file details from the S3 event
    try:
        # Extract bucket and key from the S3 event
        bucket_name = event['Records'][0]['s3']['bucket']['name']
        video_key = event['Records'][0]['s3']['object']['key']
        print(f"Processing video: {video_key} from bucket: {bucket_name}")
    except KeyError as e:
        print(f"Error extracting S3 event details: {e}")
        return {
            'statusCode': 400,
            'body': json.dumps('Invalid S3 event structure.')
        }

    # Define temporary paths for video and frames
    tmp_dir = "/tmp"
    video_file_path = os.path.join(tmp_dir, video_key.split('/')[-1]) # Use only filename
    output_image_pattern = os.path.join(tmp_dir, "image-%03d.jpeg")

    # Download video from S3
    try:
        print(f"Downloading {video_key} to {video_file_path}")
        s3_client.download_file(bucket_name, video_key, video_file_path)
        print("Video downloaded successfully.")
    except Exception as e:
        print(f"Error downloading video from S3: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error downloading video: {e}")
        }

    # 2. Extract frames using ffmpeg
    # Extract one frame per second
    ffmpeg_command = f"ffmpeg -i {video_file_path} -r 1 {output_image_pattern}"
    print(f"Executing ffmpeg command: {ffmpeg_command}")
    os.system(ffmpeg_command)
    print("FFmpeg frame extraction completed.")

    # Load known face encodings
    # The encoding file should be placed in the /tmp directory or directly in the image
    # For this setup, we assume it's copied into the function directory by Dockerfile
    # and accessible directly.
    # If it's in S3, you'd download it first:
    # s3_client.download_file(INPUT_BUCKET_NAME, ENCODING_FILE_NAME, os.path.join(tmp_dir, ENCODING_FILE_NAME))
    # known_faces_data = open_encoding(os.path.join(tmp_dir, ENCODING_FILE_NAME))
    
    # In this setup, we assume encoding file is packaged with the Lambda image
    known_faces_data = open_encoding(ENCODING_FILE_NAME)

    if not known_faces_data:
        print("Could not load known face encodings. Exiting.")
        return {
            'statusCode': 500,
            'body': json.dumps('Failed to load face encodings.')
        }

    known_face_encodings = known_faces_data["encodings"]
    known_face_names = known_faces_data["names"]
    print(f"Loaded {len(known_face_names)} known faces.")

    recognized_student_info = None
    # Iterate through extracted frames to find the first recognized face
    frame_number = 1
    while True:
        frame_path = os.path.join(tmp_dir, f"image-{frame_number:03d}.jpeg")
        if not os.path.exists(frame_path):
            break # No more frames

        print(f"Processing frame: {frame_path}")
        try:
            frame_image = face_recognition.load_image_file(frame_path)
            face_locations = face_recognition.face_locations(frame_image)
            face_encodings = face_recognition.face_encodings(frame_image, face_locations)

            if face_encodings:
                print(f"Found {len(face_encodings)} face(s) in frame {frame_number}.")
                # Only classify the first detected face as per requirement
                first_face_encoding = face_encodings[0]

                # Compare with known faces
                matches = face_recognition.compare_faces(known_face_encodings, first_face_encoding)
                name = "Unknown"

                # Find the best match
                if True in matches:
                    first_match_index = matches.index(True)
                    name = known_face_names[first_match_index]
                    print(f"Recognized face: {name}")

                    # 5. Search academic info in DynamoDB
                    recognized_student_info = get_student_info_from_dynamodb(name)
                    if recognized_student_info:
                        print(f"Successfully retrieved info for {name}.")
                        break # Found and processed the first recognized face, exit loop
                    else:
                        print(f"Could not retrieve info for recognized student {name}. Continuing to next frame if available.")
                else:
                    print("No known face matched in this frame.")
            else:
                print("No faces found in this frame.")

        except Exception as e:
            print(f"Error processing frame {frame_path}: {e}")
        finally:
            # Clean up the processed frame to save space
            if os.path.exists(frame_path):
                os.remove(frame_path)

        frame_number += 1

    # Clean up the downloaded video file
    if os.path.exists(video_file_path):
        os.remove(video_file_path)
        print(f"Cleaned up video file: {video_file_path}")

    if not recognized_student_info:
        print("No known student was recognized in the video.")
        return {
            'statusCode': 200,
            'body': json.dumps('No known student recognized or student data not found.')
        }

    # 6. Store student academic info in S3 output bucket
    video_name_without_ext = os.path.splitext(video_key.split('/')[-1])[0]
    output_file_name = f"{video_name_without_ext}.csv"
    output_file_path = os.path.join(tmp_dir, output_file_name)

    try:
        with open(output_file_path, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(CSV_HEADERS) # Write header
            writer.writerow([
                recognized_student_info.get('name', 'N/A'),
                recognized_student_info.get('major', 'N/A'),
                recognized_student_info.get('year', 'N/A')
            ])
        print(f"CSV file '{output_file_name}' created locally.")

        # Upload to S3 output bucket
        s3_client.upload_file(output_file_path, OUTPUT_BUCKET_NAME, output_file_name)
        print(f"CSV file '{output_file_name}' uploaded to S3 bucket '{OUTPUT_BUCKET_NAME}'.")

        # Clean up the generated CSV file
        os.remove(output_file_path)
        print(f"Cleaned up CSV file: {output_file_path}")

    except Exception as e:
        print(f"Error creating or uploading output CSV: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps(f"Error processing output: {e}")
        }

    return {
        'statusCode': 200,
        'body': json.dumps(f'Successfully processed {video_key}. Output saved to {output_file_name}.')
    }

if __name__ == "__main__":
    # Import INPUT_BUCKET_NAME from config.py for local testing context
    # In a real Lambda environment, environment variables are passed differently.
    from config import INPUT_BUCKET_NAME, OUTPUT_BUCKET_NAME, DYNAMODB_TABLE_NAME

    # Simulate an S3 event for a test video
    # Ensure 'test_0.mp4' exists in your configured INPUT_BUCKET_NAME on S3
    test_video_key = "test_0.mp4"
    simulated_event = {
        "Records": [
            {
                "s3": {
                    "bucket": {
                        "name": INPUT_BUCKET_NAME
                    },
                    "object": {
                        "key": test_video_key
                    }
                }
            }
        ]
    }

    print(f"--- Running handler locally with simulated event for {test_video_key} ---")
    # Call the main handler function
    face_recognition_handler(simulated_event, None)
    print("--- Local handler execution finished ---")

# --- End of local testing block ---