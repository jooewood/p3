# generate_encodings.py

import pickle
import json
import os
import numpy as np # Used for creating dummy face encodings

from config import ENCODING_FILE_NAME, STUDENT_DATA_FILE

def generate_dummy_encodings():
    """
    Generates a dummy encoding file for known faces.
    In a real application, this would involve loading actual images
    and generating real face encodings using face_recognition.
    """
    known_face_encodings = []
    known_face_names = []

    try:
        with open(STUDENT_DATA_FILE, 'r') as f:
            student_data = json.load(f)

        for student in student_data:
            name = student['name']
            # Create a dummy encoding (e.g., an array of zeros or random numbers)
            # In a real scenario, this would be:
            # image = face_recognition.load_image_file(f"path/to/images/{name}.jpg")
            # encoding = face_recognition.face_encodings(image)[0]
            dummy_encoding = np.zeros(128) # face_recognition uses 128-dimensional encodings
            known_face_encodings.append(dummy_encoding)
            known_face_names.append(name)

        data = {"encodings": known_face_encodings, "names": known_face_names}

        with open(ENCODING_FILE_NAME, "wb") as f:
            pickle.dump(data, f)
        print(f"Dummy encoding file '{ENCODING_FILE_NAME}' generated successfully.")

    except FileNotFoundError:
        print(f"Error: {STUDENT_DATA_FILE} not found. Please ensure it's in the same directory.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    generate_dummy_encodings()
