# Dockerfile

# Define global args
ARG FUNCTION_DIR="/home/app/"
ARG RUNTIME_VERSION="3.10"

# Stage 1 - bundle base image + runtime
FROM python:${RUNTIME_VERSION}-slim-buster AS python-base

# Install necessary system dependencies for face_recognition and ffmpeg
# - cmake: required for face_recognition build process
# - libgl1-mesa-glx: common dependency for graphical libraries, sometimes needed by opencv-python-headless
# - ffmpeg: multimedia framework
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake \
        libgl1 \
        ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN python${RUNTIME_VERSION} -m pip install --upgrade pip

# Stage 2 - build function and dependencies
FROM python-base AS build-image
# Include global args in this stage of the build
ARG FUNCTION_DIR
# Create function directory
RUN mkdir -p ${FUNCTION_DIR}

# Install Lambda Runtime Interface Client for Python
# This is essential for the Lambda custom runtime
RUN python${RUNTIME_VERSION} -m pip install awslambdaric --target ${FUNCTION_DIR}

# Stage 3 - final runtime image
FROM python-base
# Include global arg in this stage of the build
ARG FUNCTION_DIR
# Set working directory to function root directory
WORKDIR ${FUNCTION_DIR}

# Copy in the built dependencies from the build-image stage
COPY --from=build-image ${FUNCTION_DIR} ${FUNCTION_DIR}

# (Optional) Add Lambda Runtime Interface Emulator and use a script in the ENTRYPOINT for simpler local runs
# This allows local testing of the Lambda function
ADD https://github.com/aws/aws-lambda-runtime-interface-emulator/releases/latest/download/aws-lambda-rie /usr/bin/aws-lambda-rie
RUN chmod 755 /usr/bin/aws-lambda-rie

# Copy requirements.txt and install Python dependencies
COPY requirements.txt ${FUNCTION_DIR}
RUN python${RUNTIME_VERSION} -m pip install -r requirements.txt --target ${FUNCTION_DIR}

# Copy entrypoint script
COPY entry.sh /
RUN chmod 777 /entry.sh

# Copy handler function and the encoding file
COPY handler.py ${FUNCTION_DIR}
COPY encoding ${FUNCTION_DIR} # Copy the generated encoding file

# Set the CMD to your handler (could also be done as a parameter override outside of the Dockerfile)
ENTRYPOINT [ "/entry.sh" ]
CMD [ "handler.face_recognition_handler" ]
