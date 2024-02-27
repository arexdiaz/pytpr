#!/bin/bash

# Define variables
IMAGE_NAME="ubuntu_compile"
CONTAINER_NAME="pytpr_compile"
COMPILED_FILE="payload"

# Build the Docker image
docker build --network host -t $IMAGE_NAME .

# Run the Docker container in the background
docker run -d --name $CONTAINER_NAME $IMAGE_NAME

# Copy the compiled file from the Docker container to the host
docker cp $CONTAINER_NAME:/app/payloads/$COMPILED_FILE ./payloads/

# Stop and remove the Docker container
docker stop $CONTAINER_NAME
docker rm $CONTAINER_NAME