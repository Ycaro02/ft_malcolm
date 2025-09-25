#!/bin/bash

LISTEN_HOST="${1}"

# Enable access to the X server for local Docker containers
xhost +local:docker > /dev/null 2>&1

docker compose up -d --build

# Set up git user configuration
GIT_EMAIL=$(git config user.email)
GIT_NAME=$(git config user.name)
docker exec wire-shark-ft_malcolm git config --global user.email "${GIT_EMAIL}"
docker exec wire-shark-ft_malcolm git config --global user.name "${GIT_NAME}"

# Start zsh in the container
docker exec -it wire-shark-ft_malcolm zsh

