FROM python:3.10-slim

WORKDIR /app

# Install system dependencies needed for compiling tree-sitter
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements and setup file first to leverage Docker cache
COPY pyproject.toml .

# Copy the source code
COPY aegis_sast/ aegis_sast/
COPY rules/ rules/
COPY README.md .

# Install the application
RUN pip install --no-cache-dir .

# Create a directory for the target project to be mounted
RUN mkdir /target

# Set the entrypoint to the CLI
ENTRYPOINT ["aegis-sast", "scan"]

# Default command if no arguments are provided to the entrypoint
CMD ["--help"]
