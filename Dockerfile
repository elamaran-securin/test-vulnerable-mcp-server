# Intentionally vulnerable Dockerfile for ASPM scan testing
# Triggers: Trivy (container CVEs) + Checkov (dockerfile misconfigurations)

# CKV_DOCKER_7 / Trivy: Old base image with many known OS-level CVEs
FROM python:3.8

# CKV_DOCKER_8: Running as root (should use non-root USER)
USER root

WORKDIR /app

# CKV_DOCKER_9: Using ADD instead of COPY (ADD can unpack remote URLs)
ADD requirements.txt /app/requirements.txt
ADD . /app/

# Install dependencies (includes vulnerable packages)
RUN pip install --no-cache-dir -r requirements.txt

# CKV_DOCKER_7: Exposes SSH port — unnecessary attack surface
EXPOSE 22
EXPOSE 8000

# No HEALTHCHECK instruction — CKV_DOCKER_28
# No non-root user — CKV_DOCKER_8

# Hardcoded secret in ENV — also triggers Gitleaks
ENV SECRET_KEY="hardcoded_django_secret_key_12345"
ENV DATABASE_URL="postgresql://admin:password123@db:5432/prod"

CMD ["python", "server.py"]
