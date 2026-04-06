# Intentionally misconfigured Terraform for ASPM IAC (Checkov) scan testing
# Triggers: CKV_AWS_18, CKV_AWS_19, CKV_AWS_20, CKV_AWS_24, CKV_AWS_25, CKV_AWS_57, CKV2_AWS_6

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# ── S3 BUCKET — multiple misconfigs ───────────────────────────────────────────
# CKV_AWS_20: S3 bucket has public ACL
# CKV_AWS_18: S3 bucket has no access logging
# CKV_AWS_19: S3 bucket has no server-side encryption
# CKV_AWS_52: S3 bucket has no MFA delete enabled
resource "aws_s3_bucket" "public_data" {
  bucket = "my-public-insecure-bucket"
  acl    = "public-read"

  tags = {
    Name = "insecure-bucket"
  }
}

# CKV2_AWS_6: S3 bucket does not block public access
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ── SECURITY GROUP — wide-open ingress ────────────────────────────────────────
# CKV_AWS_24: Security group allows unrestricted ingress on all ports
# CKV_AWS_25: Security group allows unrestricted egress
resource "aws_security_group" "open_sg" {
  name        = "open-all-ports"
  description = "Allows all inbound and outbound traffic"

  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description      = "All traffic IPv6"
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ── EC2 INSTANCE — misconfigured ──────────────────────────────────────────────
# CKV_AWS_135: EC2 without EBS encryption
# CKV2_AWS_41: EC2 no IAM role attached
resource "aws_instance" "insecure_vm" {
  ami                    = "ami-0c55b159cbfafe1f0"
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.open_sg.id]

  # CKV_AWS_8: Detailed monitoring disabled
  monitoring = false

  # CKV_AWS_79: Metadata service v1 enabled (SSRF risk)
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"
  }

  tags = {
    Name = "insecure-instance"
  }
}

# ── IAM — over-privileged role ────────────────────────────────────────────────
# CKV_AWS_49: IAM policy with wildcard (*) resource
resource "aws_iam_policy" "admin_policy" {
  name = "AdminAllAccess"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}
