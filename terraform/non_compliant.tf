# ─────────────────────────────────────────────────────────────────────────────
# NON-COMPLIANT RESOURCES — INTENTIONALLY INSECURE
#
# These resources are written to VIOLATE each OPA security policy.
# They are used to demonstrate a failing pipeline run.
# ─────────────────────────────────────────────────────────────────────────────

# ─── VIOLATION 1: S3 bucket with NO encryption ───────────────────────────────
# Policy violated: s3_encryption.rego
# Reason: Missing server_side_encryption_configuration block entirely.
resource "aws_s3_bucket" "no_encryption" {
  bucket = "${var.project_name}-no-encryption-bucket"

  # INTENTIONALLY MISSING: server_side_encryption_configuration block
  # A compliant bucket would have:
  #   server_side_encryption_configuration {
  #     rule {
  #       apply_server_side_encryption_by_default {
  #         sse_algorithm = "AES256"
  #       }
  #     }
  #   }

  tags = {
    Name       = "non-compliant-no-encryption"
    Compliance = "FAIL-encryption"
  }
}

# ─── VIOLATION 2: S3 public access block with all flags FALSE ────────────────
# Policy violated: s3_public_access.rego
# Reason: All four flags are false — S3 bucket is publicly accessible.
resource "aws_s3_bucket_public_access_block" "not_blocked" {
  bucket = aws_s3_bucket.no_encryption.id

  block_public_acls       = false # VIOLATION — must be true
  block_public_policy     = false # VIOLATION — must be true
  ignore_public_acls      = false # VIOLATION — must be true
  restrict_public_buckets = false # VIOLATION — must be true
}

# ─── VIOLATION 3: Security group with SSH open to 0.0.0.0/0 ──────────────────
# Policy violated: ssh_access.rego
# Reason: Port 22 is open to any IP address on the internet.
resource "aws_security_group" "public_ssh" {
  name        = "${var.project_name}-public-ssh-sg"
  description = "Non-compliant: SSH open to the entire internet"

  ingress {
    description = "SSH open to the entire internet - VIOLATION"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # VIOLATION — exposes SSH to the world
  }

  tags = {
    Name       = "non-compliant-sg"
    Compliance = "FAIL-ssh"
  }
}

# ─── VIOLATION 4: IAM policy with wildcard (*) action ────────────────────────
# Policy violated: iam_wildcard.rego
# Reason: Action = "*" grants all AWS permissions — violates least privilege.
resource "aws_iam_policy" "wildcard" {
  name        = "${var.project_name}-wildcard-policy"
  description = "Non-compliant: wildcard action grants all permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*" # VIOLATION — least-privilege requires specific actions
        Resource = "*"
      }
    ]
  })
}
