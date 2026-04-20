# terraform/main.tf
# ─────────────────────────────────────────────────────────────────────────────
# COMPLIANT RESOURCES
# All four resources below satisfy every OPA security policy defined in
# the policies/ directory. Used to demonstrate a passing pipeline run.
# ─────────────────────────────────────────────────────────────────────────────

# ─── Policy 1: S3 Encryption ──────────────────────────────────────────────────
# Compliant: server-side encryption is configured via standalone resource (AWS
# provider v5+ requires aws_s3_bucket_server_side_encryption_configuration).
resource "aws_s3_bucket" "compliant" {
  bucket = "${var.project_name}-compliant-bucket"

  tags = {
    Name        = "compliant-bucket"
    Environment = "demo"
    Compliance  = "pass"
  }
}

# NOTE: The resource name "compliant" deliberately matches aws_s3_bucket.compliant
# so the OPA policy can correlate them by Terraform resource name.
resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ─── Policy 4: S3 Public Access Block ────────────────────────────────────────
# Compliant: all four public-access block flags are set to true.
resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ─── Policy 2: No Public SSH ──────────────────────────────────────────────────
# Compliant: port 22 is restricted to a private CIDR, not 0.0.0.0/0.
resource "aws_security_group" "compliant" {
  name        = "${var.project_name}-compliant-sg"
  description = "Compliant: SSH restricted to private network only"

  ingress {
    description = "SSH from private network only"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # Private RFC-1918 range — not 0.0.0.0/0
  }

  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name       = "compliant-sg"
    Compliance = "pass"
  }
}

# ─── Policy 3: No Wildcard IAM Actions ───────────────────────────────────────
# Compliant: only specific, least-privilege S3 actions are allowed.
resource "aws_iam_policy" "compliant" {
  name        = "${var.project_name}-compliant-policy"
  description = "Compliant: specific actions only — no wildcards"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = "arn:aws:s3:::${var.project_name}-*"
      }
    ]
  })
}
