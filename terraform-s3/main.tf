terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# IAM User for Security Worker
resource "aws_iam_user" "security_worker" {
  name = "security-worker-service"
  
  tags = {
    Project = "SecurityWorker"
  }
}

# IAM Policy for S3 Access
resource "aws_iam_policy" "s3_backup_policy" {
  name        = "SecurityWorkerS3BackupPolicy"
  description = "Allow security worker to write to backup S3 bucket"
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.security_worker_backup.arn,
          "${aws_s3_bucket.security_worker_backup.arn}/*"
        ]
      }
    ]
  })
}

# Attach Policy to User
resource "aws_iam_user_policy_attachment" "attach_s3_policy" {
  user       = aws_iam_user.security_worker.name
  policy_arn = aws_iam_policy.s3_backup_policy.arn
}

# Create Access Key for User
resource "aws_iam_access_key" "security_worker_key" {
  user = aws_iam_user.security_worker.name
}

# S3 Bucket
resource "aws_s3_bucket" "security_worker_backup" {
  bucket = "security-worker-backup-${random_id.bucket_suffix.hex}"
  
  tags = {
    Name    = "Security Worker Backup"
    Project = "SecurityWorker"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# Outputs
output "bucket_name" {
  value = aws_s3_bucket.security_worker_backup.id
}

output "iam_user_name" {
  value = aws_iam_user.security_worker.name
}

output "access_key_id" {
  value     = aws_iam_access_key.security_worker_key.id
  sensitive = true
}

output "secret_access_key" {
  value     = aws_iam_access_key.security_worker_key.secret
  sensitive = true
}