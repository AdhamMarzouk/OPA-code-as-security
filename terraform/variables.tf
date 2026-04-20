variable "aws_region" {
  description = "AWS region to target"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefix applied to all resource names"
  type        = string
  default     = "sec-as-code"
}
