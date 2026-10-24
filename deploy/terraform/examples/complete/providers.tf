provider "aws" {
  region = var.region
  default_tags {
    tags = { Project = "limen", Environment = var.name }
  }
}
