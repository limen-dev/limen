terraform {
  required_version = ">= 1.6"
  required_providers {
    datadog = {
      source  = "DataDog/datadog"
      version = ">= 4.0, < 5.0"
    }
  }
}
