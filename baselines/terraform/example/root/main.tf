module "app" {
  source = "../modules/app"

  bucket_name = var.bucket_name
  tags = {
    Environment = "example"
  }
}
