terraform {
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "~> 5.10"
    }
  }
}

provider "keycloak" {
  client_id = "admin-cli"
  username  = var.admin_user
  password  = var.admin_password
  realm     = "master"
  url       = "http://localhost:8080"
}
