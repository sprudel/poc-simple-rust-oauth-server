provider "keycloak" {
  client_id = "admin-cli"
  username  = "admin"
  password  = "admin"
  url       = "http://keycloak:8080"
}

terraform {
  required_providers {
    keycloak = {
      source  = "mrparkers/keycloak",
      version = "4.4.0"
    }
  }
}