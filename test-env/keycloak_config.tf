
resource "keycloak_realm" "test-realm" {
  realm = "test"
}

resource "keycloak_openid_client" "test-client" {
  access_type   = "CONFIDENTIAL"
  client_id     = "test"
  realm_id      = keycloak_realm.test-realm.id
  client_secret = "jRSpi3urLgbKOFyOycgrlRWsvFEFuMSG"
  valid_redirect_uris = ["http://localhost:3000/auth/callback"]
  standard_flow_enabled = true
}

resource "keycloak_user" "test-user" {
  realm_id       = keycloak_realm.test-realm.id
  username       = "test"
  first_name     = "Max"
  last_name      = "Mustermann"
  email          = "max@test.local"
  email_verified = true

  initial_password {
    value = "test"
    temporary = false
  }
}