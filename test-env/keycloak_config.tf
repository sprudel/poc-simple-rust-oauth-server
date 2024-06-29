
resource "keycloak_realm" "test-realm" {
  realm = "test"
}

resource "keycloak_openid_client" "test-client" {
  access_type   = "CONFIDENTIAL"
  client_id     = "demo"
  realm_id      = keycloak_realm.test-realm.id
  client_secret = "test"
}

resource "keycloak_user" "test-user" {
  realm_id       = keycloak_realm.test-realm.id
  username       = "max"
  first_name     = "Max"
  last_name      = "Mustermann"
  email          = "max@test.local"
  email_verified = true
}