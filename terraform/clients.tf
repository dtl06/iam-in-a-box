resource "keycloak_openid_client" "portail_rh" {
  realm_id  = keycloak_realm.nordivia.id
  client_id = "portail-rh"
  name      = "Portail RH"
  enabled   = true

  # Application côté serveur : elle peut garder un secret
  access_type = "CONFIDENTIAL"

  # Uniquement le flux « authorization code » + PKCE
  standard_flow_enabled        = true
  implicit_flow_enabled        = false
  direct_access_grants_enabled = false
  service_accounts_enabled     = false
  pkce_code_challenge_method   = "S256"

  root_url                        = "http://localhost:5000"
  valid_redirect_uris             = ["http://localhost:5000/callback"]
  valid_post_logout_redirect_uris = ["http://localhost:5000/"]
}

# Attributs LDAP (matricule, poste, service) → claims du jeton
resource "keycloak_openid_user_attribute_protocol_mapper" "attributs" {
  for_each  = local.ldap_attributes
  realm_id  = keycloak_realm.nordivia.id
  client_id = keycloak_openid_client.portail_rh.id
  name      = each.key

  user_attribute   = each.key
  claim_name       = each.key
  claim_value_type = "String"

  add_to_id_token     = true
  add_to_access_token = true
  add_to_userinfo     = true
}

# Rôles du realm aussi dans l'ID token (par défaut, ils ne sont que dans l'access token)
resource "keycloak_openid_user_realm_role_protocol_mapper" "roles" {
  realm_id  = keycloak_realm.nordivia.id
  client_id = keycloak_openid_client.portail_rh.id
  name      = "realm-roles-id-token"

  claim_name  = "realm_access.roles"
  multivalued = true

  add_to_id_token     = true
  add_to_access_token = false # déjà présent via le scope « roles » par défaut
  add_to_userinfo     = true
}

output "portail_rh_client_secret" {
  value     = keycloak_openid_client.portail_rh.client_secret
  sensitive = true
}
