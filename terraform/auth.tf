resource "keycloak_authentication_flow" "browser_mfa" {
  realm_id    = keycloak_realm.nordivia.id
  alias       = "browser-mfa"
  description = "Navigateur : mot de passe pour tous, OTP en plus pour admin_it"
}

# 1. Session SSO existante
resource "keycloak_authentication_execution" "cookie" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_flow.browser_mfa.alias
  authenticator     = "auth-cookie"
  requirement       = "ALTERNATIVE"
}

# 2. Sinon : formulaires
resource "keycloak_authentication_subflow" "formulaires" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_flow.browser_mfa.alias
  alias             = "browser-mfa formulaires"
  provider_id       = "basic-flow"
  requirement       = "ALTERNATIVE"

  depends_on = [keycloak_authentication_execution.cookie]
}

resource "keycloak_authentication_execution" "password" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_subflow.formulaires.alias
  authenticator     = "auth-username-password-form"
  requirement       = "REQUIRED"
}

resource "keycloak_authentication_subflow" "otp_conditionnel" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_subflow.formulaires.alias
  alias             = "browser-mfa otp-conditionnel"
  provider_id       = "basic-flow"
  requirement       = "CONDITIONAL"

  depends_on = [keycloak_authentication_execution.password]
}

# 3. Condition : l'utilisateur a-t-il le rôle admin_it ?
resource "keycloak_authentication_execution" "condition_admin_it" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_subflow.otp_conditionnel.alias
  authenticator     = "conditional-user-role"
  requirement       = "REQUIRED"
}

resource "keycloak_authentication_execution_config" "condition_admin_it" {
  realm_id     = keycloak_realm.nordivia.id
  execution_id = keycloak_authentication_execution.condition_admin_it.id
  alias        = "role-admin-it"
  config = {
    condUserRole = keycloak_role.realm["admin_it"].name
    negate       = "false"
  }
}

# 4. Si oui : OTP
resource "keycloak_authentication_execution" "otp" {
  realm_id          = keycloak_realm.nordivia.id
  parent_flow_alias = keycloak_authentication_subflow.otp_conditionnel.alias
  authenticator     = "auth-otp-form"
  requirement       = "REQUIRED"

  depends_on = [keycloak_authentication_execution.condition_admin_it]
}

# 5. Ce flux devient le flux navigateur du realm
resource "keycloak_authentication_bindings" "nordivia" {
  realm_id     = keycloak_realm.nordivia.id
  browser_flow = keycloak_authentication_flow.browser_mfa.alias

  depends_on = [
    keycloak_authentication_execution.otp,
    keycloak_authentication_execution_config.condition_admin_it,
  ]
}
