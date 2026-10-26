resource "keycloak_realm" "nordivia" {
  realm        = "nordivia"
  enabled      = true
  display_name = "Nordivia"

  # 12 caractères min, 1 majuscule, 1 chiffre, 1 spécial, pas de réutilisation des 3 derniers
  password_policy = "length(12) and upperCase(1) and digits(1) and specialChars(1) and passwordHistory(3)"

  # Un jeton volé ne vaut que 5 minutes
  access_token_lifespan = "5m"

  security_defenses {
    brute_force_detection {
      permanent_lockout                = false
      max_login_failures               = 5     # blocage après 5 échecs
      wait_increment_seconds           = 60    # 1 min de blocage, qui augmente à chaque série
      max_failure_wait_seconds         = 900   # plafonné à 15 min
      failure_reset_time_seconds       = 43200 # compteur remis à zéro après 12 h
      quick_login_check_milli_seconds  = 1000
      minimum_quick_login_wait_seconds = 60
    }
  }
}

resource "keycloak_realm_events" "nordivia" {
  realm_id = keycloak_realm.nordivia.id

  events_enabled      = true
  events_expiration   = 2592000 # 30 jours, en secondes
  enabled_event_types = ["LOGIN", "LOGIN_ERROR", "LOGOUT"]
  events_listeners    = ["jboss-logging"]

  admin_events_enabled         = true
  admin_events_details_enabled = true
}

locals {
  realm_roles = {
    employe         = "Accès de base de tout salarié"
    rh_gestion      = "Gestion des dossiers du personnel"
    paie_validation = "Validation des paies"
    admin_it        = "Administration du SI (MFA obligatoire)"
  }
}

resource "keycloak_role" "realm" {
  for_each    = local.realm_roles
  realm_id    = keycloak_realm.nordivia.id
  name        = each.key
  description = each.value
}
