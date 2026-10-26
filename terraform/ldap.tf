resource "keycloak_ldap_user_federation" "openldap" {
  name     = "openldap"
  realm_id = keycloak_realm.nordivia.id
  enabled  = true

  # Connexion : nom du conteneur + port interne, car c'est Keycloak (dans Docker) qui se connecte
  connection_url  = "ldap://openldap:1389"
  bind_dn         = "cn=admin,dc=nordivia,dc=local"
  bind_credential = var.ldap_bind_password

  # Où et comment trouver les utilisateurs
  vendor                  = "OTHER"
  users_dn                = "ou=people,dc=nordivia,dc=local"
  search_scope            = "ONE_LEVEL"
  user_object_classes     = ["inetOrgPerson"]
  username_ldap_attribute = "uid"
  rdn_ldap_attribute      = "uid"
  uuid_ldap_attribute     = "entryUUID"

  # LDAP est la source de vérité : Keycloak ne l'écrit jamais
  edit_mode          = "READ_ONLY"
  import_enabled     = true
  sync_registrations = false
  trust_email        = true

  full_sync_period    = 86400 # synchro complète une fois par jour
  changed_sync_period = 60    # synchro des modifiés toutes les 60 s
}

# ou=groups → groupes Keycloak : l'organisation (qui est où)
resource "keycloak_ldap_group_mapper" "services" {
  name                    = "services"
  realm_id                = keycloak_realm.nordivia.id
  ldap_user_federation_id = keycloak_ldap_user_federation.openldap.id

  ldap_groups_dn                 = "ou=groups,dc=nordivia,dc=local"
  group_name_ldap_attribute      = "cn"
  group_object_classes           = ["groupOfNames"]
  membership_ldap_attribute      = "member"
  membership_attribute_type      = "DN"
  membership_user_ldap_attribute = "uid"
  memberof_ldap_attribute        = "memberOf"
  user_roles_retrieve_strategy   = "LOAD_GROUPS_BY_MEMBER_ATTRIBUTE"
  mode                           = "READ_ONLY"

  preserve_group_inheritance           = false
  drop_non_existing_groups_during_sync = true
}

# ou=roles → rôles du realm : les droits (qui peut faire quoi)
resource "keycloak_ldap_role_mapper" "roles" {
  name                    = "roles"
  realm_id                = keycloak_realm.nordivia.id
  ldap_user_federation_id = keycloak_ldap_user_federation.openldap.id

  ldap_roles_dn                  = "ou=roles,dc=nordivia,dc=local"
  role_name_ldap_attribute       = "cn"
  role_object_classes            = ["groupOfNames"]
  membership_ldap_attribute      = "member"
  membership_attribute_type      = "DN"
  membership_user_ldap_attribute = "uid"
  memberof_ldap_attribute        = "memberOf"
  user_roles_retrieve_strategy   = "LOAD_ROLES_BY_MEMBER_ATTRIBUTE"
  mode                           = "READ_ONLY"
  use_realm_roles_mapping        = true
}

# Attributs métier exposés dans Keycloak
locals {
  ldap_attributes = {
    matricule = "employeeNumber"
    poste     = "title"
    service   = "departmentNumber"
  }
}

resource "keycloak_ldap_user_attribute_mapper" "attributs" {
  for_each                = local.ldap_attributes
  name                    = each.key
  realm_id                = keycloak_realm.nordivia.id
  ldap_user_federation_id = keycloak_ldap_user_federation.openldap.id

  user_model_attribute        = each.key
  ldap_attribute              = each.value
  read_only                   = true
  always_read_value_from_ldap = true
}
