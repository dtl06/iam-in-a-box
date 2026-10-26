variable "admin_user" {
  type    = string
  default = "admin"
}

variable "admin_password" {
  type      = string
  sensitive = true
}

variable "ldap_bind_password" {
  type      = string
  sensitive = true
}
