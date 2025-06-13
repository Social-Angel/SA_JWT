# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import frappe
from frappe.utils import cint

__version__ = '1.0.2'

# def on_session_creation(login_manager):
#   from jwt_frappe.utils.auth import make_jwt
#   if frappe.form_dict.get('use_jwt') and cint(frappe.form_dict.get('use_jwt')):
#     frappe.local.response['token'] = make_jwt(
#         login_manager.user, frappe.flags.get('jwt_expire_on'))
#     frappe.flags.jwt_clear_cookies = True


def on_session_creation(login_manager):
  from .utils.auth import get_bearer_token
  if frappe.form_dict.get('use_jwt') and cint(frappe.form_dict.get('use_jwt')):
    
    # Get the JWT expiry time from JWT settings 
    jwt_access_expiry_time = frappe.db.get_single_value("JWT Settings", "jwt_access_expiry_time")
    jwt_refresh_expiry_time = frappe.db.get_single_value("JWT Settings", "jwt_refresh_expiry_time")
    print("jwt_access_expiry_time", jwt_access_expiry_time)
    print("jwt_refresh_expiry_time", jwt_refresh_expiry_time)
    jwt_response = get_bearer_token(
        user=login_manager.user, 
        jwt_access_expiry_time=jwt_access_expiry_time, 
        jwt_refresh_expiry_time=jwt_refresh_expiry_time
    )
    
    # Set the JWT access token and expiry time in the response
    frappe.local.response["jwt_access"] = {
      "jwt_access_token": jwt_response["token"]["access_token"],
      "jwt_access_expiry_time": jwt_access_expiry_time
    }

    # Set the JWT refresh token and expiry time in the response

    jwt_refresh_token = jwt_response["jwt_refresh_token"]
    frappe.local.response["jwt_refresh"] = {
        "jwt_refresh_token": jwt_refresh_token,
        "jwt_refresh_expiry_time": jwt_refresh_expiry_time
    }

    # Set user details in response

    frappe.local.response['user'] = {
      "full_name": frappe.db.get_value("User", login_manager.user, "full_name"),
      "email": frappe.db.get_value("User", login_manager.user, "email"),
      "phone": frappe.db.get_value("User", login_manager.user, "phone"),
      "user_image": frappe.db.get_value("User", login_manager.user, "user_image")
    }
    # frappe.local.response['jwt_user_role'] = frappe.get_roles(login_manager.user)

   
    frappe.flags.jwt_clear_cookies = True

@frappe.whitelist()
def get_logged_user():
  user = frappe.session.user