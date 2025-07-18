import jwt
import frappe
import datetime
from frappe import _




@frappe.whitelist(allow_guest=True)
def generate_jwt_token(user, expires_in=60):

    jwt_secret_key = frappe.local.conf.jwt_secret_key
    if not jwt_secret_key:
        frappe.log_error(message="JWT Secret Key is not configured. Add jwt_secret_key in site config.json", title="JWT Configuration Error")
        raise frappe.ValidationError(_("JWT Secret Key is not configured."))
    
    # Get User details for the JWT payload
    if not frappe.db.exists("User", user):
        raise frappe.ValidationError(_("Invalid User"))

    user_doc = frappe.get_doc("User", user)
    if not user_doc.enabled:
        raise frappe.ValidationError(_("User is disabled"))
    

    payload = {
        "user": user_doc.name,
        "email": user_doc.email,
        "full_name": getattr(user_doc, "full_name", None),
        "user_type": getattr(user_doc, "user_type", None),
        "roles": [role.role for role in user_doc.get("roles")] if hasattr(user_doc, "roles") else None,
        "is_system_user": getattr(user_doc, "is_system_user", None),
        "is_active": getattr(user_doc, "enabled", None),
        "is_guest": getattr(user_doc, "is_guest", None),
        "is_new_user": getattr(user_doc, "is_new_user", None),
        "language": getattr(user_doc, "language", None),
        "time_zone": getattr(user_doc, "time_zone", None),
        "ip_address": frappe.local.request_ip or None,
        "device": frappe.local.request.headers.get("User-Agent", None),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + datetime.timedelta(seconds=expires_in),
        "custom_data": {
            "flag": "jwt_frappe1",
            "extra": "your_custom_info"
        }
    }

    token = jwt.encode(payload, jwt_secret_key, algorithm="HS256")
    return token


@frappe.whitelist(allow_guest=True)
def decode_jwt_token(token, token_type , secret_key="your_secret_here"):
    try:
        jwt_secret_key = frappe.local.conf.jwt_secret_key
        if not jwt_secret_key:
            frappe.log_error(message="JWT Secret Key is not configured. Add jwt_secret_key in site config.json", title="JWT Configuration Error")
            raise frappe.ValidationError(_("JWT Secret Key is not configured."))

        if not token:
            return {"success": False, "message": "Token is required"}
        
        try:
            access_token = frappe.get_doc("OAuth Bearer Token", token)
        except frappe.DoesNotExistError:
            return {"success": False, "message": "Token not found"}
        if token_type == "refresh_token":
            decoded = jwt.decode(access_token.jwt_refresh_token, jwt_secret_key, algorithms=["HS256"])
        elif token_type == "access_token":
            decoded = jwt.decode(access_token.jwt_access_token, jwt_secret_key, algorithms=["HS256"])
        else:
            return {
                {"success": False, "message": "Token Type Is Wrong"}
            }
        return {
            "success": True,
            "data": decoded
        }
    except jwt.ExpiredSignatureError:
        return {"success": False, "message": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"success": False, "message": "Invalid token"}