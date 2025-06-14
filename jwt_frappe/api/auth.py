import frappe
import jwt
from frappe import _
from frappe.utils import get_url
from frappe.auth import LoginManager
from jwt_frappe.utils.auth import get_bearer_token
from jwt_frappe.utils.jwt_auth import generate_jwt_token
from jwt_frappe.utils.jwt_auth import decode_jwt_token


@frappe.whitelist(allow_guest=True)
def refresh_token():
    """
    Refresh the JWT token using the refresh token
    :param refresh_token: The refresh token to use for refreshing the JWT token
    """
    try:
        token = frappe.form_dict.get("token")
        # token = (frappe.request.headers.get("Authorization").replace("Bearer ", "").strip())

        if not token:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token is missing."}
            
        JWT_Data = decode_jwt_token(token, token_type="refresh_token")
        print("JWT_Data", JWT_Data)
        if JWT_Data.get("success") is False and JWT_Data.get("message") == "Token not found":
            frappe.response["http_status_code"] = 401
            return {"message": JWT_Data.get("message", "Unauthorized access. Token not found")}
        if JWT_Data.get("success") is True:
            jwt_access_expiry_time = frappe.db.get_single_value("JWT Settings", "jwt_access_expiry_time")
            jwt_refresh_expiry_time = frappe.db.get_single_value("JWT Settings", "jwt_refresh_expiry_time")

            jwt_access_token = generate_jwt_token(user="user", expires_in=jwt_access_expiry_time)    
            
            token_doc = frappe.get_doc("OAuth Bearer Token", token)
            if not token_doc:
                frappe.response["http_status_code"] = 401
                return {"message": "Unauthorized access. Token not found."}
            # Update the token document with new access token and expiry
            frappe.db.set_value("OAuth Bearer Token", token_doc.name, "jwt_access_token", jwt_access_token)
            frappe.db.set_value("OAuth Bearer Token", token_doc.name, "jwt_access_token", jwt_access_token)

            frappe.db.commit() 
            # token_doc.add_comment("Comment", text="Access token refreshed")


            # Prepare response
            response = {
                "jwt_access_token": token_doc.name,
                "jwt_refresh_token": token_doc.jwt_refresh_token,
                "jwt_refresh_expiry_time": jwt_refresh_expiry_time,
            }

            return response

        if JWT_Data.get("message") == "Token has expired":
            frappe.response["http_status_code"] = 401
            return {
                "message": "Unauthorized access.Refresh Token has expired.",
            }
        if JWT_Data.get("message") == "Invalid token":
            frappe.response["http_status_code"] = 401
            return {
                "message": "Unauthorized access. Invalid token.",
            }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Refresh Token Error")
        frappe.throw(_("Failed to refresh token"))


@frappe.whitelist(allow_guest=True)
def logout_jwt():
    """
    Logout the user by clearing the JWT token
    """
    try:
        token = (frappe.request.headers.get("Authorization").replace("Bearer ", "").strip())
        if not token:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token is missing."}
        print("tokentoken",token)
        # Clear the token from the database
        token_doc = frappe.get_doc("OAuth Bearer Token", token)
        if not token_doc:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token not found."}
        
        token_doc.delete()
        frappe.db.commit()

        return {"message": "Logged out successfully"}

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Logout Error")
        frappe.throw(_("Failed to logout"))