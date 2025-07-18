import frappe
from frappe import _
from jwt_frappe.utils.jwt_auth import generate_jwt_token
from jwt_frappe.utils.jwt_auth import decode_jwt_token
import frappe
from datetime import timedelta

from jwt_frappe.utils.constants import EMAIL_REGEX




# True
# Api 2
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
        if (
            JWT_Data.get("success") is False
            and JWT_Data.get("message") == "Token not found"
        ):
            frappe.response["http_status_code"] = 401
            return {
                "message": JWT_Data.get(
                    "message", "Unauthorized access. Token not found"
                )
            }
        if JWT_Data.get("success") is True:
            user = frappe.db.get_value("OAuth Bearer Token", token, "user")
            jwt_access_expiry_time = frappe.db.get_single_value(
                "JWT Settings", "jwt_access_expiry_time"
            )
            jwt_refresh_expiry_time = frappe.db.get_single_value(
                "JWT Settings", "jwt_refresh_expiry_time"
            )

            jwt_access_token = generate_jwt_token(
                user=user, expires_in=jwt_access_expiry_time
            )

            token_doc = frappe.get_doc("OAuth Bearer Token", token)
            if not token_doc:
                frappe.response["http_status_code"] = 401
                return {"message": "Unauthorized access. Token not found."}
            # Update the token document with new access token and expiry
            expiration_time = frappe.utils.now_datetime() + timedelta(
                seconds=jwt_access_expiry_time
            )
            frappe.db.set_value(
                "OAuth Bearer Token",
                token_doc.name,
                "jwt_access_token",
                jwt_access_token,
            )
            frappe.db.set_value(
                "OAuth Bearer Token", token_doc.name, "expiration_time", expiration_time
            )
            frappe.db.set_value(
                "OAuth Bearer Token",
                token_doc.name,
                "expires_in",
                jwt_access_expiry_time,
            )
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
                "success": False,
                "refresh_token_expired": True,
                "message": "Unauthorized access.Refresh Token has expired.",
            }
        if JWT_Data.get("message") == "Invalid token":
            frappe.response["http_status_code"] = 401
            return {
                "success": False,
                "message": "Unauthorized access. Invalid token.",
            }

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Refresh Token Error")
        frappe.throw(_("Failed to refresh token"))
