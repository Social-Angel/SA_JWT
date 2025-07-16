import frappe
import jwt
from frappe import _
from frappe.utils import get_url
from frappe.auth import LoginManager
from jwt_frappe.utils.auth import get_bearer_token
from jwt_frappe.utils.jwt_auth import generate_jwt_token
from jwt_frappe.utils.jwt_auth import decode_jwt_token
from frappe.utils import cint
import requests, re
import frappe, random
from datetime import timedelta
from frappe.utils import get_url, random_string, now_datetime, add_to_date
from requests import RequestException
from socialangel.api.donor import get_details_of_donor_donations

# from frappe.utils.password import hash_password
from frappe.utils.password import passlibctx
from jwt_frappe.utils.constants import EMAIL_REGEX
from jwt_frappe.domain.auth_domain import generateOTP ,register_real_user,login_jwt_without_password ,get_user_summary ,get_user_summary, send_reset_password_email ,reset_password



# Api 12
@frappe.whitelist(allow_guest=True)
def forgot_password(email):
    """
    Handle forgot password functionality. Generates a reset password link if the user exists.
    """
    try:
        email = str(email).strip().lower()
        user = frappe.db.get_value("User", {"email": email}, "name")
        if not user:
            return {"status": "failed", "message": "User not found with this email"}

        from frappe.utils.data import sha256_hash

        key = frappe.generate_hash()
        hashed_key = sha256_hash(key)

        frappe.db.set_value("User", user, "reset_password_key", hashed_key)
        frappe.db.set_value(
            "User", user, "last_reset_password_key_generated_on", now_datetime()
        )

        reset_url = "/update-password?key=" + key
        base_url = frappe.db.get_single_value("SocialAngel Setting", "base_url")
        if not base_url:
            return {"status": "failed", "message": "Base URL not configured"}
        link = base_url + reset_url

        message = send_reset_password_email(email, link)
        if message.get("success"):
            frappe.local.response.http_status_code = 200
            return {"status": "success", "message": message.get("message")}
        else:
            frappe.response.http_status_code = 500
            frappe.log_error(
                message=f"Error sending reset password email: {message.get('message')}",
                title="Forgot Password Error",
            )
            return {"status": "failed", "message": message.get("message")}

    except Exception as e:
        frappe.log_error(
            message=f"Forgot Password Error: Email={email}, Error={str(e)}",
            title="Forgot Password Error",
        )
        frappe.response.http_status_code = 500
        return {
            "status": "failed",
            "message": "An error occurred while processing your request",
        }

