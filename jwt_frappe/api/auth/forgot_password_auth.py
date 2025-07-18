import frappe
from frappe import _
from frappe.utils import now_datetime
from jwt_frappe.utils.constants import EMAIL_REGEX
from jwt_frappe.domain.auth_domain import send_reset_password_email 



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

