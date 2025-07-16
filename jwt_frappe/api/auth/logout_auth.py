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



# True
@frappe.whitelist(allow_guest=True)
def logout_jwt():
    """
    Logout the user by clearing the JWT token
    """
    try:
        token = (
            frappe.request.headers.get("Authorization").replace("Bearer ", "").strip()
        )
        if not token:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token is missing."}
        # Clear the token from the database
        token_doc = frappe.get_doc("OAuth Bearer Token", token)
        if not token_doc:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token not found."}

        token_doc.delete(ignore_permissions=True)
        frappe.db.commit()

        return {"message": "Logged out successfully"}

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Logout Error")
        frappe.throw(_("Failed to logout"))
