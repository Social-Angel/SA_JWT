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
# Api 3
@frappe.whitelist(allow_guest=True)
def create_website_user(email, full_name, password, uuid=None):
    """
    Creates a Website User with the given details if the email is unique and number_verified is not True.
    """
    try:
        # Email format validation
        email = str(email).strip().lower()
        if not re.match(EMAIL_REGEX, email):
            frappe.log_error(
                message=f"Invalid email format: {email.lower()}",
                title="User Creation Error",
            )
            frappe.response.http_status_code = 403
            return {
                "status": "error",
                "data": None,
                "message": _(
                    "Invalid email format. Please provide a valid email address."
                ),
            }
        # Check if the email is already registered
        existing_user = frappe.db.get_value(
            "Website User",
            filters={"email": email.lower()},
            fieldname=["name", "number_verified", "email", "mobile_no"],
        )
        if existing_user:
            name, number_verified, user_email, mobile_no = existing_user
            if number_verified:
                frappe.response.http_status_code = 200
                return {
                    "success": False,
                    "Action_Required": "Login",
                    "message": "Email is already registered and phone number is verified. Cannot create a new user.",
                }
            else:
                frappe.response.http_status_code = 200
                return {
                    "success": True,
                    "Action_Required": "verify_mobile",
                    "message": "Email is already registered. Please verify your mobile number.",
                    "user_doc": {
                        "name": existing_user[0],
                        "email": existing_user[2],
                        "mobile_no": existing_user[3],
                    },
                }
        else:
            # Create the Website User
            hashed_password = passlibctx.hash(password)

            user_doc = frappe.get_doc(
                {
                    "doctype": "Website User",
                    "email": email.lower(),
                    "full_name": full_name,
                    # "password": hashed_password,
                }
            )
            user_doc.append("roles", {"doctype": "Roles Table", "roles": "Website User"})
            user_doc.insert(ignore_permissions=True)

            auth_doc = frappe.db.sql(
                """
                    INSERT INTO `__Auth` (name, doctype,fieldname, password, encrypted)
                    VALUES (%s, %s, %s, %s, %s)
                """,
                (email.lower(), "Website User", "password", hashed_password, 0),
            )

            frappe.db.commit()
            if uuid:
                frappe.db.set_value(
                    "Website Visitor", {"uuid": uuid}, "website_user", email
                )
            frappe.response.http_status_code = 201
            return {
                "success": True,
                "message": "Website User created successfully.",
                "user_doc": {
                    "name": user_doc.name.lower(),
                    "email": user_doc.email,
                    "mobile_no": user_doc.mobile_no,
                },
            }
    except Exception as e:
        frappe.log_error(
            message=f"Error creating Website User: {e}\nTraceback: {frappe.get_traceback()}",
            title="Website User Creation Error",
        )
        frappe.response.http_status_code = 500
        return {"success": False, "message": "Failed to create Website User."}
