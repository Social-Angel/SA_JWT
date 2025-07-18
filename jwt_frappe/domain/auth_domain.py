import frappe
from frappe import _
from jwt_frappe.utils.auth import get_bearer_token
import re
import frappe, random
from jwt_frappe.utils.constants import EMAIL_REGEX



def generate_otp(digit):
    """
    Generates a random OTP of the specified digit length.
    """
    try:
        digits = "0123456789"
        return "".join(random.choice(digits) for _ in range(digit))
    except Exception as e:
        frappe.response.http_status_code = 500
        frappe.log_error(
            message=f"Error generating OTP: {e}", title="OTP Generation Error"
        )
        return ""


def register_real_user(full_name, email, phone_number, roles=None):
    """
    Registers a new user. If the user already exists, appropriate error messages are returned.
    """
    try:
        email = str(email).strip().lower()
        if not email:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Email is required"}

        if not phone_number:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Phone number is required"}
        if not re.match(r"^\+?[0-9]{10,15}$", phone_number):
            frappe.response["http_status_code"] = 400
            return {
                "success": False,
                "message": "Invalid phone number format. It should be 10 to 15 digits long.",
            }
        if not re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email):
            frappe.response["http_status_code"] = 400
            return {
                "success": False,
                "message": "Invalid email format. Please provide a valid email address.",
            }

        user = frappe.db.get_value("User", email, fieldname=["name"])
        if user:
            frappe.response["http_status_code"] = 409
            return {
                "success": False,
                "message": f"User with email {email} already exists. Please use a different email or login.",
            }

        users_count_with_same_phone = frappe.db.count("User", {"phone": phone_number})
        if users_count_with_same_phone > 5:
            frappe.response["http_status_code"] = 409
            return {
                "success": False,
                "message": "This phone number exceeds the limit of users registered with it.",
            }

        full_name = full_name.split()
        first_name_part = full_name[0]
        last_name_part = " ".join(full_name[1:]) if len(full_name) > 1 else ""
        user_doc = frappe.get_doc(
            {
                "doctype": "User",
                "email": email,
                "first_name": first_name_part,
                "last_name": last_name_part,
                "phone": phone_number,
                "send_welcome_email": 0,
                # "new_password": password,
                "number_verified": 1,
            }
        )
        if roles:
            for role in roles:
                user_doc.append("roles", {"role": role["roles"]})

        try:
            user_doc.insert(ignore_permissions=True)
            frappe.db.commit()

            frappe.response["http_status_code"] = 201
            return {
                "success": True,
                "message": "User created successfully",
                "user_doc": {
                    "name": user_doc.name,
                    "email": user_doc.email,
                    "phone": user_doc.phone,
                },
            }
        except frappe.ValidationError as e:
            if "Failed to decrypt key" in str(e):
                frappe.log_error(
                    message=f"Encryption error while sending welcome email: {e} {frappe.get_traceback()}",
                    title="Email Encryption Issue",
                )
                frappe.response["http_status_code"] = 206
                return {
                    "success": True,
                    "message": f"User created successfully, but failed to send welcome email: {e}",
                }
            else:
                frappe.log_error(
                    message=f"Validation error during user creation: {e} {frappe.get_traceback()}",
                    title="User Registration Error",
                )
                frappe.response["http_status_code"] = 400
                return {"success": False, "message": f"Validation error: {e}"}

    except frappe.ValidationError as e:
        frappe.log_error(
            message=f"Validation error during registration: {e} {frappe.get_traceback()}",
            title="User Registration Error",
        )
        frappe.response["http_status_code"] = 400
        return {"success": False, "message": f"Validation error: {e}"}

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error during registration: First Name: {full_name}, Email: {email}, Phone: {phone_number}. Error: {e}. {frappe.get_traceback()}",
            title="User Registration Error",
        )
        frappe.response["http_status_code"] = 500
        return {"success": False, "message": f"Error: {e}"}


def login_jwt_without_password(usr, expires_in=60, expire_on=None, device=None):
    """
    Login the usr and return the JWT token without password
    """
    try:
        frappe.flags.skip_on_session_creation = True

        # Check if the user are provided
        if not usr:
            frappe.response["http_status_code"] = 400
            return {"Success": False, "message": _("Username is required")}

        # Check if the user exists
        if not frappe.db.exists("User", usr):
            frappe.response["http_status_code"] = 400
            return {"Success": False, "message": _("Invalid User")}

        # Generate JWT tokens
        jwt_access_expiry_time = frappe.db.get_single_value(
            "JWT Settings", "jwt_access_expiry_time"
        )
        jwt_refresh_expiry_time = frappe.db.get_single_value(
            "JWT Settings", "jwt_refresh_expiry_time"
        )
        jwt_response = get_bearer_token(
            user=usr,
            jwt_access_expiry_time=jwt_access_expiry_time,
            jwt_refresh_expiry_time=jwt_refresh_expiry_time,
        )

        # Prepare response
        response = {
            "jwt_access": {
                "jwt_access_token": jwt_response["token"]["access_token"],
                "jwt_access_expiry_time": jwt_access_expiry_time,
            },
            "jwt_refresh": {
                "jwt_refresh_token": jwt_response["jwt_refresh_token"],
                "jwt_refresh_expiry_time": jwt_refresh_expiry_time,
            },
            "user": {
                "full_name": frappe.db.get_value("Website User", usr, "full_name"),
                "email": frappe.db.get_value("Website User", usr, "name"),
                "mobile_no": frappe.db.get_value("Website User", usr, "mobile_no"),
                "user_image": frappe.db.get_value("Website User", usr, "user_image"),
            },
        }

        frappe.response["http_status_code"] = 200
        return response

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Login Error")
        frappe.response["http_status_code"] = 500
        return {"message": _("Internal Server Error")}


def get_user_summary(email):
    """
    Fetches user summary details. Handles cases where the User document does not exist.
    """
    try:
        website_user = frappe.db.get_value(
            "Website User", filters={"name": email}, fieldname=["user_image"]
        )
        donation_amount = frappe.db.get_value(
            "Donation", {"donor_email": email}, "sum(donation_amount)"
        )
        last_donation = frappe.db.get_value(
            "Donation",
            filters={"donor_email": email, "status": "Paid"},
            fieldname="creation",
            order_by="creation desc",
        )
        donation_count = frappe.db.count(
            "Donation", {"donor_email": email, "status": "Paid"}
        )

        return {
            "avatar": website_user if website_user else None,
            "total_invoices": donation_amount if donation_amount else 0,
            "last_invoice_date": last_donation,
            "fundraiser": donation_count if donation_count else 0,
        }

    except Exception as e:
        frappe.log_error(
            message=f"Error fetching user summary for email {email}: {e}",
            title="Get User Summary Error",
        )
        return {
            "avatar": None,
            "total_invoices": 0,
            "last_invoice_date": None,
            "fundraiser": 0,
            "message": "An error occurred while fetching user summary.",
        }


def send_reset_password_email(email, link):
    try:
        frappe.sendmail(
            recipients=email,
            subject=f"Reset Your Password on SocialAngel",
            message=f"Click on the link to reset your password: {link}",
            now=True,
        )
        return {
            "success": True,
            "message": f"Reset link sent to your email address: {email}",
        }
    except Exception as e:
        frappe.log_error(
            message=f"Error sending reset password email: {str(e)}",
            title="Reset Password Email Error",
        )
        frappe.response.http_status_code = 500
        return {
            "success": False,
            "message": f"An error occurred while sending the email. {str(e)}",
        }


@frappe.whitelist(allow_guest=True)
def reset_password(key, new_password):
    """
    Reset the password of the user with the given reset key.
    """
    try:
        user = frappe.db.get_value(
            "User",
            {"reset_password_key": frappe.utils.data.sha256_hash(key)},
            "name",
        )
        if not user:
            return {"status": "failed", "message": "Invalid or expired reset key"}

        user_doc = frappe.get_doc("User", user)
        user_doc.new_password = new_password
        user_doc.reset_password_key = ""
        user_doc.last_reset_password_key_generated_on = None
        user_doc.otp_verified = 1
        user_doc.save(ignore_permissions=True)
        frappe.db.commit()

        return {"status": "success", "message": "Password reset successfully"}

    except Exception as e:
        frappe.log_error(
            message=f"Reset Password Error: Key={key}, Error={str(e)}",
            title="Reset Password Error",
        )
        frappe.response.http_status_code = 500
        return {
            "status": "failed",
            "message": "An error occurred while processing your request",
        }
