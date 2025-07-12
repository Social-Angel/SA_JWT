import frappe, random
from frappe.auth import LoginManager, CookieManager
from frappe.utils import now_datetime
import requests, re
from frappe.utils import now_datetime, add_to_date
from datetime import datetime, timedelta
from frappe import _
from .auth import login_jwt_without_password


def generateOTP(digit):
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


"""
EMAIL LOGIN
"""


@frappe.whitelist(allow_guest=True)
def email_otp_sender(email):
    """
    Generates and stores OTP in the User DocType, then sends it via email.
    """
    try:
        email = str(email).strip()
        # frappe.throw(_("Email address is required."))
        if not email:
            frappe.local.response.http_status_code = 400
            return "Email address is required."

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            frappe.local.response.http_status_code = 400
            return "Invalid email address format."

        if not frappe.db.exists("User", email):
            frappe.local.response.http_status_code = 404
            return "User not found. Please register first."
        else:
            user_doc = frappe.get_doc("User", email)

        generated_otp = generateOTP(4)

        otp_doc = frappe.new_doc("SMS OTP")
        otp_doc.update({"email": email, "otp": generated_otp, "status": "Sent"})
        otp_doc.insert(ignore_permissions=True)
        frappe.db.commit()

        email_message = f"""
        <p>Dear {user_doc.full_name},</p>
        <p>Your OTP to verify your SocialAngel profile is <strong>{generated_otp}</strong>.</p>
        <p>Do not share this OTP with anyone. It is valid for 5 minutes.</p>
        <p>Thank you!</p>
        <p>Warmly,<br>SocialAngel</p>
        """

        frappe.sendmail(
            recipients=email,
            subject=f"{generated_otp} - Your OTP to Verify Your SocialAngel Profile",
            message=email_message,
            now=True,
        )
        frappe.local.response.http_status_code = 200
        return {
            "success": True,
            "message": f"OTP sent to {email}",
        }

    except Exception as e:
        frappe.local.response.http_status_code = 500
        frappe.log_error(f"Unexpected error: {e}", "Send Email OTP Error")
        return "An error occurred while sending the OTP. Please try again."


@frappe.whitelist(allow_guest=True)
def email_otp_verifier(email, otp, need_login=False):
    try:
        otp = str(otp).strip()
        email = str(email).strip()
        frappe.set_user("Administrator")
        if not frappe.db.exists("SMS OTP", {"email": email, "otp": otp}):
            frappe.local.response.http_status_code = 403
            return "Invalid OTP."

        stored_otp = frappe.get_last_doc(
            "SMS OTP", filters={"email": email, "otp": otp, "status": "Sent"}
        )

        if stored_otp.creation < add_to_date(now_datetime(), minutes=-5):
            frappe.local.response.http_status_code = 403
            return "OTP expired. Please request a new one."

        frappe.db.set_value("SMS OTP", stored_otp.name, "status", "Verified")
        frappe.db.set_value("User", email, "otp_verified", 1)
        frappe.db.set_value("User", email, "email_verified", 1)
        frappe.db.commit()

        frappe.local.response.http_status_code = 200
        return {
            "success": True,
            "message": "OTP verified successfully.",
        }

    except frappe.DoesNotExistError:
        frappe.log_error(
            message=f"Document not found error while verifying OTP for email: {email}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 404
        return "Document not found. Please try again."

    except frappe.PermissionError:
        frappe.log_error(
            message=f"Permission error while verifying OTP for email: {email}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 403
        return "Permission denied. Please contact support."

    except frappe.ValidationError as ve:
        frappe.log_error(
            message=f"Validation error while verifying OTP for email: {email}. Error: {ve}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 400
        return f"Validation error: {ve}"

    except frappe.AuthenticationError as ae:
        frappe.log_error(
            message=f"Authentication error while verifying OTP for email: {email}. Error: {ae}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 401
        return f"Authentication error: {ae}"

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error while verifying OTP for email: {email}. Error: {e}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 500
        return "An unexpected error occurred. Please contact support."




@frappe.whitelist(allow_guest=True)
def send_complete_email_otp(email):
    """
    Generates and stores OTP in the Website User DocType, then sends it via email.
    """
    try:
        email = str(email).strip()
        # frappe.throw(_("Email address is required."))
        if not email:
            frappe.local.response.http_status_code = 400
            return {
                "status": "error",
                "data": None,
                "message": "Email address is required.",
            }

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            frappe.local.response.http_status_code = 400
            return {
                "status": "error",
                "data": None,
                "message": "Invalid email address format.",
            }

        if not frappe.db.exists("Website User", email):
            frappe.local.response.http_status_code = 404
            return {
                "status": "error",
                "data": None,
                "message": "User not found. Please register first.",
            }
        else:
            website_user_doc = frappe.get_doc("Website User", email)

        generated_otp = generateOTP(4)

        otp_doc = frappe.new_doc("SMS OTP")
        otp_doc.update({"email": email, "otp": generated_otp, "status": "Sent"})
        otp_doc.insert(ignore_permissions=True)
        frappe.db.commit()

        email_message = f"""
        <p>Dear {website_user_doc.full_name},</p>
        <p>Your OTP to verify your SocialAngel profile is <strong>{generated_otp}</strong>.</p>
        <p>Do not share this OTP with anyone. It is valid for 5 minutes.</p>
        <p>Thank you!</p>
        <p>Warmly,<br>SocialAngel</p>
        """

        frappe.sendmail(
            recipients=email,
            subject=f"{generated_otp} - Your OTP to Verify Your SocialAngel Profile",
            message=email_message,
            now=True,
        )
        frappe.local.response.http_status_code = 200
        return {
            "success": True,
            "message": f"OTP sent to {email}",
        }

    except Exception as e:
        frappe.local.response.http_status_code = 500
        frappe.log_error(f"Unexpected error: {e}", "Send Email OTP Error")
        return {
            "status": "error",
            "data": None,
            "message": "An error occurred while sending the OTP. Please try again.",
        }



@frappe.whitelist(allow_guest=True)
def complete_email_login(email, otp, uuid=None):
    try:
        otp = str(otp).strip()
        email = str(email).strip()
        frappe.set_user("Administrator")
        if not frappe.db.exists("SMS OTP", {"email": email, "otp": otp}):
            frappe.local.response.http_status_code = 403
            return {
                "status": "error",
                "data": None,
                "message": "Invalid OTP. Please try again.",
            }
        if not frappe.db.exists("Website User", email):
            frappe.local.response.http_status_code = 404
            return {
                "status": "error",
                "data": None,
                "message": "User not found. Please register first.",
            }

        stored_otp = frappe.get_last_doc(
            "SMS OTP", filters={"email": email, "otp": otp, "status": "Sent"}
        )

        if stored_otp.creation < add_to_date(now_datetime(), minutes=-5):
            frappe.local.response.http_status_code = 403
            return {
                "status": "error",
                "data": None,
                "message": "OTP expired. Please request a new one.",
            }

        website_user = frappe.get_doc("Website User", email.lower())


        user = frappe.new_doc("User")
        user.update(
            {
                "doctype": "User",
                "email": email,
                "first_name": website_user.full_name.split(" ")[0],
                "last_name": " ".join(website_user.full_name.split(" ")[1:]),
                "phone": website_user.phone,
                "gender": website_user.gender,
                "birth_date": website_user.dob,
                "send_welcome_email": 1,
            }
        )
        if user:
            website_user.email_verified = 1
            website_user.number_verified = 1
            website_user.user = email

            website_user.save(ignore_permissions=True)
            user.save(ignore_permissions=True)

            frappe.db.set_value("SMS OTP", stored_otp.name, "status", "Verified")
            frappe.db.commit()
            login_response = login_jwt_without_password(email)
            frappe.response["http_status_code"] = 201
            
            try:
                if uuid:
                    frappe.db.set_value(
                        "Website Visitor", {"uuid": uuid}, "website_user", email
                    )
            except Exception as e:
                pass
            

            return {
                "success": True,
                "message": "OTP verified successfully and User Created.",
                "Action_Required": "Login",
                **login_response,
            }
        else:
            frappe.local.response.http_status_code = 500
            return {
                "status": "error",
                "data": None,
                "message": "Failed to create user. Please try again.",
            }

    except frappe.DoesNotExistError:
        frappe.log_error(
            message=f"Document not found error while verifying OTP for email: {email}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 404
        return {
            "status": "error",
            "data": None,
            "message": "Document not found. Please try again.",
        }

    except frappe.PermissionError:
        frappe.log_error(
            message=f"Permission error while verifying OTP for email: {email}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 403
        return {
            "status": "error",
            "data": None,   
            "message": "Permission denied. Please contact support.",
        }

    except frappe.ValidationError as ve:
        frappe.log_error(
            message=f"Validation error while verifying OTP for email: {email}. Error: {ve}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 400
        return {
            "status": "error",
            "data": None,
            "message": f"Validation error: {ve}",
        }

    except frappe.AuthenticationError as ae:
        frappe.log_error(
            message=f"Authentication error while verifying OTP for email: {email}. Error: {ae}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 401
        return {
            "status": "error",
            "data": None,
            "message": f"Authentication error: {ae}",
        }

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error while verifying OTP for email: {email}. Error: {e}",
            title="Verify Email OTP Error",
        )
        frappe.local.response.http_status_code = 500
        return {
            "status": "error",
            "data": None,
            "message": "An unexpected error occurred. Please contact support.",
        }
