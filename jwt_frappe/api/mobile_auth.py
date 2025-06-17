import frappe, random
from frappe.auth import LoginManager, CookieManager
from frappe.utils import now_datetime
import requests, re
from frappe import _
from frappe.utils import get_url, random_string, now_datetime, add_to_date
from socialangel.api.utils import create_lead
from socialangel.api.auths.utils import create_website_user ,send_otp_to_number ,generateOTP
from datetime import datetime, timedelta
from socialangel.api.donor import get_details_of_donor_donations
from frappe.core.doctype.user.user import test_password_strength


def log_error(context, error):
    frappe.log_error(title=context, message=str(error))


#
# <----------------  Separate Functions Start ---------------->
#




#
# <----------------  Separate Functions End ---------------->
#


#
# <----------------  Check Login User By Mobile Number  ---------------->
#


@frappe.whitelist(allow_guest=True)
def check_user_by_mobile(phone):
    frappe.set_user("Administrator")
    user = frappe.db.get_value("User", filters={"phone": phone}, fieldname=["name"])
    if user:
        return True
    else:
        return False


#
# <----------------  Send Otp to Mobile Number  ---------------->
#


@frappe.whitelist(allow_guest=True)
def init_user_with_otp(number, email, full_name, is_login=False):
    """
    Sends the generated OTP to the given phone number using the SMS service.
    Creates a Website User if the email is unique and tracks OTP attempts.
    """
    from requests import RequestException

    try:
        if is_login:
            if not check_user_by_mobile(number):
                frappe.response.http_status_code = 404
                return "Phone number not found in the system. Please use a registered phone number."

        # Check if the SMS OTP exists before fetching
        if frappe.db.exists("SMS OTP", {"number": number}):
            check_user_mobile_otp_attempts = frappe.get_doc("SMS OTP", {"number": number})
            # Check if last_attempt is older than 24 hours
            if check_user_mobile_otp_attempts.last_attempt:
                time_difference = datetime.now() - check_user_mobile_otp_attempts.last_attempt
                if time_difference > timedelta(hours=24):
                    check_user_mobile_otp_attempts.otp_attempts = 0
                    check_user_mobile_otp_attempts.save(ignore_permissions=True)

            if check_user_mobile_otp_attempts.otp_attempts >= 3:
                frappe.response.http_status_code = 429
                return {
                    "success": False,
                    "message": "Too many OTP attempts. Please try again later.",
                }
        else:
            check_user_mobile_otp_attempts = None

        # Check if email is unique
        existing_user = frappe.db.get_value(
            "User", filters={"email": email}, fieldname=["name"]
        )

        if existing_user:
            frappe.response.http_status_code = 400
            return {
                "success": False,
                "message": "Email is already registered. Please use a different email.",
            }

        
        if not number:
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Phone number is required."}



        # Create Website User
        user_response = create_website_user(email, full_name, number)
        if not user_response["success"]:
            return user_response
        otp = generateOTP(4)
        otp_response = send_otp_to_number(number, otp)
        if not otp_response["success"]:
            return otp_response
        
        # Update or create SMS OTP document
        if frappe.db.exists("SMS OTP", {"number": number}):
            sms_otp_doc = frappe.get_doc("SMS OTP", {"number": number})
            sms_otp_doc.otp_attempts += 1
            sms_otp_doc.otp = str(otp)
            sms_otp_doc.status = "Sent"
            sms_otp_doc.last_website_user = user_response['user_doc']['name']
            sms_otp_doc.last_attempt = datetime.now()
            sms_otp_doc.save(ignore_permissions=True)
        else:
            sms_otp_doc = frappe.get_doc(
                {
                    "doctype": "SMS OTP",
                    "number": number,
                    "otp": str(otp),
                    "status": "Sent",
                    "otp_attempts": 1,
                    "last_website_user": user_response['user_doc']['name'],
                    "last_attempt": datetime.now(),
                }
            )
            sms_otp_doc.insert(ignore_permissions=True)

        frappe.db.commit()
        

        frappe.local.response.http_status_code = 200

        return {
            "success": True,
            "message": f"OTP sent to {number} and Website User created successfully.",
            "data": {
            "website_user_email": user_response['user_doc']['email'],
            "message": user_response["message"],
            "phone_number": number,
            },
        }

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error during OTP initialization: {e}\nTraceback: {frappe.get_traceback()}",
            title="SMS OTP Error",
        )
        frappe.response.http_status_code = 500
        return {
            "message": "An unexpected error occurred while sending OTP. Please try again later."
        }


@frappe.whitelist(allow_guest=True)
def login_with_sms(phone):
    """
    Generates an OTP, creates an SMS OTP document, and sends the OTP to the provided phone number.
    """
    if not phone:
        return {"message": "Phone number is required."}

    try:
        frappe.set_user("Administrator")
        if not check_user_by_mobile(phone):
            frappe.response.http_status_code = 404
            return {
                "message": "Phone number not found in the system. Please use a registered phone number."
            }

        otp = generateOTP(4)

        # Create and insert OTP document
        doc = frappe.get_doc(
            {"doctype": "SMS OTP", "number": phone, "otp": otp, "status": "Sent"}
        )
        doc.insert(ignore_permissions=True)
        frappe.db.commit()

        # Send OTP via SMS
        return init_user_with_otp(phone)

    except frappe.ValidationError as ve:
        frappe.response.http_status_code = 400
        error_message = f"Validation error during OTP generation: {ve}. Phone: {phone}"
        frappe.log_error(error_message, title="OTP Login Error")
        return {"message": "Validation error occurred."}

    except Exception as e:
        frappe.response.http_status_code = 500
        error_message = f"Unexpected error: {e}. Phone: {phone}"
        frappe.log_error(error_message, title="OTP Login Error")
        return {"message": "An unexpected error occurred. Please try again later."}


#
# <----------------  Validate OTP  ---------------->
#


@frappe.whitelist(allow_guest=True)
def verify_sms_otp_login(number, otp, website_user_email=None):
    """Verifies the last OTP stored in the SMS OTP document within 5 minutes."""
    try:


        # Check if the document exists
        if not frappe.db.exists("SMS OTP", {"number": number}):
            frappe.response["http_status_code"] = 404
            return {
            "success": False,
            "message": "No OTP found number."
            }

        # Fetch the last document
        try:
            otp_doc = frappe.get_last_doc(
                "SMS OTP", filters={"number": number, "status": "Sent"}
            )
        except frappe.DoesNotExistError:
            frappe.response["http_status_code"] = 404
            return {
                "success": False,
                "message": "No OTP found for this number."
            }

        # Check if OTP has expired
        expiry_time = add_to_date(otp_doc.creation, minutes=5)
        if now_datetime() > expiry_time:
            frappe.response["http_status_code"] = 403
            frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Expired")
            frappe.db.commit()
            return "OTP expired. Please request a new one."

        # Validate OTP
        if otp_doc.otp != str(otp):
            frappe.response["http_status_code"] = 400
            return "Invalid OTP."

        # Mark OTP as verified
        frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Verified")

        # Update Website User if email is provided
        if website_user_email:
            frappe.db.set_value("Website User", {"email": website_user_email}, "number_verified", 1)

        frappe.db.commit()

        frappe.response["http_status_code"] = 200
        return "OTP verified successfully."
    except frappe.PermissionError:
        frappe.response["http_status_code"] = 403
        return "Permission denied for SMS OTP."
    except Exception as e:
        frappe.log_error(message=f"Unexpected error: {e} : {frappe.get_traceback()}", title="Verify SMS OTP Error")
        frappe.response["http_status_code"] = 500
        return "An unexpected error occurred."
