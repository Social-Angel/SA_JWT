import frappe
from frappe import _
import requests, re
from frappe.utils import now_datetime, add_to_date
from requests import RequestException
from jwt_frappe.utils.constants import  PHONE_REGEX
from jwt_frappe.domain.auth_domain import generate_otp ,get_user_summary
from frappe.utils.password import decrypt





# Api 6
@frappe.whitelist(allow_guest=True)
def send_sms_otp_for_mobile_login(number):
    """
    Sends the generated OTP to the given phone number using the SMS service.
    """
    try:
        # Check the phone number
        number = str(number).strip()
        if not number:
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Phone number is required."}
        
        if not re.match(PHONE_REGEX, number):
            frappe.log_error(
                message=f"Invalid phone number format: {number}",
                title="User Creation Error",
            )
            frappe.response.http_status_code = 403
            return {
                "status": "error",
                "data": None,
                "message": _("Invalid phone number format. Please provide a valid phone number."),
            }
        # Check number in website user
        website_user = frappe.db.get_value(
            "Website User", filters={"mobile_no": number}, fieldname=["name"]
        )
        if not website_user:
            frappe.response.http_status_code = 404
            return {
                "success": False,
                "message": "Website User not found for the provided phone number.",
            }

        # Query the Mobile Login Attempt doctype
        mobile_login_attempt = frappe.db.get_value(
            "Mobile Login Attempt",
            filters={"mobile_number": number},
            fieldname=["otp_attempts", "last_attempt_time"],
        )

        # If the record doesn't exist, create it
        if not mobile_login_attempt:
            frappe.get_doc(
                {
                    "doctype": "Mobile Login Attempt",
                    "mobile_number": number,
                    "otp_attempts": 0,
                    "last_attempt_time": None,
                }
            ).insert(ignore_permissions=True)
            frappe.db.commit()
            mobile_login_attempt = (0, None)

        otp_attempts, last_attempt_time = mobile_login_attempt

        # Check if the user has exceeded the OTP request limit
        if last_attempt_time:
            time_difference = frappe.utils.time_diff_in_seconds(
                frappe.utils.now_datetime(), last_attempt_time
            )
            if time_difference >= 3600:
                # Reset OTP attempts if time_difference exceeds 1 hour
                otp_attempts = 0
                frappe.db.set_value(
                    "Mobile Login Attempt",
                    {"mobile_number": number},
                    {"otp_attempts": 0},
                )
            elif otp_attempts >= 4:
                frappe.response.http_status_code = 429
                return {
                    "success": False,
                    "message": "Too many OTP requests. Please try again after 1 hour.",
                }

        # Update OTP attempts and last attempt time
        try:
            frappe.db.set_value(
                "Mobile Login Attempt",
                {"mobile_number": number},
                {
                    "otp_attempts": otp_attempts + 1,
                    "last_attempt_time": frappe.utils.now_datetime(),
                },
            )
        except Exception as e:
            frappe.log_error(
                message=f"Error updating OTP attempts: {e}",
                title="Mobile OTP Update Error",
            )
            frappe.response.http_status_code = 500
            return {
                "success": False,
                "message": "An error occurred while updating OTP attempts.",
            }

        # Generate OTP
        otp = generate_otp(4)
        if not number:
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Phone number is required."}

        ss = frappe.get_doc("SMS Settings", "SMS Settings")
        if not ss.sms_gateway_url:
            frappe.response.http_status_code = 500
            return {"success": False, "message": "SMS Gateway URL is not configured"}

        message = f"Hi Your OTP for SocialAngel is {otp}. Please do not share this with anyone. Regards SocialAngel"
        encoded_message = requests.utils.quote(message)

        args = {"message": encoded_message}
        for d in ss.get("parameters"):
            args[d.parameter] = d.value

        args["mobile"] = number

        query_string = "&".join(f"{key}={value}" for key, value in args.items())
        url = f"{ss.sms_gateway_url}?{query_string}"
        response = requests.get(url)
        response_text = response.text

        if response.status_code == 200 and "SUBMIT_SUCCESS" in response_text:
            frappe.get_doc(
                {"doctype": "SMS OTP", "number": number, "status": "Sent"}
            ).insert(ignore_permissions=True)

            frappe.db.commit()
            frappe.local.response.http_status_code = 200

            return {
                "success": True,
                "Action_Required": "Verify Mobile OTP for Login",
                "message": f"OTP sent to {number}",
            }

        else:
            frappe.log_error(
                message=f"SMS sending failed. Response: {response_text}. Phone: {number}",
                title="SMS OTP Error",
            )
            frappe.response.http_status_code = 500
            return "Failed to send OTP. Please try again."

    except RequestException as re:
        frappe.log_error(
            message=f"Request error during SMS OTP send: {re}. Phone: {number}",
            title="SMS OTP Error",
        )
        frappe.response.http_status_code = 500
        return "Failed to send OTP due to a network error. Please try again later."

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error during SMS OTP send: {e}. Phone: {number}",
            title="SMS OTP Error",
        )
        frappe.response.http_status_code = 500
        return {
            "message": "An unexpected error occurred while sending OTP. Please try again later."
        }

# Api 7
@frappe.whitelist(allow_guest=True)
def verify_sms_otp_for_mobile_login(number, otp):
    """Verifies the last OTP stored in the SMS OTP document within 5 minutes."""
    try:
        number = str(number).strip()
        otp = str(otp).strip()
        
        # Check if the number is provided
        if not number:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Phone number is required."}

        # Validate the phone number format
        if not re.match(PHONE_REGEX, number):
            frappe.log_error(
                message=f"Invalid phone number format: {number}",
                title="User Creation Error",
            )
            frappe.response.http_status_code = 403
            return {
                "status": "error",
                "data": None,
                "message": _("Invalid phone number format. Please provide a valid phone number."),
            }

        # Check if the document exists
        if not frappe.db.exists("SMS OTP", {"number": number}):
            frappe.response["http_status_code"] = 404
            return {"success": False, "message": "No OTP found for this number."}

        # Fetch the last document
        try:
            otp_doc = frappe.get_last_doc(
                "SMS OTP", filters={"number": number, "status": "Sent"}
            )
        except frappe.DoesNotExistError:
            frappe.response["http_status_code"] = 404
            return {"success": False, "message": "No OTP found for this number."}

        # Check if OTP has expired
        expiry_time = add_to_date(otp_doc.creation, minutes=5)
        if now_datetime() > expiry_time:
            frappe.response["http_status_code"] = 403
            frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Expired")
            frappe.db.commit()
            return {
                "success": False,
                "message": "OTP expired. Please request a new one.",
            }
        decrypted_otp = decrypt(otp_doc.otp)
        # Validate OTP
        if otp != decrypted_otp:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Invalid OTP."}

        # Mark OTP as verified
        frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Verified")

        # Fetch website user details
        website_users = frappe.get_all(
            "Website User",
            filters={"mobile_no": number},
            fields=[
                "name",
                "full_name",
                "mobile_no",
                "email_verified",
                "number_verified",
                "user",
            ],
        )
        for user in website_users:
            user_email = user.get("name")
            user["user_summary"] = (
                get_user_summary(user_email) if user_email else "None"
            )

        if not website_users:
            frappe.response["http_status_code"] = 404
            return {
                "success": False,
                "message": "Website User not found for the provided phone number.",
            }
        frappe.db.set_value("Website User", {"mobile_no": number}, "number_verified", 1)
        frappe.db.commit()
        frappe.response["http_status_code"] = 200
        return {
            "success": True,
            "Action_Required": "Choose email to Login",
            "message": "OTP verified successfully.",
            "website_users": website_users,
        }

    except frappe.PermissionError:
        frappe.response["http_status_code"] = 403
        return {"success": False, "message": "Permission denied for SMS OTP."}
    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error: {e} : {frappe.get_traceback()}",
            title="Verify SMS OTP Error",
        )
        frappe.response["http_status_code"] = 500
        return {"success": False, "message": "An unexpected error occurred."}
