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


@frappe.whitelist(allow_guest=True)
def login_jwt(usr, pwd, expires_in=60, expire_on=None, device=None):
    """
    Login the usr and return the JWT token
    :param usr: The usr in ctx
    :param pwd: Pwd to auth
    :param expires_in: number of seconds till expiry
    :param expire_on: yyyy-mm-dd HH:mm:ss to specify the expiry (deprecated)
    :param device: The device in ctx
    """
    try:
        frappe.log_error(
            f"Login attempt: usr={usr}, expires_in={expires_in}, expire_on={expire_on}, device={device}",
            "JWT Login Debug",
        )

        if not frappe.db.exists("User", usr):
            frappe.response["http_status_code"] = 400
            return {"message": _("Invalid User")}

        from frappe.sessions import clear_sessions

        login = LoginManager()
        if not login.check_password(usr, pwd):
            frappe.response["http_status_code"] = 401
            return {"message": _("Incorrect password")}

        login.login_as(usr)
        login.resume = False
        login.run_trigger("on_session_creation")

        frappe.local.response["http_status_code"] = 200

    except frappe.ValidationError as e:
        frappe.log_error(f"Validation Error: {str(e)}", "JWT Login Error")
        frappe.response["http_status_code"] = 400
        return {"message": str(e)}

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Login Error")
        frappe.response["http_status_code"] = 500
        return {"message": _("Internal Server Error")}


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
            jwt_access_expiry_time = frappe.db.get_single_value(
                "JWT Settings", "jwt_access_expiry_time"
            )
            jwt_refresh_expiry_time = frappe.db.get_single_value(
                "JWT Settings", "jwt_refresh_expiry_time"
            )

            jwt_access_token = generate_jwt_token(
                user="user", expires_in=jwt_access_expiry_time
            )

            token_doc = frappe.get_doc("OAuth Bearer Token", token)
            if not token_doc:
                frappe.response["http_status_code"] = 401
                return {"message": "Unauthorized access. Token not found."}
            # Update the token document with new access token and expiry
            expiration_time = frappe.utils.now_datetime() + frappe.utils.timedelta(
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
        token = (
            frappe.request.headers.get("Authorization").replace("Bearer ", "").strip()
        )
        if not token:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token is missing."}
        print("tokentoken", token)
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


@frappe.whitelist(allow_guest=True)

# def generate_mobile_otp():
#     """
#     Generate a mobile OTP for the user
#     """
#     try:


#     except Exception as e:
#         frappe.log_error(frappe.get_traceback(), "JWT Generate Mobile OTP Error")
#         frappe.throw(_("Failed to generate mobile OTP"))
def validate_phone_number(phone):
        # Add your phone number validation logic here
        if not re.match(r"^\+?[1-9]\d{1,14}$", phone):  # Example: E.164 format
            raise frappe.exceptions.InvalidPhoneNumberError(
                f"Phone Number {phone} set in field mobile_no is not valid."
            )
        return phone

@frappe.whitelist(allow_guest=True)
def create_website_user(email, full_name, password, number):
    """
    Creates a Website User with the given details if the email is unique and number_verified is not True.
    """
    try:
        # Check if the email is already registered
        existing_user = frappe.db.get_value(
            "Website User",
            filters={"email": email},
            fieldname=["name", "number_verified", "email", "mobile_no"],
        )
        print(f"Existing User: {existing_user}")
        if existing_user:
            name, number_verified, user_email, mobile_no = existing_user
            if number_verified:
                frappe.response.http_status_code = 400
                return {
                    "success": False,
                    "message": "Email is already registered and phone number is verified. Cannot create a new user.",
                }
            else:
                frappe.response.http_status_code = 400
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
            user_doc = frappe.get_doc(
                {
                    "doctype": "Website User",
                    "email": email,
                    "full_name": full_name,
                    "mobile_no": number,
                    "password": password,  # Ensure password is set
                }
            )
            user_doc.insert(ignore_permissions=True)
            frappe.db.commit()
            return {
                "success": True,
                "message": "Website User created successfully.",
                "user_doc": {
                    "name": user_doc.name,
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
