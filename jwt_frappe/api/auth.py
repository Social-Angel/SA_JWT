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

# <---------------- Separate function ---------------->


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


# <---------------- Creating Real Frappe User (This is not a API Depend on verify_sms_otp_login )  ---------------->


def register_real_user(full_name, email, phone_number):
    """
    Registers a new user. If the user already exists, appropriate error messages are returned.
    """
    try:
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
                "send_welcome_email": 1,
                # "new_password": password,
                "number_verified": 1,
            }
        )

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


# <---------------- JWT Login API Without Password ---------------->


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
                "full_name": frappe.db.get_value("User", usr, "full_name"),
                "email": frappe.db.get_value("User", usr, "email"),
                "mobile_no": frappe.db.get_value("User", usr, "phone"),
                "user_image": frappe.db.get_value("User", usr, "user_image"),
            },
        }

        frappe.response["http_status_code"] = 200
        return response

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Login Error")
        frappe.response["http_status_code"] = 500
        return {"message": _("Internal Server Error")}


@frappe.whitelist(allow_guest=True)
def login_jwt(usr, pwd, expires_in=60, expire_on=None, device=None):
    """
    Login the usr and return the JWT token
    """
    try:
        frappe.flags.skip_on_session_creation = True

        # Check if the username and password are provided
        if not pwd:
            frappe.response["http_status_code"] = 400
            return {"Success": False, "message": _("Password is required")}
        if not usr:
            frappe.response["http_status_code"] = 400
            return {"Success": False, "message": _("Username is required")}

        user_doc = frappe.get_doc("User", usr)
        if not user_doc.enabled:
            raise frappe.ValidationError(_("User is disabled"))

        # Check if the user exists
        if not frappe.db.exists("User", usr):
            frappe.response["http_status_code"] = 400
            return {"Success": False, "message": _("Invalid User")}

        login = LoginManager()
        try:
            if not login.check_password(usr, pwd):
                frappe.response["http_status_code"] = 401
                return {
                    "Success": False,
                    "message": _("Incorrect username or password"),
                }
        except frappe.AuthenticationError:
            frappe.log_error(
                message=f"Authentication failed for user: {usr}", title="Login Error"
            )
            frappe.response["http_status_code"] = 401
            return {"Success": False, "message": _("Incorrect username or password")}

        login.login_as(usr)
        login.resume = True

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
                "full_name": frappe.db.get_value("User", usr, "full_name"),
                "email": frappe.db.get_value("User", usr, "email"),
                "mobile_no": frappe.db.get_value("User", usr, "phone"),
                "user_image": frappe.db.get_value("User", usr, "user_image"),
            },
        }

        frappe.response["http_status_code"] = 200
        return response

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
def create_website_user(email, full_name, password):
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
                    "Action_Required": "Login",
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
            hashed_password = passlibctx.hash(password)

            user_doc = frappe.get_doc(
                {
                    "doctype": "Website User",
                    "email": email,
                    "full_name": full_name,
                    # "password": hashed_password,
                }
            )

            user_doc.insert(ignore_permissions=True)

            auth_doc = frappe.db.sql(
                """
                    INSERT INTO `__Auth` (name, doctype,fieldname, password, encrypted)
                    VALUES (%s, %s, %s, %s, %s)
                """,
                (email, "Website User", "password", hashed_password, 0),
            )

            frappe.db.commit()
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


# <---------------- Mobile SMS Vefify for creating website user ---------------->


@frappe.whitelist(allow_guest=True)
def send_sms_otp(number, website_user):
    """
    Sends the generated OTP to the given phone number using the SMS service.
    """

    try:

        # Validate the website user
        if not website_user:
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Website User is required."}

        # Query the Website User
        validate_website_user = frappe.db.get_value(
            "Website User",
            {"name": website_user},
            ["mobile_otp_attempts", "mobile_last_attempt", "number_verified", "user"],
        )

        mobile_otp_attempts, mobile_last_attempt, number_verified, user = (
            validate_website_user if validate_website_user else (0, None, 0, None)
        )
        # Check if the website user exists
        if not validate_website_user:
            frappe.response.http_status_code = 404
            return {
                "success": False,
                "message": "Website User not found for the provided email.",
            }
        if number_verified == 1:
            frappe.response.http_status_code = 400
            return {
                "success": False,
                "Action_Required": "Login",
                "message": f"Phone number is already verified for this Email {website_user}. No need to send OTP.",
            }
        if user:
            if frappe.db.exists("User", user):
                # If the user is already registered, return a message
                frappe.response.http_status_code = 400
                return {
                    "success": False,
                    "Action_Required": "Login",
                    "message": f" User {user} is already registered. No need to send OTP.",
                }

        # Check if the user has exceeded the OTP request limit
        # If the user has made 4 or more attempts in the last hour, block further requests
        if validate_website_user:
            if mobile_otp_attempts >= 4 and mobile_last_attempt:
                time_difference = frappe.utils.time_diff_in_seconds(
                    frappe.utils.now_datetime(), mobile_last_attempt
                )
                if time_difference < 3600:
                    frappe.response.http_status_code = 429
                    return {
                        "success": False,
                        "message": "Too many OTP requests. Please try again after 1 hour.",
                    }

        # Check and update mobile number attempts via Website User
        try:
            check_website_user = frappe.db.get_value(
                "Website User", {"name": website_user}, ["mobile_no", "name"]
            )
            mobile, name = check_website_user if check_website_user else (None, None)
            # return {"check_website_user":mobile ,"name":name ,"website_user": website_user}

            if not name:
                return {
                    "success": False,
                    "message": "Website User not found for the Email.",
                }
            else:
                if name and mobile == str(number):
                    user_doc = frappe.get_doc("Website User", website_user)
                    user_doc.mobile_otp_attempts = (
                        cint(user_doc.mobile_otp_attempts) + 1
                    )
                    user_doc.mobile_last_attempt = frappe.utils.now_datetime()
                    user_doc.save(ignore_permissions=True)
                else:
                    user_doc = frappe.get_doc("Website User", website_user)
                    user_doc.mobile_no = number
                    user_doc.mobile_otp_attempts = 1
                    user_doc.mobile_last_attempt = frappe.utils.now_datetime()
                    user_doc.save(ignore_permissions=True)

        except Exception as e:
            frappe.log_error(
                message=f"Error updating mobile OTP attempts: {e}",
                title="Mobile OTP Update Error",
            )
            frappe.response.http_status_code = 401
            return {
                "success": False,
                "message": "An error occurred while updating mobile OTP attempts.",
            }

        otp = generateOTP(4)
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
                {"doctype": "SMS OTP", "number": number, "otp": otp, "status": "Sent"}
            ).insert(ignore_permissions=True)

            frappe.db.commit()
            frappe.local.response.http_status_code = 200

            # update website user Attempt and timestamp
            return {
                "success": True,
                "Action_Required": "verify_mobile",
                "email": website_user,
                "number": number,
                "message": f"OTP sent to {number}",
            }

        else:
            frappe.log_error(
                message=f"SMS sending failed.  {response_text}. Phone: {number} Response: {e}\nTraceback: {frappe.get_traceback()}",
                title="SMS OTP Error",
            )
            frappe.response.http_status_code = 500
            return "Failed to send OTP. Please try again."

    except RequestException as re:
        frappe.log_error(
            message=f"Request error during SMS OTP send: {re}. Phone: {number} {e}\nTraceback: {frappe.get_traceback()}",
            title="SMS OTP Error",
        )
        frappe.response.http_status_code = 500
        return "Failed to send OTP due to a network error. Please try again later."

    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error during SMS OTP send: {e}. Phone: {number} {e}\nTraceback: {frappe.get_traceback()}",
            title="SMS OTP Error",
        )
        frappe.response.http_status_code = 500
        return {
            "message": "An unexpected error occurred while sending OTP. Please try again later."
        }


# <---------------- (1.) Verify SMS OTP and  (2.) Create Real User and (3.) Login  ---------------->


@frappe.whitelist(allow_guest=True)
def verify_sms_otp_login(number, otp, website_user_email=None):
    """Verifies the last OTP stored in the SMS OTP document within 5 minutes."""
    try:
        # Check if the number is provided
        if not number:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Phone number is required."}

        # Validate the phone number format
        if not re.match(r"^\+?[0-9]{10,15}$", number):
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Invalid phone number format."}

        # Check if the website user email is provided
        if not website_user_email:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Website User email is required."}

        # Checking if the user exists in the User table before create website user
        if frappe.db.exists("User", website_user_email):
            frappe.response["http_status_code"] = 400
            return {
                "success": False,
                "Action_Required": "Login",
                "message": f"User {website_user_email} is already registered. No need to verify OTP.",
            }
        website_user = frappe.db.get_value(
            "Website User", {"email": website_user_email}, ["name"]
        )
        # Check if the website user exists
        if not website_user:
            frappe.response["http_status_code"] = 404
            return {
                "success": False,
                "Action_Required": "Create First Website User for given email",
                "message": "Website User not found for the provided email.",
            }

        # Check if the document exists
        if not frappe.db.exists("SMS OTP", {"number": number}):
            frappe.response["http_status_code"] = 404
            return {"success": False, "message": "No OTP found number."}

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
            return "OTP expired. Please request a new one."

        # Validate OTP
        if otp_doc.otp != str(otp):
            frappe.response["http_status_code"] = 400
            return "Invalid OTP."

        # Mark OTP as verified
        frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Verified")

        if website_user_email:
            website_user = frappe.db.get_value(
                "Website User",
                {"email": website_user_email},
                [
                    "name",
                    "full_name",
                    "email",
                ],
            )
            if website_user:
                name, full_name, email = website_user
                user = register_real_user(
                    full_name=full_name,
                    email=email,
                    phone_number=number,
                )
                print(f"User Registration Response: {user}")
                if not isinstance(user, dict) or user.get("success") is False:
                    frappe.response["http_status_code"] = 400
                    return user.get(
                        "message", user.get("message", "User creation failed.")
                    )
                else:
                    frappe.db.set_value(
                        "Website User", name, {"number_verified": 1, "user": email}
                    )
                    frappe.db.sql(
                        """ UPDATE `__Auth` SET doctype = %s WHERE name = %s """,
                        ("User", email),
                    )
                    frappe.db.commit()
                    login_response = login_jwt_without_password(email)
                    frappe.response["http_status_code"] = 201
                    return {
                        "success": True,
                        "message": "OTP verified successfully and User Created.",
                        "Action_Required": "Login",
                        **login_response,
                    }
            else:
                frappe.response["http_status_code"] = 404
                return {
                    "success": False,
                    "Action_Required": "Create First Website User for given email",
                    "message": "Otp Verified successfully but Website User not found for the provided email.",
                }
        frappe.db.commit()

        frappe.response["http_status_code"] = 201
        return {
            "success": True,
            "message": "OTP verified successfully.",
            "Action_Required": "User Creation Failed",
        }
    except frappe.PermissionError:
        frappe.response["http_status_code"] = 403
        return {
            "success": False,
            "message": "You do not have permission to perform this action.",
        }
    except Exception as e:
        frappe.log_error(
            message=f"Unexpected error Real User: {e} : {frappe.get_traceback()}",
            title="Verify SMS OTP Error",
        )
        frappe.response["http_status_code"] = 500
        return {
            "success": False,
            "message": "An unexpected error occurred while verifying OTP. Please try again later.",
        }


# <---------------- Mobile SMS OTP Vefify for Login ---------------->


@frappe.whitelist(allow_guest=True)
def send_sms_otp_for_mobile_login(number):
    """
    Sends the generated OTP to the given phone number using the SMS service.
    """
    try:
        # Check the phone number
        if not number:
            frappe.response.http_status_code = 400
            return {"success": False, "message": "Phone number is required."}

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
        otp = generateOTP(4)
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
                {"doctype": "SMS OTP", "number": number, "otp": otp, "status": "Sent"}
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


@frappe.whitelist(allow_guest=True)
def verify_sms_otp_for_mobile_login(number, otp):
    """Verifies the last OTP stored in the SMS OTP document within 5 minutes."""
    try:
        # Check if the number is provided
        if not number:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Phone number is required."}

        # Validate the phone number format
        if not re.match(r"^\+?[0-9]{10,15}$", number):
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Invalid phone number format."}

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

        # Validate OTP
        if otp_doc.otp != str(otp):
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Invalid OTP."}

        # Mark OTP as verified
        frappe.db.set_value("SMS OTP", otp_doc.name, "status", "Verified")

        # Fetch website user details
        website_users = frappe.get_all(
            "Website User",
            filters={"mobile_no": number},
            fields=["name","full_name","mobile_no", "email_verified", "number_verified", "user",],
        )
        for user in website_users:
            user_email = user.get("name")
            user["user_summary"] = get_user_summary(user_email) if user_email else "None"
            
        if not website_users:
            frappe.response["http_status_code"] = 404
            return { 
                "success": False,
                "message": "Website User not found for the provided phone number.",
            }

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


@frappe.whitelist(allow_guest=True)
def mobile_verified_email_login(email, number):
    """
    Login using email and mobile verification status.
    If the email is verified and the mobile number is verified, login the user.
    If the email is not verified or the mobile number is not verified, return an error message.
    """
    try:
        if not number:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Phone number is required."}

        mobile_validate_status = frappe.db.get_value(
            "Mobile Login Attempt",
            filters={"name": number},
            fieldname=["last_attempt_time"],
        )
        if not mobile_validate_status:
            frappe.response["http_status_code"] = 404
            return {
                "success": False,
                "message": "Mobile Login Attempt not found for the provided phone number.",
            }
        last_attempt_time = mobile_validate_status
        expiry_time = add_to_date(last_attempt_time, minutes=5)
        if now_datetime() > expiry_time:
            frappe.response["http_status_code"] = 400
            return {
                "success": False,
                "Action_Required": "Login Again with OTP",
                "message": "Request expired. Please try again within 5 minutes.",
            }

        if not email:
            frappe.response["http_status_code"] = 400
            return {"success": False, "message": "Email is required."}

        # Check if the email exists in the Website User table
        website_user = frappe.db.get_value(
            "Website User",
            filters={"email": email},
            fieldname=["name", "email_verified", "number_verified", "user"],
        )

        if not website_user:
            frappe.response["http_status_code"] = 404
            return {
                "success": False,
                "message": "Website User not found for the provided email.",
            }

        name, email_verified, number_verified, user = website_user

        # if email_verified != 1 or number_verified != 1:
        if number_verified != 1:

            return {
                "success": False,
                "Action_Required": "Verify Phone or Email",
                "message": "Website User exists but verification is required.",
                "website_user": {
                    "name": name,
                    "email_verified": email_verified,
                    "number_verified": number_verified,
                },
            }

        # Check if user exists in the User table
        user_exists = frappe.db.get_value("User", filters={"email": email})
        if user_exists:

            login_response = login_jwt_without_password(email)
            frappe.response["http_status_code"] = 200
            return {
                "success": True,
                "Action_Required": "Login",
                "message": "User logged in successfully.",
                **login_response,
            }
        else:
            return {
                "success": False,
                "message": f"Website User exists but User registration is incomplete for {email}.",
            }

    except Exception as e:
        frappe.response["http_status_code"] = 500
        frappe.log_error(f"Error logging in with email: {str(e)}", "Email Login Error")
        return {"message": "An error occurred while logging in with email"}


@frappe.whitelist(allow_guest=True)
def login_with_google(code):
    """
    Login using Google OAuth. If the user does not exist, create a Website User,
    then create a User, and finally log them in.
    """
    try:
        if not code:
            return {"success": False, "message": _("Google code is required for login")}

        google_id_token = code.get("credential")
        if not google_id_token:
            frappe.throw(_("Google ID token is required"))

        # Validate Google token
        res = requests.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": google_id_token},
        )
        if res.status_code != 200:
            frappe.throw(_("Invalid Google token")) 

        userinfo = res.json()
        email = userinfo.get("email", "papajikatsa@gmail.com")
        first_name = userinfo.get("given_name", "vishal11")
        last_name = userinfo.get("family_name", "Kumar")
        image_url = userinfo.get("picture", "default_image_url.jpg")

        # email = "papajikatsa@gmail.com"
        # first_name = "vishal11"
        # last_name = "Kumar"
        # image_url = "default_image_url.jpg"

        if not email:
            frappe.throw(_("Email is required"))

        # Check if user exists in the User table
        user_exists = frappe.db.get_value("User", filters={"email": email})
        if user_exists:
            # Login the user if they exist
            login_response = login_jwt_without_password(email)
            frappe.response["http_status_code"] = 200
            return {
                "success": True,
                "Action_Required": "Login",
                "message": "User logged in successfully.",
                **login_response,
            }
        else:
            # Check if website user exists
            website_user = frappe.db.get_value(
                "Website User",
                filters={"email": email},
                fieldname=["name", "email_verified", "number_verified", "user"],
            )
            if website_user:
                name, email_verified, number_verified, user = website_user
            else:
                name, email_verified, number_verified, user = None, None, None, None
            if not website_user:
                # Create a new Website User
                website_user_doc = frappe.get_doc(
                    {
                        "doctype": "Website User",
                        "email": email,
                        "full_name": f"{first_name} {last_name}",
                        "user_image": image_url,
                        "email_verified": 1,
                    }
                )
                website_user_doc.insert(ignore_permissions=True)
                frappe.db.commit()
                if website_user_doc.name:
                    # Create a new User
                    user_doc = frappe.get_doc(
                        {
                            "doctype": "User",
                            "email": email,
                            "first_name": first_name,
                            "last_name": last_name,
                            "user_image": image_url,
                            "enabled": 1,
                            "send_welcome_email": 0,  # Set to 0 to avoid sending
                        }
                    )
                    user_doc.insert(ignore_permissions=True)
                    frappe.db.set_value(
                        "Website User", website_user_doc.name, "user", user_doc.name
                    )

                    frappe.db.commit()

                # Login the newly created user
                login_response = login_jwt_without_password(email)
                frappe.response["http_status_code"] = 201
                return {
                    "success": True,
                    "Action_Required": "Login",
                    "message": "User created and logged in successfully.",
                    **login_response,
                }
            else:
                user_doc = frappe.get_doc(
                    {
                        "doctype": "User",
                        "email": email,
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_image": image_url,
                        "enabled": 1,
                        "send_welcome_email": 0,  # Set to 0 to avoid sending
                    }
                )
                user_doc.insert(ignore_permissions=True)
                frappe.db.set_value(
                    "Website User", website_user_doc.name, "user", user_doc.name
                )
                frappe.set_value(
                    "Website User",
                    name,
                    {
                        "email_verified": 1,
                    },
                )
                frappe.db.commit()
                login_response = login_jwt_without_password(email)
                frappe.response["http_status_code"] = 201
                return {
                    "success": True,
                    "Action_Required": "Login",
                    "message": "User created and logged in successfully.",
                    **login_response,
                }

    except Exception as e:
        frappe.response["http_status_code"] = 500
        frappe.log_error(
            f"Error logging in with Google: {str(e)} {frappe.get_traceback()}",
            "Login with Google Error",
        )
        return {"message": "An error occurred while logging in with Google"}


"""
EMAIL LOGIN
"""


@frappe.whitelist(allow_guest=True)
def send_email_otp(email):
    """
    Generates and stores OTP in the User DocType, then sends it via email.
    """
    try:
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
        return f"OTP sent to {email}"

    except Exception as e:
        frappe.local.response.http_status_code = 500
        frappe.log_error(f"Unexpected error: {e}", "Send Email OTP Error")
        return "An error occurred while sending the OTP. Please try again."


@frappe.whitelist(allow_guest=True)
def verify_email_otp(email, otp, need_login=False):
    try:
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

        if need_login:
            login_response = login_jwt_without_password(email)
            frappe.response["http_status_code"] = 201
            return {
                "success": True,
                "message": "Email OTP verified successfully and user logged in.",
                "Action_Required": "Login",
                **login_response,
            }

        login_response = login_jwt_without_password(email)
        frappe.response["http_status_code"] = 201
        return {
                "success": True,
                "message": "Email OTP verified successfully and user logged in.",
                "Action_Required": "Login",
                **login_response,
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


def get_user_summary(email):
    user = frappe.get_doc("User", email)
    avatar = user.user_image
    data = get_details_of_donor_donations(email)
    
    fundraiser = frappe.db.count('Project', {'project_type': 'Fundraiser', 'owner': email})

    return {
        "avatar": avatar,
        "total_invoices": data.get('total_invoices'),
        "last_invoice_date": data.get('last_invoice_date'),
        "fundraiser": fundraiser
    }


""" Send Mail for Reset Password"""      
@frappe.whitelist(allow_guest=True)
def forgot_password(email):
    """
    Handle forgot password functionality. Generates a reset password link if the user exists.
    """

    try:
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


def send_reset_password_email(email, link):
    try:
        frappe.sendmail(
            recipients=email,
            subject=f"Reset Your Password on SocialAngel",
            message=f"Click on the link to reset your password: {link}",
            now=True,
        )
        return {"success":True, "message": f"Reset link sent to your email address: {email}"}
    except Exception as e:
        frappe.log_error(
            message=f"Error sending reset password email: {str(e)}",
            title="Reset Password Email Error",
        )
        frappe.response.http_status_code = 500
        return  {"success": False, "message":f"An error occurred while sending the email. {str(e)}"}
    


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