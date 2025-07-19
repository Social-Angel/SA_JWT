import frappe
from frappe import _
from frappe.auth import LoginManager
from jwt_frappe.utils.auth import get_bearer_token
import requests
from jwt_frappe.utils.constants import EMAIL_REGEX
from jwt_frappe.domain.auth_domain import login_jwt_without_password 
import re




# True 
# Api 1
@frappe.whitelist(allow_guest=True)
def login_jwt(usr, pwd, uuid=None, expires_in=60, expire_on=None, device=None):
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
        if not re.match(EMAIL_REGEX, usr):
            frappe.log_error(
                message=f"Invalid email format: {usr.lower()}",
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
        # If uuid is provided, update the device information
        if uuid:
            frappe.db.set_value("Website Visitor", {"uuid": uuid}, "website_user", usr)
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
    
# Api 9
@frappe.whitelist(allow_guest=True)
def login_with_google(code, uuid=None):
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
        image_url = ""  # userinfo.get("picture", "default_image_url.jpg")

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
            if uuid:
                frappe.db.set_value(
                    "Website Visitor", {"uuid": uuid}, "website_user", email
                )
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
                if uuid:
                    frappe.db.set_value(
                        "Website Visitor", {"uuid": uuid}, "website_user", email
                    )
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
                if uuid:
                    frappe.db.set_value(
                        "Website Visitor", {"uuid": uuid}, "website_user", email
                    )
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
