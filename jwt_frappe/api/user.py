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


# 
# <---------------- Check Email Existence ---------------->
# 

@frappe.whitelist(allow_guest=True)
def check_email_exists(email):
    try:
        email = str(email).strip().lower()
        # Check if the email exists in the User doctype
        exists = frappe.db.exists("Website User", {"email": email })
        return {"is_exist": bool(exists)}
    except Exception as e:
        frappe.log_error(message=str(e), title="Error Checking Email Existence")
        return {"error": str(e)}

# 
# <---------------- Check Phone Existence ---------------->
# 

@frappe.whitelist(allow_guest=True)
def check_phone_exists(number):
    """
    Checks if the provided phone number exists in the User DocType.
    """
    try:
        number = str(number).strip()
        # user = frappe.db.get_value("Website User", filters={"mobile_no": number}, fieldname=["name"])
        is_number_exists = frappe.db.exists("Website User", {"mobile_no": number })
        return {
            "is_exists": bool(is_number_exists)
        }
    except Exception as e:
        frappe.log_error(f"Error checking phone number existence: {str(e)}", "Check Phone Number Error")
        frappe.response.http_status_code = 500
        return {"error": str(e)}