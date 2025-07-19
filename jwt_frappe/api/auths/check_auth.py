import frappe
import re
from jwt_frappe.utils.constants import EMAIL_REGEX , PHONE_REGEX
from frappe import _

# 
# <---------------- Check Email Existence ---------------->
# 

@frappe.whitelist(allow_guest=True)
def check_email_exists(email):
    try:
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
        # Check if the email exists in the User doctype
        exists = frappe.db.exists("User", {"email": email })
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

        # user = frappe.db.get_value("Website User", filters={"mobile_no": number}, fieldname=["name"])
        is_number_exists = frappe.db.exists("User", {"phone": number })
        return {
            "is_exists": bool(is_number_exists)
        }
    except Exception as e:
        frappe.log_error(f"Error checking phone number existence: {str(e)}", "Check Phone Number Error")
        frappe.response.http_status_code = 500
        return {"error": str(e)}