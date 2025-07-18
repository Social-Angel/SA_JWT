import frappe
 

# 
# <---------------- Check Email Existence ---------------->
# 

@frappe.whitelist(allow_guest=True)
def check_email_exists(email):
    try:
        email = str(email).strip().lower()
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
        # user = frappe.db.get_value("Website User", filters={"mobile_no": number}, fieldname=["name"])
        is_number_exists = frappe.db.exists("User", {"phone": number })
        return {
            "is_exists": bool(is_number_exists)
        }
    except Exception as e:
        frappe.log_error(f"Error checking phone number existence: {str(e)}", "Check Phone Number Error")
        frappe.response.http_status_code = 500
        return {"error": str(e)}