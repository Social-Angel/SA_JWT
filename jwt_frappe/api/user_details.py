import frappe
from frappe.utils import get_url
from frappe import _
# from jwt_frappe.utils.auth import decode_token


#  in feature this method is not required
def get_dashboard_data(data):
    dashboard_data = {
        "fieldname": "user",
        "non_standard_fieldnames": {
            "ToDo":     "allocated_to",
            "Donor":  "email_address",
            "Donation":  "donor_email",
            "Razorpay Transaction": "email",
            "Lead": "email_id",
            "Customer": "custom_customer_email"
        },
        "internal_links": {
            "Supplier": ["portal_users", "user"],
            "Project":  ["users", "user"],	    
            
        },
        "transactions": [
            {"label": _("Profile"),      "items": ["Contact", "Blogger","Supplier","Project"]},
            {"label": _("Logs"),         "items": ["Access Log", "Activity Log", "Energy Point Log", "Route History"]},
            {"label": _("Settings"),     "items": ["User Permission", "Document Follow"]},
            {"label": _("Activity"),     "items": ["Communication", "ToDo"]},
            {"label": _("Integrations"), "items": ["Token Cache","Aadhar Card","PAN Card"]},
            {"label": _("Transactions"), "items": ["Donation", "Razorpay Transaction", "Donor", "Lead", "Order Cart", "Customer"]},
        ],
    }
    return dashboard_data



@frappe.whitelist(allow_guest=True)
def get_token_details(token):
    """
    Get user and token info from a valid access_token.
    """
    token_doc = frappe.get_doc("OAuth Bearer Token", token)

    # Check if expired
    if token_doc.expiration_time and frappe.utils.now_datetime() > token_doc.expiration_time:
        frappe.throw("Token has expired")

    return {
        "user": token_doc.user,
        "scopes": token_doc.scopes,
        "expires_in": int((token_doc.expiration_time - frappe.utils.now_datetime()).total_seconds()),
        "client": token_doc.client,
        "custom_data": token_doc.get("custom_data") or {},
    }



# 
# <---------------- Check Email Existence ---------------->
# 

@frappe.whitelist(allow_guest=True)
def check_email_exists(email):
    try:
        # Check if the email exists in the User doctype
        exists = frappe.db.exists("User", {"email": email})
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
        user = frappe.db.get_value("User", filters={"phone": number}, fieldname=["name"])
        is_number_exists = frappe.db.exists("User", {"phone": number})
        return {
            "is_exists": bool(is_number_exists)
        }
    except Exception as e:
        frappe.log_error(f"Error checking phone number existence: {str(e)}", "Check Phone Number Error")
        frappe.response.http_status_code = 500
        return {"error": str(e)}