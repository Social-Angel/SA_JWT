import frappe
from frappe import _
import frappe
from jwt_frappe.utils.constants import EMAIL_REGEX



# True
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
        # Clear the token from the database
        token_doc = frappe.get_doc("OAuth Bearer Token", token)
        if not token_doc:
            frappe.response["http_status_code"] = 401
            return {"message": "Unauthorized access. Token not found."}

        token_doc.delete(ignore_permissions=True)
        frappe.db.commit()

        return {"message": "Logged out successfully"}

    except Exception as e:
        frappe.log_error(frappe.get_traceback(), "JWT Logout Error")
        frappe.throw(_("Failed to logout"))
