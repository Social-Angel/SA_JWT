import jwt
import frappe
from jwt.exceptions import ExpiredSignatureError, InvalidTokenError
from frappe.auth import LoginManager
import datetime


@frappe.whitelist(allow_guest=True)
def generate_jwt_token(user, expires_in=60):
    secret_key="your_secret_here"
    payload = {
        "sub": user,
        "name": "Vishal Kumar",
        "role": "Admin",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_in),
        "custom_data": {
            "flag": "jwt_frappe1",
            "extra": "your_custom_info"
        }
    }

    token = jwt.encode(payload, secret_key, algorithm="HS256")
    return token


@frappe.whitelist(allow_guest=True)
def decode_jwt_token(token, secret_key="your_secret_here"):
    try:
        if not token:
            return {"success": False, "message": "Token is required"}
        
        access_token = frappe.get_doc("OAuth Bearer Token", token)
        if not access_token:
            return {"success": False, "message": "Token not found"}
        
        decoded = jwt.decode(access_token.jwt_access_token, secret_key, algorithms=["HS256"])
        return {
            "success": True,
            "data": decoded
        }
    except jwt.ExpiredSignatureError:
        return {"success": False, "message": "Token has expired"}
    except jwt.InvalidTokenError:
        return {"success": False, "message": "Invalid token"}