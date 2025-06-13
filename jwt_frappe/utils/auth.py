import random

import frappe
import jwt
from frappe import _
from frappe.auth import LoginManager
from frappe.utils import cint, get_url, get_datetime
from frappe.utils.password import check_password, passlibctx, update_password


def get_linked_user(id_type, id):
    """
    Returns the user associated with the details
    :param id_type: either 'mobile' or 'email'
    :param id: the email/mobile
    """
    if id_type not in ("mobile", "sms", "email"):
        frappe.throw(f"Invalid id_type: {id_type}")

    if id_type in ("mobile", "sms"):
        id_type = "mobaile_no"

    return frappe.db.get_value("User", {id_type: id})


@frappe.whitelist(allow_guest=True)
def get_token(user, pwd, expires_in=60, expire_on=None, device=None):
    """
    Get the JWT Token
    :param user: The user in ctx
    :param pwd: Pwd to auth
    :param expires_in: number of seconds till expiry
    :param expire_on: yyyy-mm-dd HH:mm:ss to specify the expiry (deprecated)
    :param device: The device in ctx
    """
    if not frappe.db.exists("User", user):
        raise frappe.ValidationError(_("Invalide User"))

    from frappe.sessions import clear_sessions

    login = LoginManager()
    login.check_if_enabled(user)
    if not check_password(user, pwd):
        login.fail("Incorrect password", user=user)
    login.login_as(user)
    login.resume = False
    login.run_trigger("on_session_creation")
    _expires_in = 60
    if cint(expires_in):
        _expires_in = cint(expires_in)
    elif expire_on:
        _expires_in = (get_datetime(expire_on) - get_datetime()).total_seconds()

    token = get_bearer_token(user=user, expires_in=_expires_in)
    frappe.local.response["token"] = token["access_token"]
    frappe.local.response.update(token)


def get_oath_client():
    client = frappe.db.get_value("OAuth Client", {})
    if not client:
        # Make one auto
        client = frappe.get_doc(
            frappe._dict(
                doctype="OAuth Client",
                app_name="default",
                scopes="all openid",
                redirect_urls=get_url(),
                default_redirect_uri=get_url(),
                grant_type="Implicit",
                response_type="Token",
            )
        )
        client.insert(ignore_permissions=True)
    else:
        client = frappe.get_doc("OAuth Client", client)

    return client


def get_bearer_token(user, expires_in=60):
    import hashlib
    import jwt
    import frappe.oauth
    from oauthlib.oauth2.rfc6749.tokens import random_token_generator, OAuth2Token

    client = get_oath_client()
    token = frappe._dict(
        {
            "access_token": random_token_generator(None),
            "expires_in": expires_in,
            "token_type": "Bearer",
            "scopes": client.scopes,
            "refresh_token": random_token_generator(None),
            "custom_data": {
                "flag": "jwt_frappe1",
                # "role": frappe.db.get_value("User", user, "role"),
                # "permissions": ["read", "write"]
            },
        }
    )
    bearer_token = frappe.new_doc("OAuth Bearer Token")
    bearer_token.client = client.name
    bearer_token.scopes = token["scopes"]
    bearer_token.access_token = token["access_token"]
    bearer_token.refresh_token = token.get("refresh_token")
    bearer_token.expires_in = token["expires_in"] or 60
    bearer_token.user = user
    bearer_token.save(ignore_permissions=True)
    frappe.db.commit()

    # ID Token
    id_token_header = {"typ": "jwt", "alg": "HS256"}
    id_token = {
        "aud": "token_client",
        "exp": int(
            (
                frappe.db.get_value(
                    "OAuth Bearer Token", token.access_token, "expiration_time"
                )
                - frappe.utils.datetime.datetime(1970, 1, 1)
            ).total_seconds()
        ),
        "sub": frappe.db.get_value(
            "User Social Login",
            {"parent": bearer_token.user, "provider": "frappe"},
            "userid",
        ),
        "iss": "frappe_server_url",
        "at_hash": frappe.oauth.calculate_at_hash(token.access_token, hashlib.sha256),
    }
    id_token_encoded = jwt.encode(
        id_token, "client_secret", algorithm="HS256", headers=id_token_header
    )
    print("ID Token Encoded:", id_token_encoded)
    id_token_encoded = frappe.safe_decode(id_token_encoded)
    token.id_token = id_token_encoded
    frappe.flags.jwt = id_token_encoded
    print("Generated ID Token:", id_token)
    return token


@frappe.whitelist()
def get_jwt_token():
    token = get_bearer_token(user=frappe.session.user, expires_in=60)
    print("JWT Token2:", token["id_token"] )
    return token["id_token"]  



@frappe.whitelist()
def decode_token(encoded_token):
    
    """
    Decodes and validates the provided JWT token.
    :param encoded_token: JWT token
    :return: Decoded custom data if valid, else raises an error
    """
    try:
        # Decode the token
        decoded_token = jwt.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6Imp3dCJ9.eyJhdWQiOiJ0b2tlbl9jbGllbnQiLCJleHAiOjE3NDk4MzA3MzMsInN1YiI6ImE3YzAwODJiNGUyMWM0NDIzZjZmYzFkYTNjY2M1Mzk5MGJlYjE2OSIsImlzcyI6ImZyYXBwZV9zZXJ2ZXJfdXJsIiwiYXRfaGFzaCI6InF6WW1GNDh1X2NjZ3p1NDR4OVFrbncifQ.wEiJVojywBeokKXE2knx4ZuE1cZctPmJL7cVlH5uqsU", "client_secret", algorithms=["HS256"])
        print("Decoded Token:", decoded_token)
        # Validate token expiration
        if "exp" in decoded_token:
            current_time = frappe.utils.datetime.datetime.utcnow()
            expiration_time = frappe.utils.datetime.datetime.utcfromtimestamp(
                decoded_token["exp"]
            )
            if current_time > expiration_time:
                frappe.throw(_("Token has expired"))
                # return {"success": False, "message": _("Token has expired")}

        # Validate required fields in the token
        if not decoded_token.get("sub") or not decoded_token.get("aud"):
            frappe.throw(_("Invalid token structure"))
            # return {"success": False, "message": _("Invalid token structure")}

        # Return custom data
        custom_data = decoded_token.get("custom_data")
        return {
            "success": True,
            "custom_data": custom_data,
        }

    except jwt.ExpiredSignatureError:
        frappe.throw(_("Token has expired"))
    except jwt.InvalidTokenError:
        frappe.throw(_("Invalid token"))
    except Exception as e:
        frappe.log_error(message=str(e), title="Error Decoding Token")
        frappe.throw(_("An error occurred while decoding the token"))
