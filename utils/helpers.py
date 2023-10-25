import jwt
import datetime
from AUTH import settings
from cryptography.fernet import Fernet
from rest_framework.response import Response
from rest_framework.utils.serializer_helpers import ReturnList
import random
from rest_framework.exceptions import APIException
from rest_framework import status
def encrypt_token(token):
    """Encrypt the jwt token so users cannot see token content

    Args:
        token ([str]): [The jwt token]

    Returns:
        [str]: [The encrypted jwt token string]
    """
    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.encrypt(token.encode()).decode("utf-8")

def decrypt_token(encrypted_token):
    """Decrypt the encrypted token string to get the original jwt token

    Args:
        encrypted_token ([str]): [The encrypted jwt token string]

    Returns:
        [str]: [The jwt token]
    """

    secret_key_bytes = b"LD7i4Pe_VDdXhRyHSQrQe3RpIJ8RymjbU_zA0Yi4Hlg="
    fernet = Fernet(secret_key_bytes)
    return fernet.decrypt(encrypted_token.encode()).decode()

def generate_access_token(user):
    # nbf: Defines the time before which the JWT MUST NOT be accepted for processing
    access_token_payload = {
        'email': user.email,
        'iat': datetime.datetime.utcnow(),
        # 'role': users.role
    }
    exp_claim = {
        "exp": access_token_payload.get("iat") + datetime.timedelta(seconds=int(settings.JWT_TOKEN_EXPIRY_DELTA))}
    # Add expiry claim to token_payload
    token_payload = {**access_token_payload, **exp_claim}
    encoded_token = jwt.encode(token_payload, settings.JWT_ENCODING_SECRET_KEY, algorithm='HS256')
    jwt_token = encrypt_token(encoded_token)
    return jwt_token

def create_response(data, message, status_code):
    result = {
        "status_code": status_code,
        "message": message,
        "data": data
    }
    return Response(result, status=status_code)

def get_first_error_message_from_serializer_errors(serialized_errors, default_message=""):
    if not serialized_errors:
        return default_message
    try:

        serialized_error_dict = serialized_errors

        # ReturnList of serialized_errors when many=True on serializer
        if isinstance(serialized_errors, ReturnList):
            serialized_error_dict = serialized_errors[0]

        serialized_errors_keys = list(serialized_error_dict.keys())
        # getting first error message from serializer errors
        try:
            message = serialized_error_dict[serialized_errors_keys[0]][0].replace("This", serialized_errors_keys[0])
            return message
        except:
            return serialized_error_dict[serialized_errors_keys[0]][0]

    except Exception as e:
        # logger.error(f"Error parsing serializer errors:{e}")
        return default_message


def generate_six_length_random_number():
    random_number = random.SystemRandom().randint(100000, 999999)
    return random_number

class SessionExpired(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_detail = {'data': {}, 'message': 'Session Expired'}
    default_code = 'not_authenticated'