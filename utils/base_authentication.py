from rest_framework.authentication import BaseAuthentication
from django.views.decorators.csrf import csrf_exempt
from authentication.models import Token
import jwt
from utils.helpers import *
from rest_framework import exceptions

class JWTAuthentication(BaseAuthentication):
    """
        custom authentication class for DRF and JWT
        https://github.com/encode/django-rest-framework/blob/master/rest_framework/authentication.py
    """

    @csrf_exempt
    def authenticate(self, request):
        authorization_header = request.headers.get('Authorization')
        if not authorization_header:
            raise exceptions.AuthenticationFailed('Token not provided')
        try:
            access_token = authorization_header.split(' ')[1]
            if not Token.objects.filter(token=access_token).exists():
                raise SessionExpired()
            access_token = decrypt_token(access_token)
            payload = jwt.decode(access_token, settings.JWT_ENCODING_SECRET_KEY, algorithms=['HS256'])
        except IndexError:
            raise exceptions.AuthenticationFailed('Token prefix missing')
        except jwt.ExpiredSignatureError:
            raise SessionExpired()
        except jwt.InvalidTokenError:
            raise exceptions.NotAcceptable('Invalid token')

        from authentication.models import User
        user = User.objects.filter(email=payload['email']).first()
        if user is None:
            raise exceptions.AuthenticationFailed('Invalid User.')
        return user, None

