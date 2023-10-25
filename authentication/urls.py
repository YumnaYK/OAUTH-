from django.urls import path
from authentication.views import *

urlpatterns = [
    path('login', LoginAPIView.as_view({"post": "post"})),
    path('change-password', ChangePasswordAPI.as_view({"post": "patch"})),
    path('forget-password', ForgetPasswordAPI.as_view({"post": "post"})),
    path('verify-otp', VerifyOtpAPI.as_view({"post": "post"})),
]