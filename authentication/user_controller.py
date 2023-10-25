from .serializers import *
from utils.helpers import *
from authentication.models import User
from django.core.mail import send_mail
from django.utils import timezone
import threading
from AUTH.settings import EMAIL_HOST_USER
from django.contrib.auth import authenticate
from authentication.models import Token
from utils.responses import *
class LoginController:
    feature_name = "Auth"

    serializer_class = LoginSerializer

    def post(self, request):
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the email and password
        request.data["email"] = request.data.get("email", "").strip()
        request.data["password"] = request.data.get("password", "").strip()
        # make the request data mutable
        request.POST._mutable = False
        email = request.data.get("email")
        password = request.data.get("password")
        print(email)
        print(password)
        # create the serializer instance
        serialized_data = self.serializer_class(data=request.data)
        # check if the data is valid
        if not serialized_data.is_valid():
            # if not valid return an error message
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   status_code=401)
        # authenticate user
        user = authenticate(username=request.data.get("email"), password=request.data.get("password"))
        if not user:
            # if not valid user return an error message
            return create_response({}, message=INCORRECT_EMAIL_OR_PASSWORD, status_code=401)
        # prepare response data
        response_data = {
            "token": user.get_access_token(),
            "name": user.first_name,
            "user_id": user.pk
        }
        # update or create token
        Token.objects.update_or_create(defaults={"token": response_data.get("token")}, user_id=user.pk)
        user.last_login = timezone.now()
        user.save()

        # return success message
        return create_response(response_data, SUCCESSFUL, status_code=200)


class ChangePasswordController:
    feature_name = "Change Password"
    """
    An endpoint for changing password.
    """

    serializer_class = ChangePasswordSerializer

    def update(self, request):
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the passwords
        request.data["old_password"] = request.data.get("old_password").strip()
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        # make the request data mutable
        request.POST._mutable = True
        # create the serializer instance
        serializer = self.serializer_class(data=request.data, context={"user": request.user})
        # check if the data is valid
        if not serializer.is_valid():
            # If the data is not valid, return a response with the errors
            return create_response({}, get_first_error_message_from_serializer_errors(serializer.errors, UNSUCCESSFUL),
                                   status_code=400)
        # check if the new password and confirm password match
        if request.data.get('new_password') != request.data.get('confirm_password'):
            # if not match return error message
            return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)

        # Check old password
        if not request.user.check_password(request.data.get("old_password")):
            # if the old password is incorrect return error message
            return create_response({}, message=INCORRECT_OLD_PASSWORD, status_code=400)

        # set_password also hashes the password that the users will get
        request.user.set_password(request.data.get("new_password"))
        request.user.save()
        # logs_controller.create_logs(feature=self.feature_name, operation=OperationType.UPDATED, user=request.user)
        # return success message
        return create_response({}, SUCCESSFUL, status_code=200)


class ForgetPasswordController:
    feature_name = "Forget Password"
    serializer_class = ForgetPasswordSerializer

    def forget_password(self, request):
        # Deserialize the request data using the defined serializer
        serialized_data = self.serializer_class(data=request.data)
        # check if the request data is valid
        if not serialized_data.is_valid():
            # if invalid return an error message
            return create_response({},
                                   get_first_error_message_from_serializer_errors(serialized_data.errors, UNSUCCESSFUL),
                                   401)
        try:
            # Try to filter the user with the provided email
            user = User.objects.filter(email=request.data.get("email")).first()
            if not user:
                # if user not found return an error message
                return create_response({}, USER_NOT_FOUND, status_code=404)
            # generate OTP
            otp = generate_six_length_random_number()
            user.otp = otp
            user.otp_generated_at = timezone.now()
            user.save()
            # Prepare the email subject and message
            subject = "Password Recovery Request"
            message = f"""
                Hi {user.first_name} {user.last_name},
                Your request for password recovery has been received.
                Please use the following otp.
                OTP: {otp}
                """

            recipient_list = [request.data.get("email")]
            # Send the email
            t = threading.Thread(target=send_mail, args=(subject, message, EMAIL_HOST_USER, recipient_list))
            t.start()
            # logs_controller.create_logs(feature=self.feature_name, operation=OperationType.UPDATED, user=user)
            # return success message
            return create_response({}, EMAIL_SUCCESSFULLY_SENT, status_code=200)
        except Exception as e:
            # print the error message
            print(e)
            # return error message
            return create_response({}, e, status_code=500)


class VerifyOtpController:
    feature_name = "Reset Password"
    serializer_class = VerifyOtpSerializer

    def verify(self, request):
        # make the request data mutable
        request.POST._mutable = True
        # strip whitespace from the passwords
        request.data["new_password"] = request.data.get("new_password").strip()
        request.data["confirm_password"] = request.data.get("confirm_password").strip()
        # make the request data mutable
        request.POST._mutable = True
        try:
            # check OTP time delay
            time_delay = timezone.now() - timezone.timedelta(seconds=300)
            user = User.objects.filter(otp=request.data.get("otp"), otp_generated_at__gt=time_delay).first()
            if not user:
                # if not valid OTP return an error message
                return create_response({}, INVALID_OTP, status_code=404)
            # create the serializer instance
            serialized_data = self.serializer_class(data=request.data, context={"user": user})
            # check if the data is valid
            if not serialized_data.is_valid():
                # if not valid return an error message
                return create_response({}, get_first_error_message_from_serializer_errors(serialized_data.errors,
                                                                                          UNSUCCESSFUL), 401)
            # check if the new password and confirm password match
            if request.data.get('new_password') != request.data.get('confirm_password'):
                # if not match return error message
                return create_response({}, message=PASSWORD_DOES_NOT_MATCH, status_code=403)
            # set new password
            user.set_password(request.data.get("new_password"))
            # clear OTP
            user.otp = None
            user.save()
            # logs_controller.create_logs(feature=self.feature_name, operation=OperationType.UPDATED, user=user)
            # return success message
            return create_response({}, SUCCESSFUL, status_code=200)
        except Exception as e:
            print(e)
            return create_response({}, e, status_code=500)