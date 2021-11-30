import jwt
from decouple import config
from django.utils import timezone
from django.template.loader import render_to_string
from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from ..serializers import (LoginUserSerializer, RegisterUserSerializer,
                           EmailConfirmationSerializer,
                           RequestPasswordResetSerializer,
                           ResetPasswordSerializer, ChangePasswordSerializer)
from ..tokens import VerificationToken, PasswordResetToken
from ...mail import Email

User = get_user_model()


class LoginView(APIView):
    serializer_class = LoginUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']

        user = authenticate(email=email, password=password)
        status_code = status.HTTP_200_OK
        response = {}
        if not user:
            status_code = status.HTTP_401_UNAUTHORIZED
            response = {'message': 'Invalid credentials'}

        if user:
            user.last_login = timezone.now()
            user.save()
            response = serializer.data
            response['username'] = user.username
            response['is_active'] = user.is_active
            response['is_verified'] = user.is_verified

        if user and not user.is_active:
            status_code = status.HTTP_403_FORBIDDEN
            response = {'message': 'User not active! Please contact admins.'}

        return Response(response, status=status_code)


class RegisterView(GenericAPIView):
    serializer_class = RegisterUserSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        send_verification_email_for_user(user)

        response = serializer.data
        # response['is_verified'] = user.is_verified
        response['message'] = f'Email Sent to {user.email}. Please continue ' \
                              f'verifying your email'
        return Response(response, status.HTTP_201_CREATED)


def send_verification_email_for_user(user):
    FRONTEND_ROOT_URL = config('FRONTEND_URL')
    frontend_url = f'{FRONTEND_ROOT_URL}/verify_email/?token='

    token = str(VerificationToken().for_user(user))
    abs_url = frontend_url + token
    data = {
        'subject': 'Email Verification',
        'body': render_to_string('email_template.html',
                                 {'token': token,
                                  'abs_url': abs_url}),
        'to': (user.email,)
    }
    Email.send_mail(data=data)


class EmailConfirmationView(GenericAPIView):
    http_method_names = ['post', ]
    serializer_class = EmailConfirmationSerializer

    def post(self, request, *args, **kwargs):
        # print(request.POST, request.GET)
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.data['token']
        # print(token)
        try:
            payload = VerificationToken().decode_token(token)
            try:
                user = User.objects.get(id=payload['user_id'])
            except User.DoesNotExist:
                return Response({'message': 'Invalid Token'},
                                status.HTTP_400_BAD_REQUEST)
            if not user.is_verified:
                user.is_verified = True
                user.save()
                return Response({'message': 'Email Verified'},
                                status.HTTP_200_OK)
            if user.is_verified:
                return Response({'message': 'User already verified!'},
                                status.HTTP_400_BAD_REQUEST)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) \
                as e:
            return Response({'message': str(e) + ' Please request a new verification code.'},
                            status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.ExpiredSignatureError as e:
            return Response({'message': str(e) + ' Please request a new verification code.'},
                            status.HTTP_400_BAD_REQUEST)


class RequestNewEmailVerificationToken(GenericAPIView):
    permission_classes = [IsAuthenticated, ]

    def get(self, request, *args, **kwargs):
        if not request.user.is_verified:
            send_verification_email_for_user(request.user)
            return Response({'message': f'Verification email sent to '
                                        f'{request.user.email}'},
                            status.HTTP_200_OK)
        else:
            return Response({'message': 'Email already verified!'},
                            status.HTTP_400_BAD_REQUEST)


class PasswordResetRequestView(GenericAPIView):
    serializer_class = RequestPasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data['email']
        response = {
            'success': True,
            'message': f'Password Reset email sent to {email}.'
        }
        return Response(response, status=status.HTTP_200_OK)


class ResetPasswordView(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        token = serializer.data['token']
        try:
            payload = PasswordResetToken().decode_token(token)
            try:
                user = User.objects.get(id=payload['user_id'])
            except User.DoesNotExist:
                return Response({'success': False,
                                 'message': 'User does not exist.'},
                                status.HTTP_400_BAD_REQUEST)
        except (jwt.exceptions.DecodeError, jwt.exceptions.InvalidTokenError) \
                as e:
            return Response({'success': False, 'message': str(e)},
                            status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.ExpiredSignatureError as e:
            return Response({'success': False, 'message': str(e)},
                            status.HTTP_400_BAD_REQUEST)
        changed_user = serializer.save(user)

        return Response({'success': True,
                         'message': f'Password successfully reset for '
                                    f'{changed_user.email}'},
                        status.HTTP_200_OK)


class ChangePasswordView(GenericAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated, ]

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        old_password = serializer.validated_data['old_password']

        if request.user.check_password(old_password):
            new_password = serializer.validated_data['new_password']
            request.user.set_password(new_password)
            request.user.save()
            return Response({'success': True, 'message': 'Password changed '
                                                         'successfully'},
                            status.HTTP_200_OK)
        else:
            return Response({'success': False, 'message': 'Old password '
                                                          'didn\'t match'},
                            status.HTTP_403_FORBIDDEN)
