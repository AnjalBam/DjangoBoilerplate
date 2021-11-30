import io
import hashlib
from uuid import uuid4

from rest_framework import serializers
from django.contrib.auth import get_user_model, authenticate
from django.core.files.base import ContentFile
from django.template.loader import render_to_string
from rest_framework.exceptions import AuthenticationFailed, ValidationError

from .tokens import PasswordResetToken
from ..mail import Email

USER = get_user_model()


class LoginUserSerializer(serializers.ModelSerializer):
    username = serializers.CharField(max_length=150, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    email = serializers.EmailField(max_length=255)
    is_verified = serializers.BooleanField(read_only=True)
    tokens = serializers.SerializerMethodField()
    # profile_pic = serializers.SerializerMethodField()

    class Meta:
        model = USER

        fields = ['email', 'password', 'username', 'tokens', 'is_verified',]

    @staticmethod
    def get_tokens(instance):
        user = USER.objects.get(email=instance['email'])
        return {
            'refresh_token': user.tokens()['refresh_token'],
            'access_token': user.tokens()['access_token']
        }

    # @staticmethod
    # def get_profile_pic(instance):
    #     user = USER.objects.get(email=instance['email'])
    #     return user.profile.profile_pics.get(is_active_pp=True).profile_pic.url

    def validate(self, attrs):
        email = attrs.get('email', '')
        password = attrs.get('password', '')

        if not email or not password:
            raise AuthenticationFailed('Either email or password is not '
                                       'provided')
        return attrs


class RegisterUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, write_only=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True)
    is_verified = serializers.BooleanField(default=False)
    tokens = serializers.SerializerMethodField()
    first_name = serializers.CharField(max_length=128)
    last_name = serializers.CharField(max_length=128)

    class Meta:
        model = USER
        fields = ['first_name', 'last_name', 'email', 'username', 'password',
                  'confirm_password', 'tokens', 'is_verified']

    def get_tokens(self, instance):
        user = USER.objects.get(email=instance['email'])
        return {
            'refresh_token': user.tokens()['refresh_token'],
            'access_token': user.tokens()['access_token']
        }

    def validate(self, attrs):
        for field in self.Meta.fields:
            if not field:
                raise ValidationError(f'{field} not provided')

        password = attrs['password']
        confirm_password = attrs['confirm_password']

        if not (password == confirm_password):
            raise ValidationError('Passwords do not match')

        attrs.pop('confirm_password')

        return super().validate(attrs)

    def save(self, commit=True):
        user = USER()
        user.first_name = self.validated_data['first_name']
        user.last_name = self.validated_data['last_name']
        user.email = self.validated_data['email']
        user.username = self.validated_data['username']
        password = self.validated_data['password']
        user.set_password(raw_password=password)
        user.save()

        return user


class EmailConfirmationSerializer(serializers.ModelSerializer):
    token = serializers.CharField(max_length=255)

    class Meta:
        model = USER
        fields = ['token']


class RequestPasswordResetSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()

    class Meta:
        model = USER
        fields = ['email', ]

    def validate(self, attrs):
        email = attrs.get('email', '')

        if not email:
            raise ValidationError('No email provided!')

        try:
            user = USER.objects.get(email=email)
            frontend_url = 'http://localhost:3000/reset-password/?token='

            token = str(PasswordResetToken().for_user(user))
            abs_url = frontend_url + token
            data = {
                'subject': 'Password Reset',
                'body': render_to_string('password_reset_email.html',
                                         {'token': token,
                                          'abs_url': abs_url}),
                'to': (user.email,)
            }
            Email.send_mail(data=data)
        except USER.DoesNotExist:
            raise ValidationError(f'User with email {email} does not exist')

        return attrs


class ResetPasswordSerializer(serializers.ModelSerializer):
    new_password = serializers.CharField(max_length=128, write_only=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255)

    class Meta:
        model = USER
        fields = ['new_password', 'confirm_password', 'token']

    def validate(self, attrs):
        new_password = attrs.get('new_password', '')
        confirm_password = attrs.get('confirm_password', '')
        token = attrs.get('token', '')

        if not new_password or not confirm_password:
            raise ValidationError('All fields should be provided!')

        if not token:
            raise ValidationError('Token not provided')

        if not (new_password == confirm_password):
            raise ValidationError('Passwords do not match. Please enter same '
                                  'password twice')

        return super().validate(attrs)

    def save(self, user: USER) -> USER:
        password = self.validated_data['new_password']
        user.set_password(password)
        user.save()
        return user


class ChangePasswordSerializer(serializers.ModelSerializer):
    old_password = serializers.CharField(max_length=128, write_only=True)
    new_password = serializers.CharField(max_length=128, write_only=True)
    confirm_password = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        model = USER
        fields = ['old_password', 'confirm_password', 'new_password']

    def validate(self, attrs):
        old_password = attrs.get('old_password', '')
        new_password = attrs.get('new_password', '')
        confirm_password = attrs.get('confirm_password', '')

        if not new_password or not confirm_password or not old_password:
            raise ValidationError('All fields should be provided!')

        if not (new_password == confirm_password):
            raise ValidationError('Passwords do not match. Please enter same '
                                  'password twice')

        return attrs
