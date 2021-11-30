from django.urls import path
from .views import (LoginView, RegisterView, EmailConfirmationView,
                    RequestNewEmailVerificationToken,
                    PasswordResetRequestView, ResetPasswordView,
                    ChangePasswordView)

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', EmailConfirmationView.as_view(), name='verify_email'),
    path('request-token/', RequestNewEmailVerificationToken.as_view(),
         name='request_token'),
    path('forget-password/', PasswordResetRequestView.as_view(),
         name='forget_password'),
    path('password-reset/', ResetPasswordView.as_view(), name='password_reset'),
    path('change-password/', ChangePasswordView.as_view(),
         name='change_password'),
]
