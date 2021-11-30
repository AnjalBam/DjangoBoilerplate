import jwt
from datetime import timedelta
from django.conf import settings
from rest_framework_simplejwt.tokens import Token

token_verification_lifetime = timedelta(minutes=30)
password_reset_token_lifetime = timedelta(minutes=10)


class VerificationToken(Token):
    lifetime = token_verification_lifetime
    token_type = 'verification'
    algorithms = ["HS256"]
    signing_key = settings.SECRET_KEY

    def decode_token(self, token):
        payload = jwt.decode(token, self.signing_key,
                             algorithms=self.algorithms)
        return payload


class PasswordResetToken(VerificationToken):
    lifetime = password_reset_token_lifetime


