from threading import Thread
from django.core.mail import EmailMessage


class EmailThread(Thread):
    def __init__(self, email):
        self.email = email
        assert isinstance(email, EmailMessage), 'The email should be an ' \
                                                'instance of ' \
                                                'django.core.mail.EmailMessage'
        Thread.__init__(self)

    def run(self):
        self.email.send()


class Email:
    @staticmethod
    def send_mail(data):
        email = EmailMessage(
                subject=data['subject'],
                body=data['body'],
                to=data['to'],
        )
        email.content_subtype = 'html'

        EmailThread(email=email).start()
