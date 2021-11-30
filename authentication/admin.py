from django.contrib import admin
from .models import User

@admin.register(User)
class AdminUser(admin.ModelAdmin):
    list_display = ('username','get_full_name',  'email')
    list_filter = ('username', 'email')