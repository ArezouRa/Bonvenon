from django.contrib import admin
from messaging.models import Message, Communication

# Register your models here.
admin.site.register(Message)
admin.site.register(Communication)
