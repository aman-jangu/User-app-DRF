from django.db import models
from django.contrib.auth.models import AbstractUser
from django.conf import settings
# Create your models here.

class User(AbstractUser):
    username = models.CharField(unique=True, max_length=50)
    email = models.EmailField(unique=True)
    address = models.CharField(max_length=200, null=True, blank=True)
    USERNAME_FIELD = 'username'
    def __str__(self):
        return self.email