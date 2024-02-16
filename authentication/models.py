from datetime import datetime
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from .managers import CustomUserManager

#class Item(models.Model):
#    username = models.CharField(max_length = 20)
#    pass1 = models.CharField(max_length = 20)


class CustomUser(AbstractBaseUser, PermissionsMixin):

    uname = models.CharField(max_length = 20, unique = True)
    email = models.EmailField(_("email address"), unique=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(default=timezone.now)
    fname = models.CharField(max_length = 20)
    lname = models.CharField(max_length = 20)
    dob = models.DateField(null = True)
    public_visibility = models.BooleanField (default = True)
    
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    def __str__(self):
        return self.email
    
class FileUpload(models.Model):
    file_title = models.CharField(max_length = 30)
    file_desc = models.CharField(max_length = 100)
    cost = models.DecimalField(max_digits = 10,  decimal_places = 2, default = 0.00)
    year_published = models.IntegerField(null=True)
    file = models.FileField(upload_to="file/",max_length=250, null=True, default=None)