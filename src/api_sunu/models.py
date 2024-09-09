from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager, User, Permission, Group
from django.utils import timezone
import random
import uuid


class CustomUserManager(BaseUserManager):
    def create_user(self, first_name, last_name, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")
        email = self.normalize_email(email)
        username = self.generate_unique_username(first_name, last_name)
        user = self.model(email=email, username=username, first_name=first_name, last_name=last_name, **extra_fields)
        user.set_password(password),
        user.save(using=self._db)
        return user

    def generate_unique_username(self, first_name, last_name):
        base_username = f"{first_name.lower()}.{last_name.lower()}"
        username = base_username
        while self.model.objects.filter(username=username).exists():
            username = f"{base_username}{random.randint(1, 999)}"
        return username


class Country(models.Model):
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=4, unique=True)

    def __str__(self):
        return self.name


class CustomUser(AbstractUser):
    groups = models.ManyToManyField(
        Group,
        related_name='customuser_set',
        blank=True
    )
    user_permissions = models.ManyToManyField(
        Permission,
        related_name='customuser_set_permissions',
        blank=True
    )
    email = models.EmailField(unique=True)
    country = models.ForeignKey(Country, on_delete=models.SET_NULL, null=True, blank=True)
    objects = CustomUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'email']

class PasswordResetToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.UUIDField(default=uuid.uuid4, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_expired(self):
        return self.created_at < timezone.now() - timezone.timedelta(hours=24)
    
    
""" class CustomUser(AbstractUser):
    email = models.EmailField(unique=True)
    country = models.CharField(max_length=100, blank=True, null=True)
    
    objects = BaseUserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    def is_global_admin(self):
        return self.is_staff and not self.country

    def is_territorial_admin(self):
        return self.is_staff and self.country """