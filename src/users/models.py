from django.db import models
from django.contrib.auth.models import AbstractUser
from django.contrib.auth.base_user import BaseUserManager

import uuid


class CustomUserManager(BaseUserManager):
    """
    Defines how the User model creates new users.
    """

    def create_user(self, username, email, password, **extra_fields):
        if not email:
            raise ValueError("The email must be set")
        email = self.normalize_email(email)

        user = self.model(
            username=username,
            email=email,
            **extra_fields,
        )

        user.set_password(password)
        user.save()

        return user

    def create_superuser(self, username, email, password, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True")

        return self.create_user(
            username,
            email,
            password,
            **extra_fields,
        )

    def create(self, username, email, password, **extra_fields):
        user = self.create_user(username, email, password, **extra_fields)

        return user


class Address(models.Model):
    city = models.CharField(max_length=128)
    postal_code = models.CharField(max_length=16, null=True, blank=True)

    def __str__(self):
        return self.city


class User(AbstractUser):
    uid = models.UUIDField(default=uuid.uuid4, editable=False)
    helper = models.BooleanField(default=False)
    seeker = models.BooleanField(default=False)
    email_verified = models.BooleanField(default=False)
    address = models.OneToOneField(
        Address,
        on_delete=models.CASCADE,
        null=True,
    )
    email = models.EmailField(unique=True, blank=True, verbose_name="email address")

    following = models.ManyToManyField(
        to="self",
        symmetrical=False,
    )

    # USERNAME_FIELD = "email"

    objects = CustomUserManager()

    def __str__(self):
        # If the user has a first and last name, return the full name.
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        # Otherwise, return the username.
        return self.username

