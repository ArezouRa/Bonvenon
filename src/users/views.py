from rest_framework import permissions, status, generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.http import Http404
from users.models import User

from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from users.tokens import account_activation_token
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings


from users.serializers import (
    CustomObtainPairSerializer,
    UserRegisterSerializer,
    ChangePasswordSerializer,
    UserInfoSerializer,
    LogoutSerializer,
    UserUpdateSerializer,
    UserFollowSerializer,
    EmailTokenSerializer,
)


class CustomObtainPairView(TokenObtainPairView):
    """
    Obtain JWT token pair using a custom serializer
    that includes the username.
    """

    permission_classes = [permissions.AllowAny]
    serializer_class = CustomObtainPairSerializer


class LogoutAPIView(generics.GenericAPIView):
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(status=status.HTTP_204_NO_CONTENT)


class UserRegistration(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """
        User registration.
        """
        data = {
            "username": request.data.get("username"),
            "email": request.data.get("email"),
            "password": request.data.get("password"),
            "password2": request.data.get("password2"),
        }
        serializer = UserRegisterSerializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"msg": "User was created"},
                status=status.HTTP_201_CREATED,
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(
            {"message": "Password successfully changed."},
            status=status.HTTP_202_ACCEPTED,
        )


class UserView(APIView):
    """
    Retrieve information about currently authenticated user.
    """

    def get_user(self, request):
        try:
            return User.objects.get(pk=request.user.id)
        except User.DoesNotExist:
            return Http404

    def get(self, request, format=None):
        user = self.get_user(request=request)

        serializer = UserInfoSerializer(user)

        return Response(serializer.data)

    def delete(self, request, format=None):
        user = self.get_user(request=request)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserUpdateView(APIView):
    def patch(self, request):
        user = request.user

        # Serialize the incoming data, allowing partial updates
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(
                {"msg": "User Account has been updated"}, status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserFollowView(APIView):
    def post(self, request):
        if request.user.username != request.data.get("current_username"):
            return Response(
                {"msg": "Cannot change followers for other users"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        serializer = UserFollowSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"msg": "User successful added to followed users"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerification(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request):
        """Send out verification email including a random token"""
        if not request.user.is_authenticated:
            return Response(
                data={"msg": "Not logged in"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not request.user.email_verified:
            user = request.user
            email = request.user.email
            subject = "Verify Email"
            message = render_to_string(
                "users/verify_email_message.html",
                {
                    "request": request,
                    "user": user,
                    "token": account_activation_token.make_token(user),
                    "uid": urlsafe_base64_encode(force_bytes(user.uid)),
                },
            )
            email = EmailMessage(
                subject,
                message,
                to=[email],
                from_email=settings.DEFAULT_FROM_EMAIL,
            )
            email.content_subtype = "html"
            email.send()
            return Response(
                {"msg": "Email verification link sent"},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"msg": "Email already verified"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def put(self, request):
        """If valid token, set email_verified to True"""
        serializer = EmailTokenSerializer(
            data=request.data,
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"msg": "Verification successful"},
                status=status.HTTP_200_OK,
            )
        return Response(status=status.HTTP_400_BAD_REQUEST)
