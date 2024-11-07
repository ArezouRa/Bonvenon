from django.urls import path

from rest_framework_simplejwt.views import TokenRefreshView


from users.views import (
    CustomObtainPairView,
    UserRegistration,
    ChangePasswordView,
    UserView,
    LogoutAPIView,
    UserUpdateView,
    UserFollowView,
    EmailVerification,
)


app_name = "users"
urlpatterns = [
    path(
        "login/",
        CustomObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "login/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "register/",
        UserRegistration.as_view(),
        name="register",
    ),
    path(
        "change_password/",
        ChangePasswordView.as_view(),
        name="change_password",
    ),
    path(
        "",
        UserView.as_view(),
        name="user",
    ),
    path("follow/", UserFollowView.as_view(), name="follow"),
    path("update/", UserUpdateView.as_view(), name="update"),
    path("logout/", LogoutAPIView.as_view(), name="logout"),
    path("verify/", EmailVerification.as_view(), name="verify_email"),
]
