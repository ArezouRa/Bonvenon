from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase, APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from users.models import User, Address
from django.test import TestCase
from django.test import Client
from unittest.mock import patch, ANY

from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from users.tokens import account_activation_token
import json
from django.conf import settings


class LogoutAPIViewTest(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", password="testpassword", email="test@test.com"
        )
        self.refresh = RefreshToken.for_user(self.user)
        self.client = APIClient()
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.refresh.access_token}"
        )
        self.logout_url = reverse("users:logout")

    def test_logout(self):
        response = self.client.post(self.logout_url, {"refresh": str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_logout_invalid(self):
        response = self.client.post(self.logout_url, {"refresh": "alkgflg8uz0p3qhgq"})

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_double_logout(self):
        response = self.client.post(self.logout_url, {"refresh": str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

        response = self.client.post(self.logout_url, {"refresh": str(self.refresh)})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestUserModel(TestCase):
    def test_user_creation_valid(self):
        User.objects.create_user(
            username="test_user",
            email="test_user@mail.com",
            password="test_password",
        )
        user = User.objects.get(username="test_user")
        self.assertEqual(user.username, "test_user")
        self.assertEqual(user.email, "test_user@mail.com")
        self.assertNotEqual(user.password, "test_password")
        self.assertTrue(user.check_password("test_password"))
        self.assertFalse(user.email_verified)
        self.assertFalse(user.seeker)
        self.assertFalse(user.helper)

    def test_user_creation_no_email(self):
        # TODO: add message checks
        with self.assertRaises(TypeError):
            User.objects.create_user(
                username="test_user",
                password="test_user_password",
            )

    def test_user_creation_no_password(self):
        # TODO: add message checks
        with self.assertRaises(TypeError):
            User.objects.create_user(
                username="test_user",
                email="test_user@mail.com",
            )

    def test_user_creation_no_username(self):
        # TODO: add message checks
        with self.assertRaises(TypeError):
            User.objects.create_user(
                email="test_user@mail.com",
                password="test_user_password",
            )


class TestLogin(TestCase):
    def setUp(self):
        self.client = Client()

        User.objects.create_user(
            username="test_user",
            email="test_user@mail.com",
            password="test_user_password",
        )
        self.login_url = reverse("users:token_obtain_pair")
        self.login_refresh_url = reverse("users:token_refresh")

    def test_login_valid_credentials(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "test_user_password",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue("refresh" in response.data.keys())
        self.assertTrue("access" in response.data.keys())

    def test_login_invalid_username(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "testuser",
                "password": "test_user_password",
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data.get("detail"),
            "No active account found with the given credentials",
        )

    def test_login_invalid_password(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "testuserpassword",
            },
        )

        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.data.get("detail"),
            "No active account found with the given credentials",
        )

    def test_refresh_valid_key(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "test_user_password",
            },
        )

        refresh = response.data.get("refresh")

        refresh_request = self.client.post(
            self.login_refresh_url,
            data={"refresh": refresh},
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue("access" in refresh_request.data.keys())

    def test_refresh_invalid_key(self):
        # TODO: add more "types" of token being invalid
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "test_user_password",
            },
        )

        # To get a JWT token that is invalid
        # for this operation, use the access
        # token instead:
        access = response.data.get("access")

        refresh_request = self.client.post(
            self.login_refresh_url,
            data={"refresh": access},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            refresh_request.data.get("detail"),
            "Token has wrong type",
        )


class TestRegistration(TestCase):
    def setUp(self):
        self.client = Client()

        User.objects.create_user(
            username="test_user2",
            email="test_user2@mail.com",
            password="test_password",
        )

        self.register_url = reverse("users:register")

    # TODO: maybe add check whether received token is a JWT token
    def test_registration(self):
        response = self.client.post(
            self.register_url,
            {
                "username": "test_user",
                "email": "test_user@mail.com",
                "password": "test_user_password",
                "password2": "test_user_password",
            },
        )

        self.assertEqual(response.status_code, 201)

        self.assertEqual(
            response.data.get("msg"),
            "User was created",
        )

    def test_registration_different_passwords(self):
        response = self.client.post(
            self.register_url,
            {
                "username": "test_user",
                "email": "test_user@mail.com",
                "password": "test_user",
                "password2": "test_user_password",
            },
        )
        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            str(response.data.get("non_field_errors")[0]),
            "Entered passwords do not match",
        )

    def test_registration_invalid_email(self):
        response = self.client.post(
            self.register_url,
            {
                "username": "test_user",
                "email": "test_user@mail",
                "password": "test_user_password",
                "password2": "test_user_password",
            },
        )
        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            str(response.data.get("email")[0]),
            "Enter a valid email address.",
        )

    def test_registration_username_taken(self):
        response = self.client.post(
            self.register_url,
            {
                "username": "test_user2",
                "email": "test_user@mail.com",
                "password": "test_user_password",
                "password2": "test_user_password",
            },
        )
        self.assertEqual(response.status_code, 400)

        self.assertEqual(
            str(response.data.get("username")[0]),
            "A user with that username already exists.",
        )


class TestUserInfo(TestCase):
    def setUp(self):
        self.client = Client()

        address = Address.objects.create(city="New York", postal_code="12345")

        User.objects.create_user(
            username="test_user",
            email="test_user@mail.com",
            password="test_user_password",
            address=address,
        )
        self.user_url = reverse("users:user")
        self.login_url = reverse("users:token_obtain_pair")

    def test_user_info(self):
        login = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "test_user_password",
            },
        )

        access = login.data.get("access")

        response = self.client.get(
            self.user_url, headers={"Authorization": f"Bearer {access}"}
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.get("username"),
            "test_user",
        )
        self.assertEqual(
            response.data.get("email"),
            "test_user@mail.com",
        )
        self.assertFalse(response.data.get("seeker"))
        self.assertFalse(response.data.get("helper"))
        self.assertEqual(
            response.data.get("address"),
            {"city": "New York", "postal_code": "12345"},
        )

    def test_user_delete(self):
        login = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "test_user_password",
            },
        )

        access = login.data.get("access")

        response = self.client.delete(
            self.user_url, headers={"Authorization": f"Bearer {access}"}
        )

        user = User.objects.filter(username="test_user")

        self.assertEqual(response.status_code, 204)
        self.assertEqual(response.data, None)
        self.assertEqual(len(user), 0)


class UserUpdateTestCase(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser5",
            password="testpassword5",
            email="testuser5@example.com",
        )

        self.user2 = User.objects.create_user(
            username="otheruser",
            password="otherpassword",
            email="otheruser@example.com",
        )

        response = self.client.post(
            reverse("users:token_obtain_pair"),
            {"username": "testuser5", "password": "testpassword5"},
            format="json",
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.token = response.data["access"]

        self.url = reverse("users:update")

        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {self.token}")

    def test_update_email(self):
        data = {"email": "update@test.com"}
        response = self.client.patch(self.url, data, format="json")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.username, "testuser5")
        self.assertEqual(self.user.email, "update@test.com")
        self.assertEqual(self.user.first_name, "")

    def test_update_existing_username(self):
        data = {"username": "otheruser"}
        response = self.client.patch(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("username", response.data)

    def test_update_existing_email(self):
        data = {"email": "otheruser@example.com"}
        response = self.client.patch(self.url, data, format="json")

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn("email", response.data)

    def test_update_empty_request(self):
        data = {}
        response = self.client.patch(self.url, data, format="json")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(self.user.first_name, "")
        self.assertEqual(self.user.last_name, "")
        self.assertEqual(self.user.email, "testuser5@example.com")

    def test_update_invalid_email(self):
        data = {"email": "notanemail"}
        response = self.client.patch(self.url, data, format="json")

        self.user.refresh_from_db()
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_authentication_required(self):
        self.client.credentials()  # Remove the authentication token
        data = {"first_name": "John"}
        response = self.client.patch(self.url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TestChangePassword(TestCase):
    def setUp(self):
        self.client = Client()

        self.user = User.objects.create_user(
            username="test_user",
            email="test_user@mail.com",
            password="old_password123",
        )

        self.change_password_url = reverse("users:change_password")
        self.login_url = reverse("users:token_obtain_pair")

        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "old_password123",
            },
        )
        self.access_token = response.data.get("access")

    def test_change_password_success(self):
        data = {
            "old_password": "old_password123",
            "password": "new_password456",
            "password2": "new_password456",
        }

        response = self.client.put(
            self.change_password_url,
            data,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data.get("message"), "Password successfully changed.")

        self.client.logout()
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user",
                "password": "new_password456",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertTrue("access" in response.data.keys())

    def test_change_password_wrong_old_password(self):
        data = {
            "old_password": "wrong_password",
            "password": "new_password456",
            "password2": "new_password456",
        }

        response = self.client.put(
            self.change_password_url,
            data,
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.access_token}",
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

        self.assertIn("old_password", response.data)

        self.assertEqual(
            str(response.data["old_password"]["old_password"]),
            "old password is not correct",
        )


class TestUserFollow(TestCase):
    def setUp(self):
        self.client = Client()

        User.objects.create_user(
            username="test_user_one",
            email="test_user_one@mail.com",
            password="test_user_password",
        )

        User.objects.create_user(
            username="test_user_two",
            email="test_user_two@mail.com",
            password="test_user_password",
        )

        User.objects.create_user(
            username="test_user_three",
            email="test_user_three@mail.com",
            password="test_user_password",
        )

        self.login_url = reverse("users:token_obtain_pair")
        self.user_follow_url = reverse("users:follow")

    def test_follow_one(self):
        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_two",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(follow_response.status_code, 200)

        user_one = User.objects.get(username="test_user_one")
        user_two = User.objects.get(username="test_user_two")

        self.assertEqual(
            list(user_one.following.all()),
            [user_two],
        )

    def test_follow_many(self):
        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_two",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(follow_response.status_code, 200)

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_three",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(follow_response.status_code, 200)

        user_one = User.objects.get(username="test_user_one")
        user_two = User.objects.get(username="test_user_two")
        user_three = User.objects.get(username="test_user_three")

        self.assertIn(user_two, list(user_one.following.all()))
        self.assertIn(user_three, list(user_one.following.all()))

    def test_no_follow_yourself(self):
        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_one",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(
            str(follow_response.data.get("non_field_errors")[0]),
            "You cannot follow yourself",
        )

        self.assertEqual(follow_response.status_code, 400)

    def test_no_follow_twice(self):
        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_two",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_two",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(
            str(follow_response.data.get("non_field_errors")[0]),
            "Cannot follow twice",
        )

        self.assertEqual(follow_response.status_code, 400)

    def test_follow_user_not_found(self):
        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_four",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(
            str(follow_response.data.get("non_field_errors")[0]),
            "User does not exist",
        )

        self.assertEqual(follow_response.status_code, 400)

    def test_follow_imposter(self):
        response = self.client.post(
            self.login_url,
            {
                "username": "test_user_two",
                "password": "test_user_password",
            },
        )

        access_token = response.data.get("access")

        self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        follow_response = self.client.post(
            self.user_follow_url,
            {
                "current_username": "test_user_one",
                "following_username": "test_user_two",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(follow_response.status_code, 400)
        self.assertEqual(
            follow_response.data.get("msg"),
            "Cannot change followers for other users",
        )


class TestUserSendEmail(TestCase):
    def setUp(self):
        self.client = Client()

        self.user = User.objects.create_user(
            username="test_user_one",
            email="test_user_one@mail.com",
            password="test_user_password",
        )

        self.login_url = reverse("users:token_obtain_pair")
        self.verify_url = reverse("users:verify_email")

    def test_not_logged_in(self):
        response = self.client.get(self.verify_url)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data.get("msg"),
            "Not logged in",
        )

    def test_already_verified(self):
        self.user.email_verified = True
        self.user.save()

        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        verify_response = self.client.get(
            self.verify_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

        self.assertEqual(verify_response.status_code, 400)
        self.assertEqual(
            verify_response.data.get("msg"),
            "Email already verified",
        )

    @patch("users.views.EmailMessage")
    def test_valid_auth(self, mock_email_class):
        # Create the mock instance that will be
        # returned when EmailMessage() is called
        mock_email_instance = mock_email_class.return_value

        login_response = self.client.post(
            self.login_url,
            {
                "username": "test_user_one",
                "password": "test_user_password",
            },
        )

        access_token = login_response.data.get("access")

        verify_response = self.client.get(
            self.verify_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        self.assertEqual(
            verify_response.data.get("msg"),
            "Email verification link sent",
        )
        self.assertEqual(verify_response.status_code, 200)

        # Assert message was sent
        mock_email_instance.send.assert_called_once()

        # Assert that EmailMessage was instantiated correctly
        # NOTE: body contains generated tokens which is why I skip testing
        # the body
        mock_email_class.assert_called_once_with(
            "Verify Email",
            ANY,
            to=["test_user_one@mail.com"],
            from_email=settings.DEFAULT_FROM_EMAIL,
        )


class TestEmailVerifyTokens(TestCase):
    def setUp(self):
        self.client = Client()

        self.user = User.objects.create_user(
            username="test_user_one",
            email="test_user_one@mail.com",
            password="test_user_password",
        )

        self.verify_url = reverse("users:verify_email")

    def test_valid_data(self):
        uuid = self.user.uid
        uid = urlsafe_base64_encode(force_bytes(uuid))

        token = account_activation_token.make_token(self.user)

        response = self.client.put(
            self.verify_url,
            data=json.dumps(
                {
                    "uid": uid,
                    "token": token,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data.get("msg"),
            "Verification successful",
        )

    def test_invalid_token(self):
        uuid = self.user.uid
        uid = urlsafe_base64_encode(force_bytes(uuid))

        response = self.client.put(
            self.verify_url,
            data=json.dumps(
                {
                    "uid": uid,
                    "token": "some_token",
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_invalid_uid(self):
        uid = urlsafe_base64_encode(force_bytes("some_wrong_uid"))

        token = account_activation_token.make_token(self.user)

        response = self.client.put(
            self.verify_url,
            data=json.dumps(
                {
                    "uid": uid,
                    "token": token,
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)

    def test_invalid_all(self):
        uid = urlsafe_base64_encode(force_bytes("some_wrong_uid"))

        response = self.client.put(
            self.verify_url,
            data=json.dumps(
                {
                    "uid": uid,
                    "token": "invalid_token",
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
