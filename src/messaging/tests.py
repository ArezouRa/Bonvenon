from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from users.models import User
from messaging.models import Communication, Message
from rest_framework_simplejwt.tokens import RefreshToken


class CommunicationTests(APITestCase):
    """Test the Communication API views"""

    def setUp(self):
        # Create test users
        self.user1 = User.objects.create_user(
            username="testuser1",
            password="testpassword",
            email="test_user1@mail.com",
        )
        self.user2 = User.objects.create_user(
            username="testuser2",
            password="testpassword",
            email="test_user2@mail.com",
        )
        # Create a user who is not a participant in any communication
        self.user3 = User.objects.create_user(
            username="testuser3",
            password="testpassword",
            email="test_user3@mail.com",
        )
        # Create a recipient user
        self.recipient_user = User.objects.create_user(
            username="recipient_user",
            password="testpassword",
            email="recipient_user@mail.com",
        )

        # Create test communications
        self.communication1 = Communication.objects.create(
            to_user=self.user1, from_user=self.user2, status="accepted"
        )
        self.communication2 = Communication.objects.create(
            to_user=self.recipient_user, from_user=self.user1, status="accepted"
        )
        self.communication3 = Communication.objects.create(
            to_user=self.recipient_user, from_user=self.user2, status="accepted"
        )
        # URLs to access the communication list and detail
        self.communication_list_url = reverse("messaging:communication-list")
        self.communication_detail_url1 = reverse(
            "messaging:communication-detail", args=[self.communication1.id]
        )
        self.communication_detail_url2 = reverse(
            "messaging:communication-detail", args=[self.communication2.id]
        )

    # Define a helper method to get the JWT token
    def get_jwt_token(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    # Define a helper method to set JWT authentication
    def set_jwt_authentication(self, user):
        jwt_token = self.get_jwt_token(user)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + jwt_token)

    def tearDown(self):
        # Cleanup after each test
        User.objects.all().delete()

    def test_communication_list_as_participant(self):
        # Authenticate the client as user2
        self.set_jwt_authentication(self.user2)
        response = self.client.get(self.communication_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # user2 should see communications where they are a participant
        self.assertEqual(len(response.data), 2)

    def test_communication_list_as_non_participant(self):
        # Authenticate the client as a user who is not a participant in any communication
        self.set_jwt_authentication(self.user3)
        response = self.client.get(self.communication_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # User2 should only see communications where they are a participant
        self.assertEqual(len(response.data), 0)
        self.assertEqual(response.data, [])

    def test_communication_detail_as_participant(self):
        # Authenticate the client as user2
        self.set_jwt_authentication(self.user2)
        response = self.client.get(self.communication_detail_url1)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["to_user"], self.user1.id)
        self.assertEqual(response.data["from_user"], self.user2.id)
        self.assertEqual(response.data["status"], "accepted")

    def test_communication_detail_as_non_participant(self):
        # Authenticate the client as user1 who is not a participant in communication1
        self.set_jwt_authentication(self.user3)
        response = self.client.get(self.communication_detail_url1)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_communication_update_as_participant(self):
        # Authenticate the client as user2
        self.set_jwt_authentication(self.user2)
        # Attempt to update communication1, which user2 should not be able to update
        response = self.client.patch(
            self.communication_detail_url1, {"status": "rejected"}
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # Ensure that the communication status has not changed
        self.communication1.refresh_from_db()
        self.assertEqual(self.communication1.status, "accepted")

    def test_communication_update_as_recipient(self):
        # Authenticate the client as the recipient
        self.set_jwt_authentication(self.recipient_user)
        # Perform the PATCH request
        response = self.client.patch(
            self.communication_detail_url2, {"status": "rejected"}
        )
        # Assert that the response status code is 200 OK
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["status"], "rejected")

    def test_communication_update_as_non_participant(self):
        # Authenticate the client as user3 who is not a participant in communication2
        self.set_jwt_authentication(self.user3)
        response = self.client.patch(
            self.communication_detail_url2, {"status": "rejected"}
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_communication_create(self):
        # Authenticate the client as user1
        self.set_jwt_authentication(self.user1)
        response = self.client.post(
            self.communication_list_url, {"to_user": self.user3.id}
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Communication.objects.count(), 4)
        self.assertEqual(response.data["to_user"], self.user3.id)
        self.assertEqual(response.data["from_user"], self.user1.id)
        self.assertEqual(response.data["status"], "pending")

    def test_perform_destroy_as_participant(self):
        # Authenticate the client as user1
        self.set_jwt_authentication(self.user1)
        response = self.client.delete(self.communication_detail_url2)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)

    def test_perform_destroy_as_non_participant(self):
        # Authenticate the client as user3 who is not a participant in communication2
        self.set_jwt_authentication(self.user3)
        response = self.client.delete(self.communication_detail_url2)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class MessageTests(APITestCase):
    """Test the Message API views"""

    def setUp(self):
        # Create test users
        self.user1 = User.objects.create_user(
            username="testuser1",
            password="testpassword",
            email="test_user1@mail.com",
        )
        self.user2 = User.objects.create_user(
            username="testuser2",
            password="testpassword",
            email="test_user2@mail.com",
        )
        self.user3 = User.objects.create_user(
            username="testuser3",
            password="testpassword",
            email="test_user3@mail.com",
        )
        # Create a user who is not a participant in any communication
        self.user4 = User.objects.create_user(
            username="testuser4",
            password="testpassword",
            email="test_user4@mail.com",
        )

        # Create test communications
        self.communication1 = Communication.objects.create(
            to_user=self.user1, from_user=self.user2, status="accepted"
        )
        self.communication2 = Communication.objects.create(
            to_user=self.user2, from_user=self.user3, status="accepted"
        )

        # Create test messages
        self.message1 = Message.objects.create(
            communication=self.communication1,
            user=self.user2,
            msg="Message for communication1",
        )
        self.message2 = Message.objects.create(
            communication=self.communication2,
            user=self.user3,
            msg="Message for communication2",
        )

        # URLs to access the message list and detail
        self.message_list_url = lambda communication_id: reverse(
            "messaging:message-list", args=[communication_id]
        )
        self.message_detail_url1 = reverse(
            "messaging:message-detail", args=[self.message1.id]
        )
        self.message_detail_url2 = reverse(
            "messaging:message-detail", args=[self.message2.id]
        )

    def get_jwt_token(self, user):
        from rest_framework_simplejwt.tokens import RefreshToken

        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    def set_jwt_authentication(self, user):
        jwt_token = self.get_jwt_token(user)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + jwt_token)

    def test_message_list_as_participant(self):
        # Authenticate as user2, who is a participant in communication1
        self.set_jwt_authentication(self.user2)
        # Fetch messages for communication1
        communication_id = self.communication1.id
        response = self.client.get(self.message_list_url(communication_id))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Check that the messages are for communication1
        messages = Message.objects.filter(communication=self.communication1)
        self.assertEqual(len(response.data), messages.count())
        self.assertGreaterEqual(len(response.data), 1)

    def test_message_list_as_non_participant(self):
        # Authenticate as user4, who is not a participant in any communication
        self.set_jwt_authentication(self.user4)
        # Attempt to fetch messages for communication1 (where user4 is not a participant)
        communication_id = self.communication1.id
        response = self.client.get(self.message_list_url(communication_id))
        # Since user4 is not a participant, expect a 403 Forbidden response
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_message_detail_as_participant(self):
        # Authenticate as user1, who is a participant in communication1
        self.set_jwt_authentication(self.user1)
        response = self.client.get(self.message_detail_url1)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["msg"], "Message for communication1")

    def test_message_detail_as_non_participant(self):
        # Authenticate as user1, who is not a participant in communication2
        self.set_jwt_authentication(self.user1)
        response = self.client.get(self.message_detail_url2)
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_create_message_as_participant(self):
        # Authenticate as user1, who is a participant in communication1
        self.set_jwt_authentication(self.user1)
        response = self.client.post(
            self.message_list_url(self.communication1.id),
            {
                "communication": self.communication1.id,
                "msg": "New message for communication1",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Message.objects.count(), 3)
        self.assertEqual(Message.objects.last().msg, "New message for communication1")

    def test_create_message_as_non_participant(self):
        # Authenticate as user1, who is not a participant in communication2
        self.set_jwt_authentication(self.user1)
        response = self.client.post(
            self.message_list_url(self.communication2.id),
            {
                "communication": self.communication2.id,
                "msg": "Attempted new message for communication2",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_update_message_as_author(self):
        # Authenticate as user3, who is the author of message2
        self.set_jwt_authentication(self.user3)
        response = self.client.put(
            self.message_detail_url2,
            {
                "communication": self.communication2.id,
                "msg": "Updated message for communication2",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            Message.objects.last().msg, "Updated message for communication2"
        )

    def test_update_message_as_non_author(self):
        # Authenticate as user2, who is not the author of message2
        self.set_jwt_authentication(self.user2)
        response = self.client.put(
            self.message_detail_url2,
            {
                "communication": self.communication2.id,
                "msg": "Attempted update by non-author",
            },
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_delete_message_as_author(self):
        # Authenticate as user3, who is the author of message2
        self.set_jwt_authentication(self.user3)
        response = self.client.delete(self.message_detail_url2)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # Ensure message2 is deleted
        self.assertEqual(Message.objects.count(), 1)

    def test_delete_message_as_non_author(self):
        # Authenticate as user2, who is not the author of message2
        self.set_jwt_authentication(self.user2)
        response = self.client.delete(self.message_detail_url2)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
