from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from users.models import User
from posts.models import Post, Comment
from rest_framework_simplejwt.tokens import RefreshToken


class PostTests(APITestCase):
    """Test the Post API views"""

    def setUp(self):
        # Create test users
        self.user1 = User.objects.create_user(
            username="testuser1",
            password="testpassword",
            email="test_user@mail.com",
        )

        self.user2 = User.objects.create_user(
            username="testuser2",
            password="testpassword",
            email="test_user2@mail.com",
        )
        # Create test posts
        self.post1 = Post.objects.create(
            user=self.user1, title="Test Post1", description="This is user1's test post"
        )
        self.post2 = Post.objects.create(
            user=self.user2, title="Test Post2", description="This is user2's test post"
        )
        # URLs to access the post list and detail
        self.post_list_url = reverse("posts:post-list")
        self.post1_detail_url = reverse("posts:post-detail", args=[self.post1.id])
        self.post2_detail_url = reverse("posts:post-detail", args=[self.post2.id])

    # Define a helper method to get the JWT token
    def get_jwt_token(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    # Define a helper method to set JWT authentication
    def set_jwt_authentication(self, user):
        jwt_token = self.get_jwt_token(user)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + jwt_token)

    def test_post_list(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        response = self.client.get(self.post_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_post_detail_as_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)

        response = self.client.get(self.post1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Test Post1")
        self.assertEqual(response.data["description"], "This is user1's test post")

    def test_post_detail_as_non_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user2)

        response = self.client.get(self.post1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["title"], "Test Post1")
        self.assertEqual(response.data["description"], "This is user1's test post")

    def test_create_post(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)

        data = {"title": "New Post", "description": "Description of the new post"}
        response = self.client.post(self.post_list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Post.objects.count(), 3)

    def test_update_post_as_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)

        data = {"title": "Updated Post", "description": "Updated description"}
        response = self.client.put(self.post1_detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(Post.objects.get(id=self.post1.id).title, "Updated Post")

    def test_update_post_as_non_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user2)

        data = {"title": "Updated Post", "description": "Updated description"}
        response = self.client.put(self.post1_detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(Post.objects.get(id=self.post1.id).title, "Test Post1")

    def test_delete_post_as_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)

        response = self.client.delete(self.post1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(Post.objects.count(), 1)  # Only post2 should be left

    def test_delete_post_as_non_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user2)

        response = self.client.delete(self.post1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # user2 should not be able to delete post1
        self.assertEqual(Post.objects.count(), 2)


class CommentTests(APITestCase):
    """Test the Comment API views"""

    def setUp(self):
        # Create test users and post
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
        self.post = Post.objects.create(
            user=self.user1, title="Test Post", description="This is a test post"
        )
        # Create comments for user1 and user2
        self.comment1 = Comment.objects.create(
            user=self.user1, post=self.post, content="This is user1's comment"
        )
        self.comment2 = Comment.objects.create(
            user=self.user2, post=self.post, content="This is user2's comment"
        )
        # URLs to access the comment list and detail
        self.comment_list_url = reverse("posts:comment-list", args=[self.post.id])
        self.comment1_detail_url = reverse(
            "posts:comment-detail", args=[self.post.id, self.comment1.id]
        )
        self.comment2_detail_url = reverse(
            "posts:comment-detail", args=[self.post.id, self.comment2.id]
        )

    # Helper method to get JWT token
    def get_jwt_token(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)

    # Helper method to set JWT authentication
    def set_jwt_authentication(self, user):
        jwt_token = self.get_jwt_token(user)
        self.client.credentials(HTTP_AUTHORIZATION="Bearer " + jwt_token)

    def test_comment_list(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        response = self.client.get(self.comment_list_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 2)

    def test_comment_detail(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        response = self.client.get(self.comment1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data["content"], "This is user1's comment")

    def test_create_comment(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        data = {"content": "New comment", "post": self.post.id}
        response = self.client.post(self.comment_list_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Comment.objects.count(), 3)

    def test_update_comment_as_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        data = {"content": "Updated comment", "post": self.post.id}
        response = self.client.put(self.comment1_detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        updated_comment = Comment.objects.get(id=self.comment1.id)
        self.assertEqual(updated_comment.content, "Updated comment")

    def test_update_comment_as_non_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user2)
        data = {"content": "Updated comment by non-author", "post": self.post.id}
        response = self.client.put(self.comment1_detail_url, data, format="json")
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        updated_comment = Comment.objects.get(id=self.comment1.id)
        self.assertEqual(updated_comment.content, "This is user1's comment")

    def test_delete_comment_as_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user1)
        response = self.client.delete(self.comment1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # Only comment2 should remain
        self.assertEqual(Comment.objects.count(), 1)

    def test_delete_comment_as_non_author(self):
        # Authenticate the client with JWT
        self.set_jwt_authentication(self.user2)
        response = self.client.delete(self.comment1_detail_url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        # user2 cannot delete comment1
        self.assertEqual(Comment.objects.count(), 2)
