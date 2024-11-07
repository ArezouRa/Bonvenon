from posts.models import Post, Comment
from rest_framework import generics
from posts.serializers import PostSerializer, CommentSerializer
from django.shortcuts import get_object_or_404
from posts.permissions import IsOwnerOrReadOnly


class PostList(generics.ListCreateAPIView):
    """This class handles listing and creating posts in our REST API."""

    queryset = Post.objects.all()
    serializer_class = PostSerializer

    def perform_create(self, serializer):
        # Set the user field to the current user
        serializer.save(user=self.request.user)


class PostDetail(generics.RetrieveUpdateDestroyAPIView):
    """This class handles operations for a single post instance.

    - GET: Retrieve the details of a specific post.
    - PUT: Update the entire post instance.
    - PATCH: Partially update the post instance.
    - DELETE: Remove the specific post instance.
    """

    queryset = Post.objects.all()
    serializer_class = PostSerializer
    # Only the author can update or delete the post.
    permission_classes = [IsOwnerOrReadOnly]


class CommentList(generics.ListCreateAPIView):
    """This class handles listing and creating comments for a specific post in our REST API."""

    serializer_class = CommentSerializer

    def get_queryset(self):
        post_id = self.kwargs["post_id"]
        return Comment.objects.filter(post_id=post_id)

    def perform_create(self, serializer):
        post_id = self.kwargs["post_id"]
        post = get_object_or_404(Post, id=post_id)
        serializer.save(user=self.request.user, post=post)


class CommentDetail(generics.RetrieveUpdateDestroyAPIView):
    """This class handles retrieving, updating, and deleting a single comment instance.

    - GET: Retrieve a specific comment instance.
    - PUT/PATCH: Update a specific comment instance.
    - DELETE: Delete a specific comment instance.
    """

    queryset = Comment.objects.all()
    serializer_class = CommentSerializer
    # Only the author can update or delete the comment.
    permission_classes = [IsOwnerOrReadOnly]
