from rest_framework import serializers
from posts.models import Post
from posts.models import Comment


class CommentSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source="user.username")
    post = serializers.PrimaryKeyRelatedField(
        queryset=Post.objects.all(), write_only=True
    )

    class Meta:
        model = Comment
        fields = ["id", "user", "post", "content", "created_at", "upvotes"]


class PostSerializer(serializers.ModelSerializer):
    user = serializers.ReadOnlyField(source="user.username")
    comments = CommentSerializer(many=True, read_only=True)

    class Meta:
        model = Post
        fields = ["id", "user", "title", "description", "created_at", "comments"]
        expandable_fields = {"comments": (CommentSerializer,)}
