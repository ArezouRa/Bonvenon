from django.urls import path
from posts.views import PostList, PostDetail, CommentList, CommentDetail

app_name = "posts"
urlpatterns = [
    path("", PostList.as_view(), name="post-list"),
    path("<int:pk>/", PostDetail.as_view(), name="post-detail"),
    path("<int:post_id>/comments/", CommentList.as_view(), name="comment-list"),
    path(
        "<int:post_id>/comments/<int:pk>/",
        CommentDetail.as_view(),
        name="comment-detail",
    ),
]
