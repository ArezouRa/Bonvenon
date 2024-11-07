from django.contrib import admin
from posts.models import Post, Comment


class CommentInline(admin.TabularInline):
    model = Comment
    extra = 1
    readonly_fields = ("user", "content", "created_at")


class PostAdmin(admin.ModelAdmin):
    list_display = ("title", "user", "created_at")
    inlines = [CommentInline]


class CommentAdmin(admin.ModelAdmin):
    list_display = ("post", "user", "content", "created_at")
    readonly_fields = ("user", "created_at")


admin.site.register(Post, PostAdmin)
admin.site.register(Comment, CommentAdmin)
