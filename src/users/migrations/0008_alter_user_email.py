# Generated by Django 5.1 on 2024-09-06 08:08

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("users", "0007_delete_blacklistedtoken"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="email",
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]