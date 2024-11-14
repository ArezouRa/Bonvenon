# Generated by Django 5.1.3 on 2024-11-14 14:11

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0014_user_uid'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='uid',
            field=models.UUIDField(default=uuid.uuid4, editable=False),
        ),
    ]