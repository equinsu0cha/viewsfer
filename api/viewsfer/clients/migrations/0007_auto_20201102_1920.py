# Generated by Django 3.1.2 on 2020-11-02 19:20

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('clients', '0006_deployment'),
    ]

    operations = [
        migrations.RenameField(
            model_name='client',
            old_name='client',
            new_name='name',
        ),
        migrations.RenameField(
            model_name='site',
            old_name='site',
            new_name='name',
        ),
    ]
