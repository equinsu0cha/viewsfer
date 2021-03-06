# Generated by Django 3.1.2 on 2020-10-26 07:19

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0010_auto_20201002_1257'),
    ]

    operations = [
        migrations.AddField(
            model_name='coresettings',
            name='sms_alert_recipients',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.CharField(blank=True, max_length=255, null=True), blank=True, default=list, null=True, size=None),
        ),
        migrations.AddField(
            model_name='coresettings',
            name='twilio_account_sid',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='coresettings',
            name='twilio_auth_token',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='coresettings',
            name='twilio_number',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
