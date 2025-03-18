from django.db import models
from django.contrib.auth.models import AbstractUser
from django.db.models.signals import post_save
from django.utils.html import mark_safe
from django.utils.text import slugify


class Contact(models.Model):
    name=models.CharField(max_length=500)
    email=models.EmailField(max_length=100,null=True,blank=True)
    subject=models.CharField(max_length=500,null=True,blank=True)
    s_link=models.TextField(null=True,blank=True)
    message=models.TextField(null=True,blank=True)
    date = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'{self.subject} from {self.name}'