from rest_framework import serializers
from authentication.models import CustomUser, FileUpload

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["uname", "email", "password"]

class FileUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = FileUpload
        fields = ['email', 'file_title', 'file_desc', 'cost', 'year_published']  # Customize fields as needed