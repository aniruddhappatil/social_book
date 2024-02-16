from django import forms
from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from .models import CustomUser, FileUpload

class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = CustomUser
        fields = '__all__'

class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = CustomUser
        fields = '__all__'

class UploadFileForm(forms.ModelForm):
    class Meta:
        model = FileUpload
        fields = '__all__'#['file_title', 'file_desc', 'cost', 'year_published', 'file']