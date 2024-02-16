from . import views
from django.urls import path

urlpatterns = [
    path("", views.home, name = "home"),
    path("signin/", views.signin, name = "signin"),
    path("signup/", views.signup, name = "signup"),
    path("signout/", views.signout, name = "signout"),
    path("user_list/", views.user_list, name='user_list'),
    path("file_upload/", views.file_upload, name='file_upload'),
    path("get_all_files/", views.get_all_files, name='get_all_files'),
]