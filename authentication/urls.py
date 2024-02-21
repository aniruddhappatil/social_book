from . import views
from django.urls import include, path
from djoser import views as djoser_views

urlpatterns = [
    path("", views.home, name = "home"),
    path("signin/", views.signin, name = "signin"),
    path("signup/", views.signup, name = "signup"),
    path("signout/", views.signout, name = "signout"),
    path("user_list/", views.user_list, name='user_list'),
    path("file_upload/", views.file_upload, name='file_upload'),
    path("view_files/", views.view_files, name='view_files'),
    path("get_all_files/", views.get_all_files, name='get_all_files'),
    path("two_factor_authentication/", views.two_factor_authentication, name="two_factor_authentication"),
    path("two_factor_authentication_signup/", views.two_factor_authentication_signup, name="two_factor_authentication_signup"),
    path("created_account/", views.created_account, name='created_account'),
]