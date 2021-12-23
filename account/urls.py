from django.urls import re_path
from django.urls import path, include
from .api import UserRegistrationView, UserLoginView, \
    ChangePasswordViewSet, UpdateUserProfile, check_user, \
    UserDetails


urlpatterns = [
    re_path(r'^auth/verify-user/', check_user),
    re_path(r'^signup/', UserRegistrationView.as_view()),
    re_path(r'^signin/', UserLoginView.as_view()),
    re_path(r'change_password/', ChangePasswordViewSet.as_view()),
    re_path(r'user/update/', UpdateUserProfile.as_view()),
    re_path(r'user/details/', UserDetails.as_view())
]
