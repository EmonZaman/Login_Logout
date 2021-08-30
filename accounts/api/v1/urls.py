from django.urls import path
from .views import UserView, UserDetail

app_name = "accounts-api-v1"

urlpatterns = [
    path('user/',UserView.as_view(),name="user"),
    path('user/<int:pk>/', UserDetail.as_view()),
]