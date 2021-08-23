from django.contrib.auth.views import LogoutView
from django.urls import path, reverse_lazy

from .views import LoginView, RegistrationView, AboutView

app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("register/", RegistrationView.as_view(), name="register"),
    path("logout/", LogoutView.as_view(next_page=reverse_lazy("accounts:login")), name="logout"),
    path('index/', AboutView.as_view(), name="index"),
]
