from django.contrib.auth.views import LogoutView
from django.urls import path, reverse_lazy

from .views import LoginView, RegistrationView, AboutView
from django.contrib.auth import views as auth_views
app_name = "accounts"

urlpatterns = [
    path("login/", LoginView.as_view(), name="login"),
    path("register/", RegistrationView.as_view(), name="register"),
    path("logout/", LogoutView.as_view(next_page=reverse_lazy("accounts:login")), name="logout"),
    path('index/', AboutView.as_view(), name="index"),
    # path('password_reset_check/', PasswordRestView.as_view(), name="password_reset"),
    path("password-reset/", auth_views.PasswordResetView.as_view(template_name="accounts/password_reset.html"),
         name="password_reset"),
    path("password-reset/done/",
         auth_views.PasswordResetDoneView.as_view(template_name="accounts/password_reset_done.html"),
         name="password_reset_done"),
    path("password-reset-confirm/<uidb64>/<token>",
         auth_views.PasswordResetConfirmView.as_view(template_name="accounts/password_reset_confirm.html"),
         name="password_reset_confirm"),
    path("password-reset-complete/",
         auth_views.PasswordResetCompleteView.as_view(template_name="accounts/password_reset_complete.html"),
         name="password_reset_complete")

]
