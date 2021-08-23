from django.contrib.auth import logout
from django.contrib.auth.views import LoginView as AuthLoginView
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import CreateView
from django.views.generic import TemplateView

from accounts.forms import UserForm
from accounts.models import User


class AboutView(TemplateView):
    template_name = "accounts/index.html"


class LoginView(AuthLoginView):
    template_name = "accounts/login.html"


class RegistrationView(CreateView):
    model = User
    form_class = UserForm
    template_name = "accounts/registration.html"
    success_url = reverse_lazy("accounts:index")


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        logout(request)
