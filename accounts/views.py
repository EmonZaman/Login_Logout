from django.contrib.auth import logout
from django.contrib.auth.views import LoginView
from django.shortcuts import render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import CreateView, RedirectView

from accounts.forms import UserForm
from accounts.models import User


# Create your views here.
from django.views.generic import TemplateView

class AboutView(TemplateView):
    template_name = "accounts/index.html"

class MyLoginView(LoginView):
    template_name = "accounts/login.html"


class RegistrationView(CreateView):
    model = User
    form_class = UserForm
    template_name = "accounts/registration.html"
    success_url = reverse_lazy("accounts:index")

class LogoutView(View):
    def get(self, request):
        logout(request)

