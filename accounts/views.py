from urllib import request

import self as self
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.forms import PasswordResetForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView as AuthLoginView
from django.shortcuts import render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.generic import CreateView, FormView
from django.views.generic import TemplateView

from accounts.forms import UserForm
from accounts.models import User


class AboutView(TemplateView):
    template_name = "accounts/index.html"


# noinspection PyMethodMayBeStatic
class LoginView(View):
    template_name = "accounts/login.html"
    template_index = "accounts/index.html"

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        print(request.POST)
        email = request.POST.get('email')
        password = request.POST.get('password')
        print(email, password)
        user = self.get_user(email, password)
        if user:
            login(request, user)
            return render(request, self.template_index)
        return render(request, self.template_name)

    def get_user(self, email, password):
        try:
            user = User.objects.get(email=email)
            print(user)
        except User.DoesNotExist:
            return None

        if user.check_password(password):
            return user

        return None


class RegistrationView(View):
    template_name = "accounts/registration.html"
    template_index = "accounts/index.html"

    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        print(request.POST)
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        confirm_password = request.POST.get('password_confirm')
        print(username, email, password, confirm_password)
        # u = User()
        # u.objects.get(username=username)
        # u.objects.get(email=email)
        # u.objects.get(password=password)
        u=User.objects.create_user(username=username, email=email, password=password)
        u.set_password(password)
        u.save()
        login(request,u)
        return render(request, self.template_index)


    # model = User
    # form_class = UserForm
    # template_name = "accounts/registration.html"



class LogoutView(View):
    def get(self, request, *args, **kwargs):
        logout(request)

class PasswordRestView(View):
    template_name='accounts/password_rest.html'
    template_index = "accounts/index.html"
    model=User
    def get(self, request):
        return render(request, self.template_name)

    def post(self, request):
        print(request.POST)
        print(request.user)
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password1')
        confirm_password = request.POST.get('new_password2')

        if request.user.check_password(old_password):
            request.user.set_password(confirm_password)
            request.user.save()
            login(request,request.user)



        return render(request, self.template_index)

