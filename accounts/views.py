from urllib import request

import self as self
from django.contrib.auth import logout, authenticate, login
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView as AuthLoginView, PasswordResetConfirmView, PasswordResetView
from django.http import HttpResponseRedirect
from django.shortcuts import render, resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import urlsafe_base64_decode
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic import CreateView, FormView
from django.views.generic import TemplateView
from environ import ImproperlyConfigured
from rest_framework.exceptions import ValidationError

from accounts.forms import UserForm
from accounts.models import User
from login_logout import settings


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
        u = User.objects.create_user(username=username, email=email, password=password)
        u.set_password(password)
        u.save()
        login(request, u)
        return render(request, self.template_index)

    # model = User
    # form_class = UserForm
    # template_name = "accounts/registration.html"


class LogoutView(View):
    def get(self, request, *args, **kwargs):
        logout(request)



# class PasswordRestView(View):
#     template_name='accounts/practice_password_rest.html'
#     template_index = "accounts/index.html"
#     model=User
#     def get(self, request):
#         return render(request, self.template_name)
#
#     def post(self, request):
#         print(request.POST)
#         print(request.user)
#         old_password = request.POST.get('old_password')
#         new_password = request.POST.get('new_password1')
#         confirm_password = request.POST.get('new_password2')
#
#         if request.user.check_password(old_password):
#             request.user.set_password(confirm_password)
#             request.user.save()
#             login(request,request.user)
#
#
#
#         return render(request, self.template_index)
#
# class PasswordContextMixin:
#     extra_context = None
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context.update({
#             'title': self.title,
#             **(self.extra_context or {})
#         })
#         return context
#
#
#
# class PasswordRst(PasswordResetView):
#     success_url = reverse_lazy('accounts:password_reset_done')
#     subject_template_name = 'password_reset/password_reset_subject.txt'
#
#
# class PasswordResetOld(PasswordContextMixin, FormView):
#     email_template_name = 'accounts/user_mail.html'
#     extra_email_context = None
#     form_class = PasswordResetForm
#     from_email = None
#     html_email_template_name = None
#     subject_template_name = 'password_reset/password_reset_subject.txt'
#     success_url = reverse_lazy('accounts:password_reset_done')
#     template_name = 'accounts/password_reset.html'
#     title = ('Password reset')
#     token_generator = default_token_generator
#
#     @method_decorator(csrf_protect)
#     def dispatch(self, *args, **kwargs):
#         return super().dispatch(*args, **kwargs)
#
#     def form_valid(self, form):
#         opts = {
#             'use_https': self.request.is_secure(),
#             'token_generator': self.token_generator,
#             'from_email': self.from_email,
#             'email_template_name': self.email_template_name,
#
#             'request': self.request,
#             'html_email_template_name': self.html_email_template_name,
#             'extra_email_context': self.extra_email_context,
#         }
#         form.save(**opts)
#         return super().form_valid(form)
#
#
# INTERNAL_RESET_SESSION_TOKEN = '_password_reset_token'
#
#
# class PasswordResetDoneView(PasswordContextMixin, TemplateView):
#     template_name = 'accounts/password_reset_done.html'
#     title = ('Password reset sent')
#
#
# def auth_login(request, user, post_reset_login_backend):
#     pass
#
#
# class PasswordResetConfirmView(PasswordContextMixin, FormView):
#     form_class = SetPasswordForm
#     post_reset_login = False
#     post_reset_login_backend = None
#     reset_url_token = 'set-password'
#     success_url = reverse_lazy('accounts:password_reset_complete')
#     template_name = 'account/password_reset_confirm.html'
#     title = ('Enter new password')
#     token_generator = default_token_generator
#
#     @method_decorator(sensitive_post_parameters())
#     @method_decorator(never_cache)
#     def dispatch(self, *args, **kwargs):
#         if 'uidb64' not in kwargs or 'token' not in kwargs:
#             raise ImproperlyConfigured(
#                 "The URL path must contain 'uidb64' and 'token' parameters."
#             )
#
#         self.validlink = False
#         self.user = self.get_user(kwargs['uidb64'])
#
#         if self.user is not None:
#             token = kwargs['token']
#             if token == self.reset_url_token:
#                 session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
#                 if self.token_generator.check_token(self.user, session_token):
#                     # If the token is valid, display the password reset form.
#                     self.validlink = True
#                     return super().dispatch(*args, **kwargs)
#             else:
#                 if self.token_generator.check_token(self.user, token):
#                     # Store the token in the session and redirect to the
#                     # password reset form at a URL without the token. That
#                     # avoids the possibility of leaking the token in the
#                     # HTTP Referer header.
#                     self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
#                     redirect_url = self.request.path.replace(token, self.reset_url_token)
#                     return HttpResponseRedirect(redirect_url)
#
#         # Display the "Password reset unsuccessful" page.
#         return self.render_to_response(self.get_context_data())
#
#     def get_user(self, uidb64):
#         try:
#             # urlsafe_base64_decode() decodes to bytestring
#             uid = urlsafe_base64_decode(uidb64).decode()
#             user = User._default_manager.get(pk=uid)
#         except (TypeError, ValueError, OverflowError, User.DoesNotExist, ValidationError):
#             user = None
#         return user
#
#     def get_form_kwargs(self):
#         kwargs = super().get_form_kwargs()
#         kwargs['user'] = self.user
#         return kwargs
#
#     def form_valid(self, form):
#         user = form.save()
#         del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
#         if self.post_reset_login:
#             auth_login(self.request, user, self.post_reset_login_backend)
#         return super().form_valid(form)
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         if self.validlink:
#             context['validlink'] = True
#         else:
#             context.update({
#                 'form': None,
#                 'title': _('Password reset unsuccessful'),
#                 'validlink': False,
#             })
#         return context
#
#
# class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
#     template_name = 'accounts/password_reset_complete.html'
#     title = ('Password reset complete')
#
#     def get_context_data(self, **kwargs):
#         context = super().get_context_data(**kwargs)
#         context['login_url'] = resolve_url(settings.LOGIN_URL)
#         return context
