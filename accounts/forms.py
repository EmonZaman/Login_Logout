from django import forms
from .models import User


class UserForm(forms.ModelForm):
    password1 = forms.CharField(widget=forms.PasswordInput())
    password2 = forms.CharField(label='Confirm_Password', widget=forms.PasswordInput)


    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'password1', 'password2')

