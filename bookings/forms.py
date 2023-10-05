from django import forms
from .models import Booking,ContactMessage

class BookingForm(forms.ModelForm):
    class Meta:
        model = Booking
        fields = ['start_date', 'end_date']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)

class ContactForm(forms.ModelForm):
    class Meta:
        model = ContactMessage
        fields = ['name', 'email', 'message']

        from django import forms
from .models import Generator, Booking, ContactMessage

class GeneratorForm(forms.ModelForm):
    class Meta:
        model = Generator
        fields = ['name', 'description', 'power_output', 'fuel_type', 'availability', 'image']