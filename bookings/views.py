from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.views.generic import ListView
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Generator, Booking
from .forms import BookingForm
from django.contrib.auth.forms import UserCreationForm
from django.views.decorators.csrf import csrf_protect
from .forms import LoginForm
from datetime import datetime
from datetime import timedelta
from django.core.exceptions import ValidationError
from django.conf import settings   #--------
import stripe                      #--------
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.urls import reverse
from .forms import ContactForm
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)

from urllib.parse import urlparse, urlunparse

from django.conf import settings

# Avoid shadowing the login() and logout() views below.
from django.contrib.auth import REDIRECT_FIELD_NAME, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import (
    AuthenticationForm,
    PasswordChangeForm,
    PasswordResetForm,
    SetPasswordForm,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.http import HttpResponseRedirect, QueryDict
from django.shortcuts import resolve_url
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.utils.http import url_has_allowed_host_and_scheme, urlsafe_base64_decode
from django.utils.translation import gettext_lazy as _
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from datetime import datetime, timedelta

UserModel = get_user_model()

stripe.api_key = settings.STRIPE_SECRET_KEY

class GeneratorListView(ListView):
    model = Generator
    template_name = 'bookings/generator_list.html'
    context_object_name = 'generators'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Calculate the available date based on today's date
        today = datetime.now().date()
        available_date = today + timedelta(days=1)  # Assuming the generator is available at least after one day

        context['available_date'] = available_date
        return context

def about_us(request):
    return render(request, 'bookings/about_us.html')

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect('bookings:login')
    else:
        form = UserCreationForm()
    return render(request, 'bookings/register.html', {'form': form})

def user_login(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('bookings:generator_list')
            else:
                messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()

    return render(request, 'bookings/login.html', {'form': form})

def contact_us(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your message has been sent. We will get back to you soon.')
            return redirect('bookings:contact_us')  # Update the redirect to use the correct URL name
    else:
        form = ContactForm()
    return render(request, 'bookings/contact_us.html', {'form': form})

class PasswordContextMixin:
    extra_context = None

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update(
            {"title": self.title, "subtitle": None, **(self.extra_context or {})}
        )
        return context

class PasswordResetView(PasswordContextMixin, FormView):
    email_template_name = "registration/password_reset_email.html"
    extra_email_context = None
    form_class = PasswordResetForm
    from_email = None
    html_email_template_name = None
    subject_template_name = "registration/password_reset_subject.txt"
    success_url = reverse_lazy("password_reset_done")
    template_name = "registration/password_reset_form.html"
    title = _("Password reset")
    token_generator = default_token_generator

    @method_decorator(csrf_protect)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def form_valid(self, form):
        opts = {
            "use_https": self.request.is_secure(),
            "token_generator": self.token_generator,
            "from_email": self.from_email,
            "email_template_name": self.email_template_name,
            "subject_template_name": self.subject_template_name,
            "request": self.request,
            "html_email_template_name": self.html_email_template_name,
            "extra_email_context": self.extra_email_context,
        }
        form.save(**opts)
        return super().form_valid(form)


INTERNAL_RESET_SESSION_TOKEN = "_password_reset_token"


class PasswordResetDoneView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_done.html"
    title = _("Password reset sent")


class PasswordResetConfirmView(PasswordContextMixin, FormView):
    form_class = SetPasswordForm
    post_reset_login = False
    post_reset_login_backend = None
    reset_url_token = "set-password"
    success_url = reverse_lazy("password_reset_complete")
    template_name = "registration/password_reset_confirm.html"
    title = _("Enter new password")
    token_generator = default_token_generator

    @method_decorator(sensitive_post_parameters())
    @method_decorator(never_cache)
    def dispatch(self, *args, **kwargs):
        if "uidb64" not in kwargs or "token" not in kwargs:
            raise ImproperlyConfigured(
                "The URL path must contain 'uidb64' and 'token' parameters."
            )

        self.validlink = False
        self.user = self.get_user(kwargs["uidb64"])

        if self.user is not None:
            token = kwargs["token"]
            if token == self.reset_url_token:
                session_token = self.request.session.get(INTERNAL_RESET_SESSION_TOKEN)
                if self.token_generator.check_token(self.user, session_token):
                    # If the token is valid, display the password reset form.
                    self.validlink = True
                    return super().dispatch(*args, **kwargs)
            else:
                if self.token_generator.check_token(self.user, token):
                    # Store the token in the session and redirect to the
                    # password reset form at a URL without the token. That
                    # avoids the possibility of leaking the token in the
                    # HTTP Referer header.
                    self.request.session[INTERNAL_RESET_SESSION_TOKEN] = token
                    redirect_url = self.request.path.replace(
                        token, self.reset_url_token
                    )
                    return HttpResponseRedirect(redirect_url)

        # Display the "Password reset unsuccessful" page.
        return self.render_to_response(self.get_context_data())

    def get_user(self, uidb64):
        try:
            # urlsafe_base64_decode() decodes to bytestring
            uid = urlsafe_base64_decode(uidb64).decode()
            user = UserModel._default_manager.get(pk=uid)
        except (
            TypeError,
            ValueError,
            OverflowError,
            UserModel.DoesNotExist,
            ValidationError,
        ):
            user = None
        return user

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.user
        return kwargs

    def form_valid(self, form):
        user = form.save()
        del self.request.session[INTERNAL_RESET_SESSION_TOKEN]
        if self.post_reset_login:
            auth_login(self.request, user, self.post_reset_login_backend)
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        if self.validlink:
            context["validlink"] = True
        else:
            context.update(
                {
                    "form": None,
                    "title": _("Password reset unsuccessful"),
                    "validlink": False,
                }
            )
        return context


class PasswordResetCompleteView(PasswordContextMixin, TemplateView):
    template_name = "registration/password_reset_complete.html"
    title = _("Password reset complete")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["login_url"] = resolve_url(settings.LOGIN_URL)
        return context



@login_required(login_url='bookings:login')
def book_generator(request, generator_id):
    generator = get_object_or_404(Generator, pk=generator_id)
    
    if not generator.availability:
        if generator.available_date and generator.available_date > datetime.now().date():
            messages.warning(request, f'The generator is not available. It becomes available after {generator.available_date}.')
        else:
            messages.warning(request, 'The generator is not available.')
        return redirect('bookings:generator_list')
    
    if request.method == 'POST':
        form = BookingForm(request.POST)
        if form.is_valid():
            booking = form.save(commit=False)
            booking.generator = generator
            booking.user = request.user

            if booking.start_date >= booking.end_date:
                form.add_error('end_date', 'End date must be greater than start date')
                return render(request, 'bookings/book_generator.html', {'generator': generator, 'form': form})

            today = datetime.now().date()
            if booking.end_date < today:
                messages.warning(request, 'The booking end date should be in the future.')
                return render(request, 'bookings/book_generator.html', {'generator': generator, 'form': form})

            booking.save()
            generator.availability = False
            #generator.save()


              # Calculate the available_date based on the end_date of this booking
            available_date = booking.end_date + timedelta(days=1)
            generator.available_date = available_date
            generator.save()


            messages.success(request, 'Generator booked successfully!')

            num_days = (booking.end_date - booking.start_date).days
            price = num_days * generator.daily_price

            booking_result = {
                'id': booking.id,
                'start_date': booking.start_date,
                'end_date': booking.end_date,
                'price': price,
            }
            return render(request, 'bookings/book_generator.html', {'generator': generator, 'form': form, 'booking_result': booking_result})
    else:
        form = BookingForm()

    return render(request, 'bookings/book_generator.html', {'generator': generator, 'form': form})

class UserBookingListView(ListView):
    model = Booking
    template_name = 'bookings/user_bookings.html'
    context_object_name = 'bookings'

    def get_queryset(self):
        return Booking.objects.filter(user=self.request.user)

def generate_receipt(request, booking_id):
    booking_result = get_object_or_404(Booking, id=booking_id)
    generator = booking_result.generator

    # Calculate the price based on the number of days
    num_days = (booking_result.end_date - booking_result.start_date).days
    price = num_days * generator.daily_price

    receipt_data = {
        'booking_result': booking_result,
        'generator': generator,
        'price': price, 
    }
    return render(request, 'bookings/receipt.html', receipt_data)


# -----------------------------------------------


@csrf_exempt
def process_payment(request):
    if request.method == 'POST':
        payment_method_id = request.POST.get('payment_method_id')
        try:
            stripe.PaymentIntent.create(
                payment_method=payment_method_id,
                confirm=True,
            )
            # Update booking status or perform any required actions
            return JsonResponse({'success': True, 'message': 'Payment successful'})
        except Exception as e:
            return JsonResponse({'success': False, 'message': 'Payment failed'})
    return JsonResponse({'success': True, 'message': 'Booking Sucessful'})


def initiate_payment(request):
    if request.method == 'POST':
        amount = 1000  # Amount in cents
        try:
            intent = stripe.PaymentIntent.create(
                amount=amount,
                currency='inr',
                payment_method_types=['card'],
            )
            client_secret = intent.client_secret
            return render(request, 'payment/payment.html', {'client_secret': client_secret})
        except Exception as e:
            return redirect(reverse('bookings:process_payment'))  # Handle payment failure
    return redirect(reverse('bookings:process_payment'))  # Invalid request method