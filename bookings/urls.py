from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import generate_receipt
from django.conf import settings
from django.conf.urls.static import static

app_name = 'bookings'

urlpatterns = [
    path('login/', views.user_login, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', auth_views.LogoutView.as_view(template_name='bookings/logout.html'), name='logout'),
    path('', views.GeneratorListView.as_view(), name='generator_list'),
    path('book/<int:generator_id>/', views.book_generator, name='book_generator'),
    path('my-bookings/', views.UserBookingListView.as_view(), name='user_bookings'),
    path('generate_receipt/<int:booking_id>/', views.generate_receipt, name='generate_receipt'),
    path('receipt/<int:booking_id>/', views.generate_receipt, name='receipt'),
    path('initiate-payment/', views.initiate_payment, name='initiate_payment'),
    path('process-payment/', views.UserBookingListView.as_view(), name='process_payment'),
    path('contact-us/', views.contact_us, name='contact_us'),
    path('about-us/', views.about_us, name='about_us'),
    ] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)