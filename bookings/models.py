from django.db import models
from django.contrib.auth.models import User

class Generator(models.Model):
    name = models.CharField(max_length=100)
    description = models.TextField()
    power_output = models.DecimalField(max_digits=8, decimal_places=2)
    fuel_type = models.CharField(max_length=50, default='Petrol')
    availability = models.BooleanField(default=True)
    daily_price = models.DecimalField(max_digits=8, decimal_places=2, default='20.0')
    image = models.ImageField(upload_to='generator_images/', blank=True, null=True)

    # New field to store the date when the generator becomes available
    available_date = models.DateField(null=True, blank=True)

    def __str__(self):
        return self.name

class Booking(models.Model):
    generator = models.ForeignKey(Generator, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    start_date = models.DateField()
    end_date = models.DateField()
    
    def __str__(self):
        return f"{self.generator.name} - {self.user.username}"

class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(default='2023-01-01 00:00:00')

    def __str__(self):
        return self.name