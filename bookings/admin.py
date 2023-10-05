from django.contrib import admin
from .models import Generator,Booking,ContactMessage

admin.site.site_title = "Generator.Ltd"
admin.site.site_header = "Generator.Ltd"
admin.site.index_title = "Generator.Ltd Dashboard"

@admin.register(Generator)
class Generator(admin.ModelAdmin):
    list_display=('name','description','power_output','fuel_type','availability')
    search_fields=('name','description','power_output','fuel_type','availability')

@admin.register(Booking)
class Booking(admin.ModelAdmin):
    list_display=('generator','user','start_date','end_date',)
    search_fields=('generator','user','start_date','end_date')

@admin.register(ContactMessage)
class Booking(admin.ModelAdmin):
    list_display=('name','email','message')
    search_fields=('name','email','message')