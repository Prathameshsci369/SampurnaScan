from django.urls import path
from .views import home  # Importing the home view

urlpatterns = [
    path('home/', home, name='home'),  # URL pattern for home view
]
