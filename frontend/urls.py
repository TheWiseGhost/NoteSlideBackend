from django.urls import path
from .views import index

urlpatterns = [
    path('', index),
    path('landing/', index),
    path('auth/', index),
    path('dashboard/', index),
    path('upload/', index),
    path('uploadad/', index),
    path('view/', index),
    path('view/<str:note_id>/', index),
    path('ad/<str:note_id>/', index),
    path('business/', index),
    path('business_main/', index),
    path('admanager/', index),
    path('profile/', index),
    path('favorites/', index),
    path('buyadcredit/', index),
    path('verify/<str:token>/', index),
    path('verify_business/<str:token>/', index),
    path('public_profile/<str:username>/', index),
]