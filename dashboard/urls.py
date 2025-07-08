from django.urls import path
from .views import ClientStatisticListView

urlpatterns = [
    path('country/clients/', ClientStatisticListView.as_view()),
]
