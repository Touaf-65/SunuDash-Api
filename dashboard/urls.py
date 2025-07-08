from django.urls import path
from .views import ClientStatisticListView, ClientStatisticView

urlpatterns = [
    path('country/clients/', ClientStatisticListView.as_view()),
    path('client/statistics/<int:client_id>/', ClientStatisticView.as_view()),
]
