from django.urls import path
from .views import ClientStatisticListView, ClientStatisticView, ClientListPolicyStatisticsView, ClientPolicyStatisticsView, CountriesListStatisticsView, CountryStatisticsDetailView

urlpatterns = [
    path('countries/<int:country_id>/statistics/', CountryStatisticsDetailView.as_view(), name='country-statistics-detail'),
    path('countries/statistics/', CountriesListStatisticsView.as_view(), name='countries-statistics'),
    path('country/clients/', ClientStatisticListView.as_view()),
    path('client/statistics/<int:client_id>/', ClientStatisticView.as_view()),
    path('client/policies/statistics/<int:client_id>/', ClientListPolicyStatisticsView.as_view()),
    path('client/policy/statistics/<int:policy_id>/', ClientPolicyStatisticsView.as_view()),
]
