from django.urls import path
from .views import register_user, login_user, CountryView, AssignTerritorialAdmin, ListCountriesView, CreateUserByTerritorialAdmin, PasswordResetRequestView, PasswordResetConfirmView

urlpatterns = [
    path('register/', register_user.as_view(), name='register_user'),
    path('login/', login_user.as_view(), name='login_user'),
    path('countries/', CountryView.as_view(), name='create_country'),
    path('assign-admin/', AssignTerritorialAdmin.as_view(), name='assign_admin'),  
    path('countries/list/', ListCountriesView.as_view(), name='list_countries'),
    path('territorial-admin/create-user/', CreateUserByTerritorialAdmin.as_view(), name='create_user_by_territorial_admin'),
    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password_reset_confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
]
