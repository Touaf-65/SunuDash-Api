# from django.urls import path
# from .views import login_user, register_user

# urlpatterns = [
#     path('login/', login_user.as_view(), name='login'),
#     path('register/', register_user.as_view(), name='register'),
# ]

# ---- ENd first version


from django.urls import path
from .views import register_user, login_user, CreateCountryView, CreateCountryFromExcel, AssignTerritorialAdmin, ListCountriesView, CreateUserByTerritorialAdmin, PasswordResetRequestView, PasswordResetConfirmView, CreateTerritorialAdminView, CreateTerritorialAdminsFromExcel, CreateGlobalAdminView, GlobalAdminListView, GlobalAdminDetailView, GlobalAdminUpdateView, GlobalAdminDeleteView, CreateGlobalAdminsFromExcel, CountryDetailView, CountryUpdateView, CountryDeleteView, TerritorialAdminListView, TerritorialAdminDetailView, TerritorialAdminUpdateView, TerritorialAdminDeleteView, SimpleUserListView, SimpleUserDetailView, SimpleUserUpdateView, SimpleUserDeleteView

urlpatterns = [
    path('register/', register_user.as_view(), name='register_user'),
    path('login/', login_user.as_view(), name='login_user'),

    path('password_reset/', PasswordResetRequestView.as_view(), name='password_reset_request'),
    path('password_reset_confirm/', PasswordResetConfirmView.as_view(), name='password_reset_confirm'),


    path('global_admins/create/', CreateGlobalAdminView.as_view(), name='register_globalal_admin'),
    path('global_admins/import_create/', CreateGlobalAdminsFromExcel.as_view(), name='import_globalal_admins'),
    path('global_admins/list/', GlobalAdminListView.as_view(), name='register_globalal_admin'),
    path('global_admins/<int:pk>/', GlobalAdminDetailView.as_view(), name='global_admin_detail'),
    path('global_admins/<int:pk>/update/', GlobalAdminUpdateView.as_view(), name='global_admin_update'),
    path('global_admins/<int:pk>/delete/', GlobalAdminDeleteView.as_view(), name='global_admin_delete'),


    path('countries/create/', CreateCountryView.as_view(), name='create_country'),
    path('countries/import_create/', CreateCountryFromExcel.as_view(), name='import_countries'),
    path('countries/list/', ListCountriesView.as_view(), name='list_countries'),
    path('countries/<int:pk>/', CountryDetailView.as_view(), name='country_detail'),
    path('countries/<int:pk>/update/', CountryUpdateView.as_view(), name='country_detail'),
    path('countries/<int:pk>/delete/', CountryDeleteView.as_view(), name='country_detail'),

    path('territorial_admins/assign/', AssignTerritorialAdmin.as_view(), name='assign_admin'),  

    
    path('territorial_admins/create/', CreateTerritorialAdminView.as_view(), name='register_territorial_admin'),
    path('territorial_admins/import_create/', CreateTerritorialAdminsFromExcel.as_view(), name='import_territorial_admins'),
    path('territorial_admins/list/', TerritorialAdminListView.as_view(), name='list_countries'),
    path('territorial_admins/<int:pk>/', TerritorialAdminDetailView.as_view(), name='country_detail'),
    path('territorial_admins/<int:pk>/update/', TerritorialAdminUpdateView.as_view(), name='country_detail'),
    path('territorial_admins/<int:pk>/delete/', TerritorialAdminDeleteView.as_view(), name='country_detail'),

    path('territorial_admins/users/create_user/', CreateUserByTerritorialAdmin.as_view(), name='create_user_by_territorial_admin'),
    path('territorial_admins/users/import_create_user/', CreateUserByTerritorialAdmin.as_view(), name='import_users_by_territorial_admin'),
    path('territorial_admins/users/list/', SimpleUserListView.as_view(), name='list_countries'),
    path('territorial_admins/users/<int:pk>/', SimpleUserDetailView.as_view(), name='country_detail'),
    path('territorial_admins/users/<int:pk>/update/', SimpleUserUpdateView.as_view(), name='country_detail'),
    path('territorial_admins/users/<int:pk>/delete/', SimpleUserDeleteView.as_view(), name='country_detail'),
    
]
