from django.contrib import admin
from .models import CustomUser
# from django.contrib.auth.admin import UserAdmin

# class UserAdminConfig(UserAdmin):
#     model = CustomUser
#     fieldsets = (
#         # Other fieldsets

#         ('Group Permissions', {
#             'fields': ('groups', 'user_permissions', )
#         }),
#     )

admin.site.register(CustomUser)