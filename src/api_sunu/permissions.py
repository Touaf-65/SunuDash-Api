from rest_framework.permissions import BasePermission

class IsGlobalAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_global_admin()

class IsTerritorialAdmin(BasePermission):
    def has_permission(self, request, view):
        return (request.user.is_authenticated and request.user.is_territorial_admin())  