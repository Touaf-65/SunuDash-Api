from rest_framework.permissions import BasePermission


class IsSuperUser(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_superuser_role()
    
class IsGlobalAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin_global()

class IsTerritorialAdmin(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_admin_territorial()

class IsTerritorialAdminWithCountry(BasePermission):
    def has_permission(self, request, view):
        user = request.user
        if user.is_authenticated and hasattr(user, 'role') and hasattr(user, 'country'):
            if user.role == user.Roles.ADMIN_TERRITORIAL:
                if user.country is None:
                    # Optionnel: on peut aussi lever une exception DRF pour customiser le message
                    return False
        return True

class IsChefDeptTech(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_chef_dept_tech()

class IsResponsableOperateur(BasePermission):
    def has_permission(self, request, view):
        return request.user.is_authenticated and request.user.is_responsable_operateur()