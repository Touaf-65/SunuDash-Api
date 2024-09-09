from rest_framework import serializers
from .models import CustomUser, Country
from django.contrib.auth.models import User
from .models import PasswordResetToken


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country 
        fields = ('id', 'name', 'code')


class UserSerializer(serializers.ModelSerializer):
    country = serializers.PrimaryKeyRelatedField(queryset=Country.objects.all(), required=True)
    
    class Meta:
        model = CustomUser
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'country')

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("Email address not found.")
        return value

class PasswordResetConfirmSerializer(serializers.Serializer):
    token = serializers.UUIDField()
    new_password = serializers.CharField(write_only=True, min_length=8)

    def validate_token(self, value):
        if not PasswordResetToken.objects.filter(token=value, user__is_active=True).exists():
            raise serializers.ValidationError("Invalid or expired token.")
        return value