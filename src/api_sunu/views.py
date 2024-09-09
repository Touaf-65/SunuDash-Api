from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .models import CustomUser, Country, PasswordResetToken
from .serializers import UserSerializer, CountrySerializer, PasswordResetConfirmSerializer, PasswordResetRequestSerializer
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsGlobalAdmin, IsTerritorialAdmin
from django.contrib.auth.models import Group, User
import random
import string

class register_user(APIView):
    def post(self, request):
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        from_email = settings.EMAIL_HOST_USER
        
        if not (first_name and last_name and email):
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)
        
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        print(password)
        try:
            user = CustomUser.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            send_mail(
                'Your new account',  
                f'Your username is {user.username} and your password is {password}',
                from_email,
                [email],
                fail_silently=False
            )
        except Exception as e:
            return Response({'error': 'Failed to send email'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class login_user(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        
        if not (username and password):
            return Response({'error': 'Username and Password are required'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid username or password."}, status=status.HTTP_401_UNAUTHORIZED)

class ManageUsersView(APIView):
    permission_classes = [IsGlobalAdmin | IsTerritorialAdmin]

    def post(self, request):
    # Add your logic here to manage users
        return Response({"message": "Action réussie."}, status=status.HTTP_200_OK)

class CountryView(APIView):
    """
    Vue pour que l'admin global puisse créer des pays.
    """
    permission_classes = [IsAuthenticated, IsGlobalAdmin]
    def post(self, request):
        name = request.data.get('name')
        code = request.data.get('code')
        
        if not (name and code):
            return Response({"error": "Name and code are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        country = Country.objects.create(name=name, code=code)
        serializer = CountrySerializer(country)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class AssignTerritorialAdmin(APIView):
    """
    Vue pour assigner un admin territorial à un pays.
    """
    permission_classes = [IsAuthenticated, IsGlobalAdmin]
    def post(self, request):
        admin_email = request.data.get('email')
        country_id = request.data.get('country_id')

        try:
            admin = CustomUser.objects.get(email=admin_email)
            country = Country.objects.get(id=country_id)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except Country.DoesNotExist:
            return Response({"error": "Country not found."}, status=status.HTTP_404_NOT_FOUND)

        admin.country = country
        admin.groups.add(Group.objects.get(name='Territorial Admin'))
        admin.save()
        
        return Response({"message": f"{admin.email} assigned as admin of {country.name}"}, status=status.HTTP_200_OK)
    

class ListCountriesView(APIView):
    """
    Vue pour lister les pays créés par l'admin global.
    """
    def get(self, request):
        countries = Country.objects.all()
        serializer = CountrySerializer(countries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CreateUserByTerritorialAdmin(APIView):
    """
    Vue pour permettre aux admins territoriaux de créer des utilisateurs dans leur propre pays.
    """
    permission_classes = [IsAuthenticated, IsTerritorialAdmin]
    def post(self, request):
        if not request.user.is_territorial_admin():
            return Response({"error": "Only territorial admins can create users."}, status=status.HTTP_403_FORBIDDEN)

        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        from_email = settings.EMAIL_HOST_USER
        
        if not (first_name and last_name and email):
            return Response({"error": "Missing fields."}, status=status.HTTP_400_BAD_REQUEST)

        password = ''.join(random.choices(string.ascii_letters + string.digits, k=8))

        user = CustomUser.objects.create_user(
            first_name=first_name,
            last_name=last_name,
            email=email,
            password=password,
            country=request.user.country
        )
        
        send_mail(
            'Account created',
            f'Your username is {user.username} and your password is {password}',
            from_email,
            [email],
            fail_silently=False,
        )

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)
            from_email = settings.EMAIL_HOST_USER
            
            token = PasswordResetToken.objects.create(user=user)
            
            reset_link = f"https://sunu-dash.netlify.app/password_reset_confirm/{token.token}/"
            send_mail(
                'Password Reset Request',
                f'Click the link to reset your password: {reset_link}',
                from_email,
                [user.email],
                fail_silently=False,
            )
            return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['new_password']

            try:
                reset_token = PasswordResetToken.objects.get(token=token)
                if reset_token.is_expired():
                    return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetToken.DoesNotExist:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
            
            user = reset_token.user
            user.set_password(new_password)
            user.save()

            reset_token.delete()

            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

