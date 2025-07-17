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
from django.db.models import Q
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin, IsTerritorialAdminWithCountry 
import random
import string
import os
import pandas as pd

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model

class SuperuserCreateAPIView(APIView):
    """
    API temporaire pour créer le superuser via une requête POST.
    Désactivée automatiquement dès qu'un superuser existe.
    """

    def post(self, request):

        if CustomUser.objects.filter(is_superuser=True).exists():
            return Response({'detail': 'Superuser already exists.'}, status=status.HTTP_403_FORBIDDEN)
        required_fields = ['first_name', 'last_name', 'email']
        for field in required_fields:
            if not request.data.get(field):
                return Response({'detail': f'{field} is required.'}, status=status.HTTP_400_BAD_REQUEST)

        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        from_email = settings.EMAIL_HOST_USER


        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(12))

        try:
            user = CustomUser.objects.create_superuser(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password,
                is_staff=True,
                is_superuser=True,
            )
            user.role = CustomUser.Roles.SUPERUSER
            user.save()
        except Exception as e:
            return Response({'detail': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'users.txt')

        with open(file_path, 'a') as file:
            file.write(f'Username: {user.username}, Password: {password}\n')

        try:
            send_mail(
                'Votre compte superuser a été créé',
                f'Bonjour {user.first_name},\n\nVotre nom d\'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : Superuser.\n\nMerci de changer votre mot de passe après votre première connexion.',
                from_email,
                [email],
                fail_silently=False,
                html_message=f"""
                <html>
                <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                    <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                        <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                        <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                        <p style='font-size: 16px; color: #222;'>Votre compte <b>Superuser</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                        <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                            <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                            <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                            <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>Superuser</span></li>
                        </ul>
                        <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                        <hr style='margin: 28px 0;'>
                        <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                    </div>
                </body>
                </html>
                """
            )
        except Exception as e:
            return Response({'detail': f'User created but failed to send email: {str(e)}'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({'detail': 'Superuser created successfully. Identifiants envoyés par email.'}, status=status.HTTP_201_CREATED)


class register_user(APIView):
    def post(self, request):
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        from_email = settings.EMAIL_HOST_USER
        
        if not (first_name and last_name and email):
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)
        
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        

        try:
            user = CustomUser.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password
            )

            print(f"Password: {password}")
            print(f"Created User : {user}")
            
            
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'users.txt')

        # Écrire dans le fichier texte
        with open(file_path, 'a') as file:
            file.write(f'Username: {user.username}, Password: {password}\n')
        
        try:
            send_mail(
                'Your new account',  
                f'Your username is {user.username} and your password is {password}',
                from_email,
                [email],
                fail_silently=False
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class login_user(APIView):
    def post(self, request):
        login = request.data.get('login')
        password = request.data.get('password')
        
        if not (login and password):
            return Response({'error': 'Login (username ou email) et Password sont requis'}, status=status.HTTP_400_BAD_REQUEST)
        
        user = authenticate(username=login, password=password)
        
        print(f"Logged User: {user}")

        if user is not None:
            refresh = RefreshToken.for_user(user)
            return Response({
                'access_token': str(refresh.access_token),
                'refresh_token': str(refresh)
            }, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Identifiants invalides."}, status=status.HTTP_401_UNAUTHORIZED)



class GetConnectedUserByLogin(APIView):

    def get(self, request, login):
        try:
            user = CustomUser.objects.filter(Q(username=login) | Q(email=login)).select_related('country').first()
            if not user:
                return Response({'error': 'Utilisateur non trouvé.'}, status=status.HTTP_404_NOT_FOUND)
            data = {
                'id': user.id,
                'role': user.role,
                'country': {'id': user.country.id, 'name': user.country.name} if user.country else None,
                'email': user.email,
                'username': user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
            }
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CreateGlobalAdminView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]
    def post(self, request):
        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        from_email = settings.EMAIL_HOST_USER
            
        if not (first_name and last_name and email):
            return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)
            
        password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            

        try:
            user = CustomUser.objects.create_user(
                first_name=first_name,
                last_name=last_name,
                email=email,
                password=password,
                is_staff=True
            )
            user.role = CustomUser.Roles.ADMIN_GLOBAL
            user.save()
            print(f"Password: {password}")
            print(f"Created User : {user}")
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'global_users.txt')
        # Écrire dans le fichier texte
        with open(file_path, 'a') as file:
            file.write(f'Username: {user.username}, Password: {password}\n')

        try:
            send_mail(
                'Votre nouveau compte Administrateur Global',
                f"Bonjour {user.first_name},\n\nVotre nom d'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : Administrateur Global.\n\nMerci de changer votre mot de passe après votre première connexion.",
                from_email,
                [email],
                fail_silently=False,
                html_message=f"""
                <html>
                <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                    <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                        <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                        <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                        <p style='font-size: 16px; color: #222;'>Votre compte <b>Administrateur Global</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                        <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                            <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                            <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                            <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>Administrateur Global</span></li>
                        </ul>
                        <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                        <hr style='margin: 28px 0;'>
                        <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                    </div>
                </body>
                </html>
                """
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CreateGlobalAdminsFromExcel(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]

    def post(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier Excel
            df = pd.read_excel(file)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier les en-têtes du fichier Excel
        required_headers = ['firstname', 'lastname', 'email']
        if not all(header in df.columns for header in required_headers):
            return Response({'error': 'Missing required headers in the Excel file'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier la conformité des adresses e-mail
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        valid_rows = df[df['email'].str.match(email_regex)].index.tolist()
        invalid_rows = df[~df['email'].str.match(email_regex)].index.tolist()

        # Créer les administrateurs globaux avec les adresses e-mail valides
        created_users = []
        for row_idx in valid_rows:
            first_name = df.loc[row_idx, 'firstname']
            last_name = df.loc[row_idx, 'lastname']
            email = df.loc[row_idx, 'email']

            try:
                password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                user = CustomUser.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=password,
                    is_staff=True
                )

                user.role = CustomUser.Roles.ADMIN_GLOBAL
                user.save()

                file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'global_users.txt')
                with open(file_path, 'a') as f:
                    f.write(f'Username: {user.username}, Password: {password}\n')

                send_mail(
                    'Votre nouveau compte Administrateur Global',
                    f'Bonjour {user.first_name},\n\nVotre nom d\'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : Administrateur Global.\n\nMerci de changer votre mot de passe après votre première connexion.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    html_message=f"""
                    <html>
                    <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                        <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                            <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                            <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                            <p style='font-size: 16px; color: #222;'>Votre compte <b>Administrateur Global</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                            <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                                <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                                <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                                <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>Administrateur Global</span></li>
                            </ul>
                            <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                            <hr style='margin: 28px 0;'>
                            <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                        </div>
                    </body>
                    </html>
                    """
                )

                created_users.append(user)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Renvoyer les numéros de ligne des adresses e-mail non valides
        if invalid_rows:
            return Response({'error': f'Invalid email addresses in rows: {", ".join(map(str, invalid_rows))}'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(created_users, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class GlobalAdminListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]

    def get(self, request):
        users = CustomUser.objects.filter(role=CustomUser.Roles.ADMIN_GLOBAL)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class GlobalAdminDetailView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]

    def get(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_GLOBAL)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Administrateur global non trouvé'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

class GlobalAdminUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]

    def put(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_GLOBAL)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Administrateur global non trouvé'}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GlobalAdminDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser]

    def delete(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_GLOBAL)
        except CustomUser.DoesNotExist:
            return Response({'error': 'Administrateur global non trouvé'}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CreateCountryView(APIView):
    """
    Vue pour que l'admin global puisse créer des pays.
    """
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def post(self, request):
        name = request.data.get('name')
        code = request.data.get('code')

        if not (name and code):
            return Response({"error": "Name and code are required."}, status=status.HTTP_400_BAD_REQUEST)
        
        country = Country.objects.create(name=name, code=code)
        serializer = CountrySerializer(country)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class CreateCountryFromExcel(APIView):
    """
    Vue pour que l'admin global puisse créer des pays.
    """
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def post(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier Excel
            df = pd.read_excel(file)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier les en-têtes du fichier Excel
        required_headers = ['name', 'code']
        if not all(header in df.columns for header in required_headers):
            return Response({'error': 'Missing required headers in the Excel file'}, status=status.HTTP_400_BAD_REQUEST)

        # Créer les pays avec les données valides
        created_countries = []
        for _, row in df.iterrows():
            name = row['name']
            code = row['code']

            try:
                country = Country.objects.create(name=name, code=code)
                created_countries.append(country)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        serializer = CountrySerializer(created_countries, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class ListCountriesView(APIView):
    """
    Vue pour lister les pays créés par l'admin global.
    """
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def get(self, request):
        countries = Country.objects.all()
        serializer = CountrySerializer(countries, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CountryDetailView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def get(self, request, pk):
        try:
            country = Country.objects.get(pk=pk)
        except Country.DoesNotExist:
            return Response({"error": "Country not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = CountrySerializer(country)
        return Response(serializer.data, status=status.HTTP_200_OK)

class CountryUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def put(self, request, pk):
        try:
            country = Country.objects.get(pk=pk)
        except Country.DoesNotExist:
            return Response({"error": "Country not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = CountrySerializer(country, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CountryDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def delete(self, request, pk):
        try:
            country = Country.objects.get(pk=pk)
        except Country.DoesNotExist:
            return Response({"error": "Country not found."}, status=status.HTTP_404_NOT_FOUND)

        country.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CreateTerritorialAdminView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def post(self, request):
        if request.user.is_superuser or request.user.is_admin_global():
            first_name = request.data.get('first_name')
            last_name = request.data.get('last_name')
            email = request.data.get('email')
            from_email = settings.EMAIL_HOST_USER
            
            if not (first_name and last_name and email):
                return Response({'error': 'Missing required fields'}, status=status.HTTP_400_BAD_REQUEST)
            
            password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
            

            try:
                user = CustomUser.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=password,
                    is_staff=True
                )
                user.role = CustomUser.Roles.ADMIN_TERRITORIAL
                user.save()
                print(f"Password: {password}")
                print(f"Created User : {user}")
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'territorial_users.txt')
            # Écrire dans le fichier texte
            with open(file_path, 'a') as file:
                file.write(f'Username: {user.username}, Password: {password}\n')

            try:
                send_mail(
                    'Votre nouveau compte Administrateur Territorial',
                    f'Bonjour {user.first_name},\n\nVotre nom d\'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : Administrateur Territorial.\n\nMerci de changer votre mot de passe après votre première connexion.',
                    from_email,
                    [email],
                    fail_silently=False,
                    html_message=f"""
                    <html>
                    <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                        <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                            <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                            <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                            <p style='font-size: 16px; color: #222;'>Votre compte <b>Administrateur Territorial</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                            <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                                <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                                <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                                <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>Administrateur Territorial</span></li>
                            </ul>
                            <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                            <hr style='margin: 28px 0;'>
                            <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                        </div>
                    </body>
                    </html>
                    """
                )
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)    


class CreateTerritorialAdminsFromExcel(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]

    def post(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier Excel
            df = pd.read_excel(file)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier les en-têtes du fichier Excel
        required_headers = ['firstname', 'lastname', 'email']
        if not all(header in df.columns for header in required_headers):
            return Response({'error': 'Missing required headers in the Excel file'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier la conformité des adresses e-mail
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        valid_rows = df[df['email'].str.match(email_regex)].index.tolist()
        invalid_rows = df[~df['email'].str.match(email_regex)].index.tolist()

        # Créer les administrateurs territoriaux avec les adresses e-mail valides
        created_users = []
        for row_idx in valid_rows:
            first_name = df.loc[row_idx, 'firstname']
            last_name = df.loc[row_idx, 'lastname']
            email = df.loc[row_idx, 'email']

            try:
                password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                user = CustomUser.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=password,
                    is_staff=True
                )

                user.role = CustomUser.Roles.ADMIN_TERRITORIAL
                user.save()

                created_users.append(user)

                file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'territorial_users.txt')
                with open(file_path, 'a') as f:
                    f.write(f'Username: {user.username}, Password: {password}\n')

                send_mail(
                    'Votre nouveau compte Administrateur Territorial',
                    f'Bonjour {user.first_name},\n\nVotre nom d\'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : Administrateur Territorial.\n\nMerci de changer votre mot de passe après votre première connexion.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    html_message=f"""
                    <html>
                    <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                        <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                            <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                            <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                            <p style='font-size: 16px; color: #222;'>Votre compte <b>Administrateur Territorial</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                            <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                                <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                                <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                                <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>Administrateur Territorial</span></li>
                            </ul>
                            <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                            <hr style='margin: 28px 0;'>
                            <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                        </div>
                    </body>
                    </html>
                    """
                )
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Renvoyer les numéros de ligne des adresses e-mail non valides
        if invalid_rows:
            return Response({'error': f'Invalid email addresses in rows: {", ".join(map(str, invalid_rows))}'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(created_users, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class TerritorialAdminListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def get(self, request):
        territorial_admins = CustomUser.objects.filter(role=CustomUser.Roles.ADMIN_TERRITORIAL)
        serializer = UserSerializer(territorial_admins, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TerritorialAdminDetailView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def get(self, request, pk):
        try:
            territorial_admin = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_TERRITORIAL)
        except CustomUser.DoesNotExist:
            return Response({"error": "Territorial admin not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(territorial_admin)
        return Response(serializer.data, status=status.HTTP_200_OK)


class TerritorialAdminUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def put(self, request, pk):
        try:
            territorial_admin = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_TERRITORIAL)
        except CustomUser.DoesNotExist:
            return Response({"error": "Territorial admin not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(territorial_admin, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class TerritorialAdminDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def delete(self, request, pk):
        try:
            territorial_admin = CustomUser.objects.get(pk=pk, role=CustomUser.Roles.ADMIN_TERRITORIAL)
        except CustomUser.DoesNotExist:
            return Response({"error": "Territorial admin not found."}, status=status.HTTP_404_NOT_FOUND)

        territorial_admin.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)



class AssignTerritorialAdmin(APIView):
    """
    Vue pour assigner un admin territorial à un pays.
    """
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin]
    def post(self, request):
        if request.user.is_superuser or request.user.is_admin_global():
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
            admin.save()

            from_email = settings.EMAIL_HOST_USER
            try:
                send_mail(
                    'Affectation à un pays sur Sunu Dash',
                    f'Bonjour {admin.first_name},\n\nVous avez été désigné comme administrateur territorial pour le pays : {country.name}. Connectez-vous à Sunu Dash pour accéder à vos nouvelles responsabilités.',
                    from_email,
                    [admin.email],
                    fail_silently=False,
                    html_message=f"""
                    <html>
                    <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                        <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                            <h2 style='color: #2d5be3; margin-bottom: 12px;'>Affectation à un pays</h2>
                            <p style='font-size: 16px; color: #222;'>Bonjour <strong>{admin.first_name}</strong>,</p>
                            <p style='font-size: 16px; color: #222;'>Vous avez été désigné comme <b>administrateur territorial</b> pour le pays&nbsp;: <span style='color: #2d5be3; font-weight: bold;'>{country.name}</span>.</p>
                            <p style='font-size: 15px; color: #444; margin-top: 20px;'>Connectez-vous à Sunu Dash pour accéder à vos nouvelles responsabilités et gérer les utilisateurs de ce pays.</p>
                            <hr style='margin: 28px 0;'>
                            <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                        </div>
                    </body>
                    </html>
                    """
                )
            except Exception as e:
                return Response({"message": f"{admin.email} assigned as admin of {country.name} mais l'email n'a pas pu être envoyé : {str(e)}"}, status=status.HTTP_200_OK)

            return Response({"message": f"{admin.email} assigned as admin of {country.name}"}, status=status.HTTP_200_OK)
        return Response({"detail": "Permission denied."}, status=status.HTTP_403_FORBIDDEN)    



class CreateUserByTerritorialAdmin(APIView):
    """
    Vue pour permettre aux admins territoriaux de créer des utilisateurs dans leur propre pays.
    """
    permission_classes = [IsAuthenticated, IsTerritorialAdmin, IsTerritorialAdminWithCountry]
    def post(self, request):
        if not request.user.is_territorial_admin():
            return Response({"error": "Only territorial admins can create users."}, status=status.HTTP_403_FORBIDDEN)

        first_name = request.data.get('first_name')
        last_name = request.data.get('last_name')
        email = request.data.get('email')
        role = request.data.get('role', CustomUser.Roles.RESPONSABLE_OPERATEUR)  # Par défaut Responsable Opérateur de Saisie
        from_email = settings.EMAIL_HOST_USER

        # Rôles autorisés pour un admin territorial
        allowed_roles = ['CHEF_DEPT_TECH', 'RESP_OPERATEUR']
        role_labels = {
            'CHEF_DEPT_TECH': 'Chef Département Technique',
            'RESP_OPERATEUR': 'Responsable Opérateur de Saisie'
        }
        if role not in allowed_roles:
            return Response({"error": "Rôle non autorisé pour un admin territorial."}, status=status.HTTP_400_BAD_REQUEST)

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
        user.role = role
        user.save()
        
        file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'simple_users.txt')

        # Écrire dans le fichier texte
        with open(file_path, 'a') as file:
            file.write(f'Username: {user.username}, Password: {password}\n')
        try:
            send_mail(
                f"Votre nouveau compte {role_labels.get(role, 'Utilisateur')}",
                f"Bonjour {user.first_name},\n\nVotre nom d'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : {role_labels.get(role, 'Utilisateur')}.\n\nMerci de changer votre mot de passe après votre première connexion.",
                from_email,
                [email],
                fail_silently=False,
                html_message=f"""
                <html>
                <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                    <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                        <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                        <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                        <p style='font-size: 16px; color: #222;'>Votre compte <b>{role_labels.get(role, 'Utilisateur')}</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                        <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                            <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                            <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                            <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>{role_labels.get(role, 'Utilisateur')}</span></li>
                        </ul>
                        <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                        <hr style='margin: 28px 0;'>
                        <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                    </div>
                </body>
                </html>
                """
            )
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

   

class CreateUsersByTerritorialAdminFromExcel(APIView):
    """
    Vue pour permettre aux admins territoriaux de créer des utilisateurs dans leur propre pays.
    """
    permission_classes = [IsAuthenticated, IsTerritorialAdmin, IsTerritorialAdminWithCountry]

    def post(self, request):
        file = request.FILES.get('file')
        if not file:
            return Response({'error': 'No file provided'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier Excel
            df = pd.read_excel(file)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier les en-têtes du fichier Excel
        required_headers = ['firstname', 'lastname', 'email', 'role']
        if not all(header in df.columns for header in required_headers):
            return Response({'error': 'Missing required headers in the Excel file'}, status=status.HTTP_400_BAD_REQUEST)

        # Vérifier la conformité des adresses e-mail
        email_regex = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        valid_rows = df[df['email'].str.match(email_regex)].index.tolist()
        invalid_rows = df[~df['email'].str.match(email_regex)].index.tolist()

        # Créer les utilisateurs avec les adresses e-mail valides
        created_users = []
        import unicodedata

        def normalize_role(val):
            if not isinstance(val, str):
                return ''
            # minuscules, sans accent, sans espaces ni underscores
            val = val.strip().lower()
            val = unicodedata.normalize('NFD', val)
            val = ''.join([c for c in val if unicodedata.category(c) != 'Mn'])
            val = val.replace('_', '').replace(' ', '')
            return val

        role_variants = {
            'CHEF_DEPT_TECH': [
                'chefdepartementtechnique', 'chefdepttech', 'chefdepartement', 'chefdept', 'cheftechnique', 'chef', 'cdt'
            ],
            'RESP_OPERATEUR': [
                'responsableoperateur', 'responsableoperateurdesaisie', 'responsableops', 'respoperateur', 'respops', 'ops', 'responsable', 'ro'
            ]
        }
        def map_role(val):
            norm = normalize_role(val)
            for key, variants in role_variants.items():
                if norm in variants:
                    return key
            return None

        role_labels = {
            'CHEF_DEPT_TECH': 'Chef Département Technique',
            'RESP_OPERATEUR': 'Responsable Opérateur de Saisie'
        }
        invalid_role_rows = []
        for row_idx in valid_rows:
            first_name = df.loc[row_idx, 'firstname']
            last_name = df.loc[row_idx, 'lastname']
            email = df.loc[row_idx, 'email']
            raw_role = df.loc[row_idx, 'role'] if 'role' in df.columns else ''
            role = map_role(raw_role)
            if role is None:
                invalid_role_rows.append(row_idx)
                continue
            try:
                password = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
                user = CustomUser.objects.create_user(
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    password=password,
                    country=request.user.country
                )
                user.role = role
                user.save()
                file_path = os.path.join(settings.BASE_DIR, 'users/users_txt', 'simple_users.txt')
                with open(file_path, 'a') as f:
                    f.write(f'Username: {user.username}, Password: {password}\n')
                send_mail(
                    f'Votre nouveau compte {role_labels.get(role, role)}',
                    f'Bonjour {user.first_name},\n\nVotre nom d\'utilisateur est : {user.username}\nVotre mot de passe est : {password}\nVotre rôle sur la plateforme est : {role_labels.get(role, role)}.\n\nMerci de changer votre mot de passe après votre première connexion.',
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    html_message=f"""
                            <html>
                            <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                                <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                                    <h2 style='color: #2d5be3; margin-bottom: 12px;'>Bienvenue sur Sunu Dash !</h2>
                                    <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                                    <p style='font-size: 16px; color: #222;'>Votre compte <b>{role_labels.get(role, role)}</b> a été créé avec succès. Voici vos identifiants&nbsp;:</p>
                                    <ul style='font-size: 16px; color: #222; list-style: none; padding: 0;'>
                                        <li><b>Nom d'utilisateur&nbsp;:</b> <span style='color: #2d5be3;'>{user.username}</span></li>
                                        <li><b>Mot de passe&nbsp;:</b> <span style='color: #2d5be3;'>{password}</span></li>
                                        <li><b>Rôle&nbsp;:</b> <span style='color: #2d5be3;'>{role_labels.get(role, role)}</span></li>
                                    </ul>
                                    <p style='font-size: 15px; color: #444; margin-top: 20px;'>Merci de changer votre mot de passe après votre première connexion pour garantir la sécurité de votre compte.</p>
                                    <hr style='margin: 28px 0;'>
                                    <p style='font-size: 13px; color: #999;'>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                                </div>
                            </body>
                            </html>
                            """
                        )

                created_users.append(user)
            except Exception as e:
                return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        # Renvoyer les numéros de ligne des adresses e-mail non valides
        if invalid_rows:
            return Response({'error': f'Invalid email addresses in rows: {", ".join(map(str, invalid_rows))}'}, status=status.HTTP_400_BAD_REQUEST)

        serializer = UserSerializer(created_users, many=True)
        return Response(serializer.data, status=status.HTTP_201_CREATED)
    

class SimpleUserListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def get(self, request):
        users = CustomUser.objects.exclude(
            role__in=[CustomUser.Roles.ADMIN_GLOBAL, CustomUser.Roles.ADMIN_TERRITORIAL]).exclude(is_superuser=True)
        serializer = UserSerializer(users, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class SimpleUserDetailView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def get(self, request, pk):
    
        try:
            user = CustomUser.objects.get(pk=pk)

            if user.is_superuser:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            if user.role in [CustomUser.Roles.ADMIN_GLOBAL, CustomUser.Roles.ADMIN_TERRITORIAL]:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            serializer = UserSerializer(user)
            return Response(serializer.data, status=status.HTTP_200_OK)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)


class SimpleUserUpdateView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def put(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)

            if user.is_superuser:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            if user.role in [CustomUser.Roles.ADMIN_GLOBAL, CustomUser.Roles.ADMIN_TERRITORIAL]:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except CustomUser.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SimpleUserDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def delete(self, request, pk):
        try:
            user = CustomUser.objects.get(pk=pk)

            if user.is_superuser:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)

            if user.role in [CustomUser.Roles.ADMIN_GLOBAL, CustomUser.Roles.ADMIN_TERRITORIAL]:
                return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        except CustomUser.DoesNotExist:
            return Response({"error": "Territorial admin not found."}, status=status.HTTP_404_NOT_FOUND)

        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PasswordResetRequestView(APIView):
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            user = CustomUser.objects.get(email=email)
            from_email = settings.EMAIL_HOST_USER
            
            token = PasswordResetToken.objects.create(user=user)

            reset_link = f"https://sunu-dash.netlify.app/auth/new-password/{token.token}/"
            send_mail(
                'Réinitialisation de votre mot de passe Sunu Dash',
                f'Bonjour {user.first_name},\n\nPour réinitialiser votre mot de passe, cliquez sur ce lien : {reset_link}\nCe lien expirera dans 24h.',
                from_email,
                [user.email],
                fail_silently=False,
                html_message=f"""
                <html>
                <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                    <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                        <h2 style='color: #2d5be3; margin-bottom: 12px;'>Réinitialisation de votre mot de passe</h2>
                        <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                        <p style='font-size: 16px; color: #222;'>Vous avez demandé la réinitialisation de votre mot de passe Sunu Dash.</p>
                        <p style='font-size: 16px; color: #222;'>Cliquez sur le bouton ci-dessous pour choisir un nouveau mot de passe&nbsp;:</p>
                        <div style='margin: 24px 0;'>
                            <a href='{reset_link}' style='background: #2d5be3; color: #fff; padding: 12px 24px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 16px;'>Réinitialiser mon mot de passe</a>
                        </div>
                        <p style='font-size: 14px; color: #555;'>Ce lien expirera dans 24 heures.</p>
                        <hr style='margin: 28px 0;'>
                        <p style='font-size: 13px; color: #999;'>Si vous n'êtes pas à l'origine de cette demande, ignorez cet email.<br>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                    </div>
                </body>
                </html>
                """
            )
            return Response({"message": "Password reset email sent."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            token = serializer.validated_data['token']
            new_password = serializer.validated_data['confirm_password']
            confirm_password = serializer.validated_data['confirm_password']
            from_email = settings.EMAIL_HOST_USER

            try:
                reset_token = PasswordResetToken.objects.get(token=token)
                print(reset_token)
                if reset_token.is_expired():
                    return Response({"error": "Token has expired."}, status=status.HTTP_400_BAD_REQUEST)
            except PasswordResetToken.DoesNotExist:
                return Response({"error": "Invalid token."}, status=status.HTTP_400_BAD_REQUEST)
            
            user = reset_token.user
            user.set_password(new_password)
            user.save()

            reset_token.delete()

            send_mail(
                'Votre mot de passe Sunu Dash a été réinitialisé',
                f'Bonjour {user.first_name},\n\nVotre mot de passe a bien été réinitialisé. Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.',
                from_email,
                [user.email],
                fail_silently=False,
                html_message=f"""
                <html>
                <body style='font-family: Arial, sans-serif; background: #f8f9fa; padding: 32px;'>
                    <div style='max-width: 480px; margin: auto; background: #fff; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.06); padding: 32px;'>
                        <h2 style='color: #2d5be3; margin-bottom: 12px;'>Mot de passe réinitialisé</h2>
                        <p style='font-size: 16px; color: #222;'>Bonjour <strong>{user.first_name}</strong>,</p>
                        <p style='font-size: 16px; color: #222;'>Votre mot de passe Sunu Dash a bien été réinitialisé.</p>
                        <p style='font-size: 15px; color: #444;'>Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.</p>
                        <hr style='margin: 28px 0;'>
                        <p style='font-size: 13px; color: #999;'>Si vous n'êtes pas à l'origine de cette action, contactez immédiatement un administrateur.<br>Ceci est un message automatique. Merci de ne pas répondre directement à cet email.</p>
                    </div>
                </body>
                </html>
                """
            )
            return Response({"message": "Password has been reset successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    