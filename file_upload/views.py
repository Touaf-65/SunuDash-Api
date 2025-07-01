from django.shortcuts import render
from django.http import FileResponse
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from users.permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin
from .models import File
from .serializers import FileSerializer
from .functions import open_excel_csv, generate_no_conformity_excel
from .analysis import compare_data, preparing_data
from .importer import import_data

import os

class FileListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin|IsTerritorialAdmin]

    def get(self, request):
        files = File.objects.all().order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class StatisticalFileListView(ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin|IsTerritorialAdmin]
    
    def get(self, request):
        files = File.objects.filter(file_type='stat').order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class RecapFileListView(ListAPIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin|IsTerritorialAdmin]
    
    def get(self, request):
        files = File.objects.filter(file_type='recap').order_by("-uploaded_at")
        serializer = FileSerializer(files, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UploadFileView1(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


import traceback


class UploadAndValidateFiles(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser|IsGlobalAdmin|IsTerritorialAdmin]

    expected_stat_headers = [
        "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
        "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
        "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
        "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
        "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
        "Note Générale", "Numero de Facture", "Modifié par"
    ]

    expected_recap_headers = [
        "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
        "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
        "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
    ]

    def post(self, request):
        file_stat = request.FILES.get('file_stat')
        file_recap = request.FILES.get('file_recap')

        if not file_stat or not file_recap:
            return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            df_stat = open_excel_csv(file_stat)
            df_recap = open_excel_csv(file_recap)

            missing_stat = [h for h in self.expected_stat_headers if h not in df_stat.columns]
            missing_recap = [h for h in self.expected_recap_headers if h not in df_recap.columns]

            if missing_stat or missing_recap:
                return Response({
                    "errors": {
                        "stat_file_missing": missing_stat,
                        "recap_file_missing": missing_recap
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            df_stat, df_recap = preparing_data(df_stat, df_recap)

            df_conformes, df_non_conformes, common_range = compare_data(df_stat, df_recap)

            if common_range is None:
                return Response({
                    "error": "Les fichiers ne couvrent pas de période commune."
                }, status=status.HTTP_400_BAD_REQUEST)

            if df_conformes.empty and df_non_conformes.empty:
                return Response({
                    "warning": "Aucune donnée exploitable dans la période commune. Les deux fichiers sont invalides."
                }, status=status.HTTP_204_NO_CONTENT)

            if df_conformes.empty:
                print(f"# views: df conforme vide")
                file_path = generate_no_conformity_excel(df_non_conformes, df_stat, df_recap)
                return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=os.path.basename(file_path))

            file_instance = File.objects.create(
                file=file_stat,
                file_type='stat',
                user=request.user,
                country=request.user.country,
            )

            import_data(df_conformes, request.user, file_instance)

            if df_non_conformes.empty:
                return Response({
                    "message": "Les deux fichiers sont conformes.",
                    # "imported_count": nb_imported,
                    "date_range": {
                        "start": str(common_range[0]),
                        "end": str(common_range[1])
                    }
                }, status=status.HTTP_201_CREATED)

            # Générer le fichier de non-conformité
            file_path = generate_no_conformity_excel(df_non_conformes, df_stat, df_recap)
            return FileResponse(open(file_path, 'rb'), as_attachment=True, filename=os.path.basename(file_path))

        except Exception as e:
            print("Traceback de l'erreur :")
            print(traceback.format_exc())  
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# import pandas as pd
# from rest_framework.response import Response
# from django.core.files.storage import default_storage
# from .functions import open_excel_csv
# from .analysis import clean_recap_data, clean_statistic_data, compare_data

# import tempfile


# class UploadAndValidateFiles(APIView):
#     #permission_classes = [IsAuthenticated]

#     expected_stat_headers = [
#         "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
#         "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
#         "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
#         "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
#         "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
#         "Note Générale", "Numero de Facture", "Modifié par"
#     ]

#     expected_recap_headers = [
#         "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
#         "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
#         "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
#     ]

#     def post(self, request):
#         # Récupérer les fichiers
#         file_stat = request.FILES.get('file_stat')
#         file_recap = request.FILES.get('file_recap')

#         # Vérifier que les fichiers sont fournis
#         if not file_stat or not file_recap:
#             return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Lire le fichier statistique et vérifier les en-têtes
#             df_stat = open_excel_csv(file_stat)
#             stat_headers = df_stat.columns.tolist()

#             missing_stat_headers = [header for header in self.expected_stat_headers if header not in stat_headers]
#             if missing_stat_headers:
#                 return Response({"errors": f"Les en-têtes manquants dans le fichier statistique : {', '.join(missing_stat_headers)}."},
#                                 status=status.HTTP_400_BAD_REQUEST)

#             # Lire le fichier récap et vérifier les en-têtes
#             df_recap = open_excel_csv(file_recap)
#             recap_headers = df_recap.columns.tolist()

#             missing_recap_headers = [header for header in self.expected_recap_headers if header not in recap_headers]
#             if missing_recap_headers:
#                 return Response({"errors": f"Les en-têtes manquants dans le fichier récap : {', '.join(missing_recap_headers)}."},
#                                 status=status.HTTP_400_BAD_REQUEST)


#             # Intégration de la fonction compare_data
#             comparison_result, common_range = compare_data(df_stat, df_recap)

#             if isinstance(comparison_result, pd.DataFrame):
#                 # Si il y a des non-conformités, renvoyer le DataFrame
#                 return Response({"date_range_start": {common_range[0]}, "date_range_end": {common_range[1]}, "non_conformities": comparison_result.to_dict(orient='records')}) #, status=status.HTTP_400_BAD_REQUEST)
            


#             return Response({f"message": "Les fichiers compris entre {common_range[0]} et {common_range[1]} ont été validés et enregistrés avec succès."}, status=status.HTTP_201_CREATED)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
class UploadAndValidateFiles(APIView):
    permission_classes = [IsAuthenticated]

    expected_stat_headers = [
        "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
        "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
        "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
        "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
        "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
        "Note Générale", "Numero de Facture", "Modifié par"
    ]

    expected_recap_headers = [
        "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
        "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
        "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
    ]

    def post(self, request):
        # Récupérer les fichiers
        file_stat = request.FILES.get('file_stat')
        file_recap = request.FILES.get('file_recap')

        # Vérifier que les fichiers sont fournis
        if not file_stat or not file_recap:
            return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier statistique et vérifier les en-têtes
            df_stat = open_excel_csv(file_stat)
            stat_headers = df_stat.columns.tolist()

            missing_stat_headers = [header for header in self.expected_stat_headers if header not in stat_headers]
            if missing_stat_headers:
                return Response({"errors": f"Les en-têtes manquants dans le fichier statistique : {', '.join(missing_stat_headers)}."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Lire le fichier récap et vérifier les en-têtes
            df_recap = open_excel_csv(file_recap)
            recap_headers = df_recap.columns.tolist()

            missing_recap_headers = [header for header in self.expected_recap_headers if header not in recap_headers]
            if missing_recap_headers:
                return Response({"errors": f"Les en-têtes manquants dans le fichier récap : {', '.join(missing_recap_headers)}."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Nettoyer les données
            df_stat = clean_statistic_data(df_stat)
            df_recap = clean_recap_data(df_recap)

            # Intégration de la fonction compare_data
            comparison_result = compare_data(df_stat, df_recap)

            if isinstance(comparison_result, pd.DataFrame):
                # Si il y a des non-conformités, renvoyer le DataFrame
                return Response({"non_conformities": comparison_result.to_dict(orient='records')}, status=status.HTTP_400_BAD_REQUEST)

            # Si tout est conforme
            return Response({"message": "Les fichiers ont été validés et enregistrés avec succès."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
"""


# class UploadAndValidateFiles(APIView):
#     permission_classes = [IsAuthenticated]

#     expected_stat_headers = [
#         "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
#         "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
#         "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
#         "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
#         "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
#         "Note Générale", "Numero de Facture", "Modifié par"
#     ]

#     expected_recap_headers = [
#         "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
#         "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
#         "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
#     ]

#     def post(self, request):
#         # Récupérer les fichiers
#         file_stat = request.FILES.get('file_stat')
#         file_recap = request.FILES.get('file_recap')

#         # Vérifier que les fichiers sont fournis
#         if not file_stat or not file_recap:
#             return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Utiliser des fichiers temporaires
#             with tempfile.NamedTemporaryFile(delete=True) as stat_temp_file, \
#                  tempfile.NamedTemporaryFile(delete=True) as recap_temp_file:
                
#                 # Écrire le contenu des fichiers uploadés dans les fichiers temporaires
#                 for chunk in file_stat.chunks():
#                     stat_temp_file.write(chunk)
#                 for chunk in file_recap.chunks():
#                     recap_temp_file.write(chunk)

#                 # Assurez-vous que les fichiers temporaires sont bien enregistrés
#                 stat_temp_file.flush()  # S'assurer que le contenu est écrit
#                 recap_temp_file.flush()

#                 # Lire les fichiers Excel
#                 df_stat = pd.read_excel(stat_temp_file.name)
#                 df_recap = pd.read_excel(recap_temp_file.name)

#                 # Vérifier les en-têtes
#                 stat_headers = df_stat.columns.tolist()
#                 recap_headers = df_recap.columns.tolist()

#                 errors = []

#                 # Vérification des en-têtes du fichier statistique
#                 missing_stat_headers = [header for header in self.expected_stat_headers if header not in stat_headers]
#                 if missing_stat_headers:
#                     errors.append(f"Les en-têtes manquants dans le fichier statistique : {', '.join(missing_stat_headers)}.")

#                 # Vérification des en-têtes du fichier récap
#                 missing_recap_headers = [header for header in self.expected_recap_headers if header not in recap_headers]
#                 if missing_recap_headers:
#                     errors.append(f"Les en-têtes manquants dans le fichier récap : {', '.join(missing_recap_headers)}.")

#                 if errors:
#                     return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

#                 # Si tout est correct, renvoyer un message de succès
#                 return Response({"message": "Les fichiers ont été validés avec succès."}, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# class UploadAndValidateFiles(APIView):
#     permission_classes = [IsAuthenticated]

#     expected_stat_headers = [
#         "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
#         "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
#         "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
#         "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
#         "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
#         "Note Générale", "Numero de Facture", "Modifié par"
#     ]

#     expected_recap_headers = [
#         "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
#         "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
#         "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
#     ]

#     def post(self, request):
#         # Récupérer les fichiers
#         file_stat = request.FILES.get('file_stat')
#         file_recap = request.FILES.get('file_recap')

#         # Vérifier que les fichiers sont fournis
#         if not file_stat or not file_recap:
#             return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

#         try:
#             # Utiliser des fichiers temporaires
#             with tempfile.NamedTemporaryFile(delete=True) as stat_temp_file, \
#                  tempfile.NamedTemporaryFile(delete=True) as recap_temp_file:
                
#                 # Écrire le contenu des fichiers uploadés dans les fichiers temporaires
#                 for chunk in file_stat.chunks():
#                     stat_temp_file.write(chunk)
#                 for chunk in file_recap.chunks():
#                     recap_temp_file.write(chunk)

#                 # Assurez-vous que les fichiers temporaires sont bien enregistrés
#                 stat_temp_file.flush()  # S'assurer que le contenu est écrit
#                 recap_temp_file.flush()

#                 # Lire les fichiers Excel
#                 df_stat = pd.read_excel(stat_temp_file.name)
#                 df_recap = pd.read_excel(recap_temp_file.name)

#                 # Vérifier les en-têtes
#                 stat_headers = df_stat.columns.tolist()
#                 recap_headers = df_recap.columns.tolist()

#                 errors = []

#                 print(f'stat headers : {stat_headers}')
#                 if stat_headers != self.expected_stat_headers:
#                     errors.append("Les en-têtes du fichier statistique ne sont pas corrects.")

#                 if recap_headers != self.expected_recap_headers:
#                     errors.append("Les en-têtes du fichier récap ne sont pas corrects.")

#                 if errors:
#                     return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

#                 # Si tout est correct, renvoyer un message de succès
#                 return Response({"message": "Les fichiers ont été validés avec succès."}, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# class UploadAndValidateFiles(APIView):
#     permission_classes = [IsAuthenticated]

#     # En-têtes attendus pour les fichiers
#     expected_stat_headers = [
#         "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
#         "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
#         "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
#         "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
#         "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
#         "Note Générale", "Numero de Facture", "Modifié par"
#     ]

#     expected_recap_headers = [
#         "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
#         "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
#         "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
#     ]

#     def post(self, request):
#         # Récupérer les fichiers
#         file_stat = request.FILES.get('file_stat')
#         file_recap = request.FILES.get('file_recap')

#         # Vérifier que les fichiers sont fournis
#         if not file_stat or not file_recap:
#             return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

#         # Stocker les fichiers temporairement
#         stat_path = default_storage.save(file_stat.name, file_stat)
#         recap_path = default_storage.save(file_recap.name, file_recap)

#         try:
#             # Lire les fichiers Excel
#             df_stat = pd.read_excel(stat_path)
#             df_recap = pd.read_excel(recap_path)

#             # Vérifier les en-têtes
#             stat_headers = df_stat.columns.tolist()
#             recap_headers = df_recap.columns.tolist()

#             errors = []

#             if stat_headers != self.expected_stat_headers:
#                 errors.append("Les en-têtes du fichier statistique ne sont pas corrects.")

#             if recap_headers != self.expected_recap_headers:
#                 errors.append("Les en-têtes du fichier récap ne sont pas corrects.")

#             if errors:
#                 return Response({"errors": errors}, status=status.HTTP_400_BAD_REQUEST)

#             # Si tout est correct, renvoyer un message de succès
#             return Response({"message": "Les fichiers ont été validés avec succès."}, status=status.HTTP_200_OK)

#         except Exception as e:
#             return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#         finally:
#             # Supprimer les fichiers temporaires
#             default_storage.delete(stat_path)
#             default_storage.delete(recap_path)



"""

j'avais deja une vue pour uploader un fichier:

class UploadFileView1(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = FileSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

et voici mon model pour les fichiers:

from django.db import models
from users.models import CustomUser as User

class File(models.Model):
    FILE_TYPE_CHOICES = [
        ('stat', 'Fichier Statistique'),
        ('recap', 'Fichier Récap'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to='uploads/')
    file_type = models.CharField(max_length=5, choices=FILE_TYPE_CHOICES)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    size = models.PositiveIntegerField()

    def save(self, *args, **kwargs):
        self.size = self.file.size
        super().save(*args, **kwargs)

    def __str__(self):
        return self.file.name

        

"""



"""

class UploadAndValidateFiles(APIView):
    permission_classes = [IsAuthenticated]

    expected_stat_headers = [
        "Nom Employeur", "Broker Name", "Nom bénéficiaire", "Acte_Contraté_Assuré",
        "Statut Assuré", "Numero de police", "Nom Assuré Principal", "Nom du partenaire",
        "Adresse du Partenaire", "Pays du partenaire", "Numero de sinistre", "Statut",
        "Date de sinistre", "Date de règlement", "Categorie d'acte", "Famille Acte",
        "Nom Acte", "Montant facturé", "N°cheque/Autre_Moyent_de_payement",
        "Note Générale", "Numero de Facture", "Modifié par"
    ]

    expected_recap_headers = [
        "reglementId", "date_reglement", "beneficiaire", "N°_Cheque",
        "autres_Moyen_de_payement", "partnerId", "Assurés_principal", "Employeur",
        "N°_police", "totalmttreclame", "totalmttrembourse", "NumFacture", "Note"
    ]

    def post(self, request):
        # Récupérer les fichiers
        file_stat = request.FILES.get('file_stat')
        file_recap = request.FILES.get('file_recap')

        # Vérifier que les fichiers sont fournis
        if not file_stat or not file_recap:
            return Response({"error": "Les deux fichiers doivent être fournis."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Lire le fichier statistique et vérifier les en-têtes
            df_stat = pd.read_excel(file_stat)
            stat_headers = df_stat.columns.tolist()

            missing_stat_headers = [header for header in self.expected_stat_headers if header not in stat_headers]
            if missing_stat_headers:
                return Response({"errors": f"Les en-têtes manquants dans le fichier statistique : {', '.join(missing_stat_headers)}."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Lire le fichier récap et vérifier les en-têtes
            df_recap = pd.read_excel(file_recap)
            recap_headers = df_recap.columns.tolist()

            missing_recap_headers = [header for header in self.expected_recap_headers if header not in recap_headers]
            if missing_recap_headers:
                return Response({"errors": f"Les en-têtes manquants dans le fichier récap : {', '.join(missing_recap_headers)}."},
                                status=status.HTTP_400_BAD_REQUEST)

            # Enregistrer les fichiers dans le modèle File
            stat_file_instance = File(user=request.user, file=file_stat, file_type='stat')
            stat_file_instance.save()

            recap_file_instance = File(user=request.user, file=file_recap, file_type='recap')
            recap_file_instance.save()

            return Response({"message": "Les fichiers ont été validés et enregistrés avec succès."}, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


comment verifier si chacun des fichiers fournis est excel ou csv et personnonalier leur ouverture vu que pour excel c'est pd.read_excel() et pd.read_csv() pour csv

"""