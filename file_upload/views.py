from django.shortcuts import render, get_object_or_404
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


class FileDeleteView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin | IsTerritorialAdmin]

    def delete(self, request, file_id):
        file = get_object_or_404(File, id=file_id)

        # Optionnel : autoriser uniquement l'utilisateur propriétaire ou un admin
        if request.user != file.user and not (
            request.user.is_superuser or
            getattr(request.user, 'is_global_admin', False) or
            getattr(request.user, 'is_territorial_admin', False)
        ):
            return Response({"detail": "You do not have permission to delete this file."}, status=status.HTTP_403_FORBIDDEN)

        file.delete()
        return Response({"detail": "File deleted successfully."}, status=status.HTTP_204_NO_CONTENT)



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