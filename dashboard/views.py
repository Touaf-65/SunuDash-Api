from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from users.models import Country
from users.permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin
from file_upload.models import Client, Claim, Invoice, InsuredEmployer
from datetime import datetime

from file_upload.models import Policy, InsuredEmployer, Insured

class ClientStatisticListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin | IsTerritorialAdmin]

    def post(self, request):

        user = request.user

        if user.is_superuser or getattr(user, 'is_global_admin', False):
            country_id = request.data.get('country_id')
            if not country_id:
                return Response({"error": "country_id est requis pour les superusers et global admins."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            if hasattr(user, 'country') and user.country:
                country_id = user.country.id
            else:
                return Response({"error": "Aucun pays associé à cet utilisateur."}, status=status.HTTP_400_BAD_REQUEST)

        date_start = request.data.get('date_start')
        date_end = request.data.get('date_end')
        if not (country_id and date_start and date_end):
            return Response({"error": "country_id, date_start et date_end sont requis."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            date_start = datetime.strptime(date_start, "%Y-%m-%d")
            date_end = datetime.strptime(date_end, "%Y-%m-%d")
        except ValueError:
            return Response({"error": "Format de date invalide. Utilisez YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)
        
        clients = Client.objects.filter(country_id=country_id)
        results = []
        for client in clients:

            nb_policies = Policy.objects.filter(client=client).count()

            insured_links = InsuredEmployer.objects.filter(employer=client)

            nb_primary = insured_links.filter(role='primary').count()

            nb_total = insured_links.count()

            insured_ids = insured_links.values_list('insured_id', flat=True)
            claims = Claim.objects.filter(
                insured_id__in=insured_ids,
                claim_date__range=(date_start, date_end)
            )
            invoice_ids = claims.values_list('invoice_id', flat=True)
            total_consumption = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('claimed_amount'))['total'] or 0
            total_reimbursement = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('reimbursed_amount'))['total'] or 0

            results.append({
                "client_id": client.id,
                "client_name": client.name,
                "contact": client.contact,
                "nb_policies": nb_policies,
                "nb_primary_insured": nb_primary,
                "nb_total_insured": nb_total,
                "total_consumption": float(total_consumption),
                "total_reimbursement": float(total_reimbursement),
            })
        return Response(results, status=status.HTTP_200_OK)