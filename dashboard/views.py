from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from users.models import Country
from users.permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin
from file_upload.models import Client, Claim, Invoice, InsuredEmployer
from datetime import datetime

from file_upload.models import Policy, InsuredEmployer, Insured, ClientPrimeHistory
from django.db.models.functions import TruncDay, TruncMonth, TruncQuarter, TruncYear
from django.db.models import Sum, Count

import pytz
tz = pytz.UTC

# Fonction utilitaire pour choisir la granularité
from datetime import timedelta

def get_granularity(date_start, date_end):
    delta = date_end - date_start
    if delta.days <= 31:
        return 'day'
    elif delta.days <= 365:
        return 'month'
    elif delta.days <= 5 * 365:
        return 'quarter'
    else:
        return 'year'

class ClientStatisticView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, client_id):
        date_start = request.data.get('date_start')
        date_end = request.data.get('date_end')
        if not (date_start and date_end):
            return Response({"error": "date_start et date_end sont requis."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            date_start = tz.localize(datetime.strptime(date_start, "%Y-%m-%d"))
            date_end = tz.localize(datetime.strptime(date_end, "%Y-%m-%d"))
        except ValueError:
            return Response({"error": "Format de date invalide. Utilisez YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        granularity = get_granularity(date_start, date_end)
        if granularity == 'day':
            trunc = TruncDay
        elif granularity == 'month':
            trunc = TruncMonth
        elif granularity == 'quarter':
            trunc = TruncQuarter
        else:
            trunc = TruncYear

        # IDs des assurés du client
        insured_ids = list(InsuredEmployer.objects.filter(employer_id=client_id).values_list('insured_id', flat=True))

        # 1. Evolution consommation par type d'assuré
        from django.db.models import F
        claims_by_role = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .annotate(period=trunc('settlement_date'))
            .values('period', 'insured__insured_clients__role')
            .annotate(reimbursed=Sum('invoice__reimbursed_amount'))
            .order_by('period', 'insured__insured_clients__role')
        )
        # Structure la réponse pour chaque période et chaque rôle
        role_map = {'primary': 'Assurés Principaux', 'spouse': 'Assurés conjoints', 'child': 'Assurés enfants'}
        # Collecte toutes les périodes et tous les rôles rencontrés
        periods_set = set()
        roles_set = set()
        data_map = {}
        for c in claims_by_role:
            period = c['period']
            role = c['insured__insured_clients__role']
            role_label = role_map.get(role, role)
            reimbursed = float(c['reimbursed'] or 0)
            periods_set.add(period)
            roles_set.add(role_label)
            data_map.setdefault(role_label, {})[period] = reimbursed
        # Trie les périodes (pour affichage chronologique)
        sorted_periods = sorted(periods_set)
        # Format attendu par le front
        consumption_by_role_list = []
        for role_label in ['Assurés Principaux', 'Assurés conjoints', 'Assurés enfants']:
            if role_label in data_map:
                serie = {
                    'name': role_label,
                    'data': [
                        {'x': str(period), 'y': data_map[role_label].get(period, 0)}
                        for period in sorted_periods
                    ]
                }
                consumption_by_role_list.append(serie)
        # Ajoute les rôles "Autre" s'ils existent
        if 'Autre' in data_map:
            serie = {
                'name': 'Autre',
                'data': [
                    {'x': str(period), 'y': data_map['Autre'].get(period, 0)}
                    for period in sorted_periods
                ]
            }
            consumption_by_role_list.append(serie)

        # 2. Top 5 partenaires sur la période (tous partners consommés)
        top_partners = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .values('partner_id')
            .annotate(total=Sum('invoice__reimbursed_amount'))
            .order_by('-total')[:5]
        )
        top_partner_ids = [p['partner_id'] for p in top_partners]
        # Récupérer les noms des partenaires
        from file_upload.models import Partner
        partner_names = {p.id: p.name for p in Partner.objects.filter(id__in=top_partner_ids)}
        # Evolution par période pour ces partenaires
        claims_by_partner = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False,
                partner_id__in=top_partner_ids
            )
            .annotate(period=trunc('settlement_date'))
            .values('period', 'partner_id')
            .annotate(reimbursed=Sum('invoice__reimbursed_amount'))
            .order_by('period', 'partner_id')
        )
        # Structure pour le front
        consumption_by_partner = {}
        for c in claims_by_partner:
            period = c['period']
            partner = partner_names.get(c['partner_id'], str(c['partner_id']))
            reimbursed = float(c['reimbursed'] or 0)
            if period not in consumption_by_partner:
                consumption_by_partner[period] = {}
            consumption_by_partner[period][partner] = reimbursed
        consumption_by_partner_list = [
            {'period': period, **partners} for period, partners in sorted(consumption_by_partner.items())
        ]
        # Liste des top partenaires pour légende front
        top_partner_labels = [partner_names.get(pid, str(pid)) for pid in top_partner_ids]

        # 3. Top 5 actes sur la période
        top_acts = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .values('act_id')
            .annotate(total=Sum('invoice__reimbursed_amount'))
            .order_by('-total')[:5]
        )
        top_act_ids = [a['act_id'] for a in top_acts]
        from file_upload.models import Act
        act_names = {a.id: a.label for a in Act.objects.filter(id__in=top_act_ids)}
        claims_by_act = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False,
                act_id__in=top_act_ids
            )
            .annotate(period=trunc('settlement_date'))
            .values('period', 'act_id')
            .annotate(reimbursed=Sum('invoice__reimbursed_amount'))
            .order_by('period', 'act_id')
        )
        consumption_by_act = {}
        for c in claims_by_act:
            period = c['period']
            act = act_names.get(c['act_id'], str(c['act_id']))
            reimbursed = float(c['reimbursed'] or 0)
            if period not in consumption_by_act:
                consumption_by_act[period] = {}
            consumption_by_act[period][act] = reimbursed
        consumption_by_act_list = [
            {'period': period, **acts} for period, acts in sorted(consumption_by_act.items())
        ]
        top_act_labels = [act_names.get(aid, str(aid)) for aid in top_act_ids]

        # Les autres stats déjà présentes
        policies = (
            Policy.objects.filter(client_id=client_id, creation_date__range=(date_start, date_end))
            .annotate(period=trunc('creation_date'))
            .values('period')
            .annotate(count=Count('id'))
            .order_by('period')
        )
        primes = (
            ClientPrimeHistory.objects.filter(client_id=client_id, date__range=(date_start, date_end))
            .annotate(period=trunc('date'))
            .values('period')
            .annotate(prime=Sum('prime'))
            .order_by('period')
        )
        claims = (
            Claim.objects.filter(
                policy__client_id=client_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .annotate(period=trunc('settlement_date'))
            .values('period')
            .annotate(
                reimbursed=Sum('invoice__reimbursed_amount')
            )
            .order_by('period')
        )
        prime_map = {p['period']: p['prime'] for p in primes}
        result = []
        for c in claims:
            period = c['period']
            reimbursed = c['reimbursed'] or 0
            prime = prime_map.get(period, 0)
            ratio = reimbursed #(reimbursed / prime) if prime else None
            result.append({
                "period": period,
                "reimbursed": reimbursed,
                "prime": prime,
                "ratio": ratio,
            })

        import calendar
        from dateutil.parser import parse
        policies_series = []
        for p in policies:
            period = p['period']
            count = p['count']
            if hasattr(period, 'timestamp'):
                ts = int(calendar.timegm(period.timetuple())) * 1000
            else:
                ts = int(calendar.timegm(parse(str(period)).timetuple())) * 1000
            policies_series.append([ts, count])
        policies_series_formatted = [{
            "name": "Nouvelles polices",
            "data": policies_series
        }]

        # Formatage de la série prime pour le front
        prime_series = []
        for p in primes:
            period = p['period']
            montant = p['prime']
            if hasattr(period, 'timestamp'):
                ts = int(calendar.timegm(period.timetuple())) * 1000
            else:
                ts = int(calendar.timegm(parse(str(period)).timetuple())) * 1000
            prime_series.append([ts, float(montant or 0)])
        prime_series_formatted = [{
            "name": "Montant de la prime",
            "data": prime_series
        }]

        # Formatage de la série ratio pour le front
        ratio_series = []
        for r in result:
            period = r['period']
            ratio = r['ratio']
            if hasattr(period, 'timestamp'):
                ts = int(calendar.timegm(period.timetuple())) * 1000
            else:
                ts = int(calendar.timegm(parse(str(period)).timetuple())) * 1000
            ratio_series.append([ts, float(ratio or 0)])
        ratio_series_formatted = [{
            "name": "Ratio consommation/prime",
            "data": ratio_series
        }]

        # Formatage des séries partenaires pour le front
        partner_periods_set = set()
        partner_data_map = {name: {} for name in top_partner_labels}
        for c in claims_by_partner:
            period = c['period']
            partner = partner_names.get(c['partner_id'], str(c['partner_id']))
            montant = float(c['reimbursed'] or 0)
            partner_periods_set.add(period)
            if partner in partner_data_map:
                partner_data_map[partner][period] = montant
        sorted_partner_periods = sorted(partner_periods_set)
        partner_series = []
        for partner in top_partner_labels:
            serie = {
                "name": partner,
                "data": [
                    [
                        int(calendar.timegm(period.timetuple())) * 1000 if hasattr(period, 'timestamp') else int(calendar.timegm(parse(str(period)).timetuple())) * 1000,
                        partner_data_map[partner].get(period, 0)
                    ]
                    for period in sorted_partner_periods
                ]
            }
            partner_series.append(serie)

        # Formatage des séries actes pour le front
        act_periods_set = set()
        act_data_map = {name: {} for name in top_act_labels}
        for c in claims_by_act:
            period = c['period']
            act = act_names.get(c['act_id'], str(c['act_id']))
            montant = float(c['reimbursed'] or 0)
            act_periods_set.add(period)
            if act in act_data_map:
                act_data_map[act][period] = montant
        sorted_act_periods = sorted(act_periods_set)
        act_series = []
        for act in top_act_labels:
            serie = {
                "name": act,
                "data": [
                    [
                        int(calendar.timegm(period.timetuple())) * 1000 if hasattr(period, 'timestamp') else int(calendar.timegm(parse(str(period)).timetuple())) * 1000,
                        act_data_map[act].get(period, 0)
                    ]
                    for period in sorted_act_periods
                ]
            }
            act_series.append(serie)

        # Prépare le tableau des top 5 partenaires pour affichage tabulaire
        top_partners_table_qs = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .values('partner_id')
            .annotate(
                reimbursed=Sum('invoice__reimbursed_amount'),
                claimed=Sum('invoice__claimed_amount')
            )
            .order_by('-reimbursed')[:5]
        )
        partner_ids_table = [p['partner_id'] for p in top_partners_table_qs]
        partner_objs_table = {p.id: p for p in Partner.objects.filter(id__in=partner_ids_table)}
        top_partners_table = []
        for p in top_partners_table_qs:
            partner_obj = partner_objs_table.get(p['partner_id'])
            top_partners_table.append({
                "id": p['partner_id'],
                "name": partner_obj.name if partner_obj else str(p['partner_id']),
                "claimed": float(p['claimed'] or 0),
                "reimbursed": float(p['reimbursed'] or 0)
            })

        return Response({
            "granularity": granularity,
            # "policies_evolution": list(policies),
            # "prime_evolution": list(primes),
            # "consumption_ratio_evolution": result,
            "consumption_by_role": consumption_by_role_list,
            # "consumption_by_partner": consumption_by_partner_list,
            # "top_partner_labels": top_partner_labels,
            # "consumption_by_act": consumption_by_act_list,
            "top_act_labels": top_act_labels,
            "policies_series": policies_series_formatted,
            "prime_series": prime_series_formatted,
            "ratio_series": ratio_series_formatted,
            "partner_series": partner_series,
            "act_series": act_series,
            "top_partners_table": top_partners_table,
        }, status=status.HTTP_200_OK)




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


        

    