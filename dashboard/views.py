from django.db.models import Sum, Count, Q
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from users.models import Country, CustomUser
from users.permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin, IsChefDeptTech, IsResponsableOperateur
from file_upload.models import Client, Claim, Invoice, InsuredEmployer, Policy, Insured, ClientPrimeHistory
from datetime import datetime, timedelta, date
from django.db.models.functions import TruncDay, TruncMonth, TruncQuarter, TruncYear
from dateutil.relativedelta import relativedelta
import traceback

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


class ClientStatisticListView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin | IsTerritorialAdmin]

    def post(self, request):

        user = request.user

        if user.role == CustomUser.Roles.ADMIN_GLOBAL or user.role == CustomUser.Roles.SUPERUSER:
            country_id = request.data.get('country_id')
            if not country_id:
                return Response({"error": "country_id est requis pour les superusers et global admins."}, status=status.HTTP_400_BAD_REQUEST)
        else:
            if hasattr(user, 'country') and user.country:
                country_id = user.country.id
                if 'country_id' in request.data and int(request.data['country_id']) != country_id:
                    return Response({"error": "Vous ne pouvez accéder qu'à votre propre pays."}, status=status.HTTP_403_FORBIDDEN)
            else:
                return Response({"error": "Aucun pays associé à cet utilisateur."}, status=status.HTTP_400_BAD_REQUEST)

        date_start = request.data.get('date_start')
        date_end = request.data.get('date_end')
        if not (country_id and date_start and date_end):
            return Response({"error": "country_id, date_start et date_end sont requis."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            date_start = tz.localize(datetime.strptime(date_start, "%Y-%m-%d"))
            date_end = tz.localize(datetime.strptime(date_end, "%Y-%m-%d"))
        except ValueError:
            return Response({"error": "Format de date invalide. Utilisez YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)
        
        clients = Client.objects.filter(country_id=country_id)
        results = []

        for client in clients:
            nb_policies = Policy.objects.filter(client=client).count()
            insured_links = InsuredEmployer.objects.filter(employer=client)
            nb_primary = insured_links.filter(role='primary').count()
            nb_total = insured_links.count()
            insured_ids = list(insured_links.values_list('insured_id', flat=True))
            claims = Claim.objects.filter(
                insured_id__in=insured_ids,
                claim_date__range=(date_start, date_end)
            )
            invoice_ids = list(claims.values_list('invoice_id', flat=True))
            total_consumption = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('claimed_amount'))['total'] or 0
            total_reimbursement = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('reimbursed_amount'))['total'] or 0

            total_consumption = int(total_consumption)
            total_reimbursement = int(total_reimbursement)
            print(f"  total_consumption: {total_consumption}, total_reimbursement: {total_reimbursement}")

            results.append({
                "client_id": client.id,
                "client_name": client.name,
                "contact": client.contact,
                "nb_policies": nb_policies,
                "nb_primary_insured": nb_primary,
                "nb_total_insured": nb_total,
                "total_consumption": total_consumption,
                "total_reimbursement": total_reimbursement,
                # "type total consumption": type(str(total_consumption)).__name__,
                # "type total reimbursement": type(str(total_reimbursement)).__name__,
            })
        return Response(results, status=status.HTTP_200_OK)



class ClientStatisticView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, client_id):
        user = request.user
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



class ClientListPolicyStatisticsView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, client_id):
        # client_id = request.data.get('client_id')
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

        # 1. Part de consommation par type d'assuré (toutes polices du client)
        insured_ids = list(InsuredEmployer.objects.filter(employer_id=client_id).values_list('insured_id', flat=True))
        role_map = {'primary': 'Assurés Principaux', 'spouse': 'Assurés Conjoints', 'child': 'Assurés Enfants'}
        claims_by_role = (
            Claim.objects.filter(
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .values('insured__insured_clients__role')
            .annotate(total=Sum('invoice__reimbursed_amount'))
        )
        total = sum(float(c['total'] or 0) for c in claims_by_role)
        # On prépare un mapping role -> pourcentage
        role_percents = {'primary': 0, 'spouse': 0, 'child': 0}
        for c in claims_by_role:
            role = c['insured__insured_clients__role']
            value = float(c['total'] or 0)
            percent = (value / total * 100) if total else 0
            if role in role_percents:
                role_percents[role] = percent
        role_consumption_share = [
            role_percents['primary'],
            role_percents['spouse'],
            role_percents['child'],
        ]

        # 2. Evolution consommation par police
        policies = Policy.objects.filter(client_id=client_id)
        policy_consumption_series = []
        policies_table = []
        for policy in policies:
            # Série d'évolution
            claims = (
                Claim.objects.filter(
                    policy_id=policy.id,
                    settlement_date__range=(date_start, date_end),
                    invoice__isnull=False
                )
                .annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(total=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            serie = {
                "name": policy.policy_number,
                "data": [
                    [int(period['period'].timestamp()) * 1000, float(period['total'] or 0)]
                    for period in claims
                ]
            }
            policy_consumption_series.append(serie)

            # Table des polices
            insured_links = InsuredEmployer.objects.filter(policy_id=policy.id)
            nb_primary = insured_links.filter(role='primary').count()
            nb_total = insured_links.count()
            insured_ids = insured_links.values_list('insured_id', flat=True)
            total_consumption = Claim.objects.filter(
                policy_id=policy.id,
                insured_id__in=insured_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            ).aggregate(total=Sum('invoice__reimbursed_amount'))['total'] or 0
            policies_table.append({
                "policy_number": policy.policy_number,
                "nb_primary": nb_primary,
                "nb_total": nb_total,
                "consumption": float(total_consumption),
            })

        return Response({
            "granularity": granularity,
            "role_consumption_share": role_consumption_share,
            "policy_consumption_series": policy_consumption_series,
            "policies_table": policies_table,
        }, status=status.HTTP_200_OK)



class ClientPolicyStatisticsView(APIView):
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin | IsTerritorialAdmin]

    def post(self, request, policy_id):
        user = request.user
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

        # 1. Evolution consommation totale sur la police
        claims = (
            Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .annotate(period=trunc('settlement_date'))
            .values('period')
            .annotate(total=Sum('invoice__reimbursed_amount'))
            .order_by('period')
        )
        consumption_series = [
            [int(period['period'].timestamp()) * 1000, float(period['total'] or 0)]
            for period in claims
        ]

        # Génère la liste des périodes selon la granularité
        from datetime import timedelta
        import pytz
        periods = []
        current = date_start
        while current <= date_end:
            periods.append(current)
            if granularity == 'day':
                current += timedelta(days=1)
            elif granularity == 'month':
                year = current.year + (current.month // 12)
                month = ((current.month % 12) + 1)
                current = current.replace(year=year, month=month, day=1)
            elif granularity == 'quarter':
                month = ((current.month - 1) // 3) * 3 + 1
                next_quarter = month + 3
                year = current.year + (next_quarter > 12)
                month = (next_quarter - 1) % 12 + 1
                current = current.replace(year=year, month=month, day=1)
            else:
                current = current.replace(year=current.year + 1, month=1, day=1)

        nb_primary_series = []
        nb_beneficiary_series = []
        from django.db.models import Q
        for period in periods:
            # Comptage des assurés principaux présents à la période
            nb_primary = InsuredEmployer.objects.filter(
                policy_id=policy_id,
                role='primary',
                start_date__lte=period
            ).filter(Q(end_date__gt=period) | Q(end_date__isnull=True)).count()
            # Comptage des bénéficiaires (conjoints + enfants)
            nb_benef = InsuredEmployer.objects.filter(
                policy_id=policy_id,
                role__in=['spouse','child'],
                start_date__lte=period
            ).filter(Q(end_date__gt=period) | Q(end_date__isnull=True)).count()
            ts = int(period.timestamp()) * 1000
            nb_primary_series.append([ts, nb_primary])
            nb_beneficiary_series.append([ts, nb_benef])

        # insured_percent_series = [percent_principal, percent_beneficiary] sur la consommation
        claims = (
            Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .values('insured__insured_clients__role')
            .annotate(total=Sum('invoice__reimbursed_amount'))
        )
        total = sum(float(c['total'] or 0) for c in claims)
        total_principal = sum(float(c['total'] or 0) for c in claims if c['insured__insured_clients__role'] == 'primary')
        total_benef = sum(float(c['total'] or 0) for c in claims if c['insured__insured_clients__role'] in ['spouse','child'])
        percent_principal = (total_principal / total * 100) if total else 0
        percent_benef = (total_benef / total * 100) if total else 0
        insured_percent_series = [percent_principal, percent_benef]

        # 5. Evolution du nombre de consommations par type d'assuré
        role_map = {'primary': 'Assurés Principaux', 'spouse': 'Assurés Conjoints', 'child': 'Assurés Enfants'}
        claims_by_role = (
            Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            )
            .annotate(period=trunc('settlement_date'))
            .values('period', 'insured__insured_clients__role')
            .annotate(nb=Count('id'))
            .order_by('period', 'insured__insured_clients__role')
        )
        # Regrouper par période et par rôle
        periods = sorted(set([c['period'] for c in claims_by_role]))
        role_series_map = {'primary': [], 'spouse': [], 'child': []}
        for period in periods:
            for role in ['primary','spouse','child']:
                nb = next((c['nb'] for c in claims_by_role if c['period']==period and c['insured__insured_clients__role']==role), 0)
                role_series_map[role].append([int(period.timestamp()) * 1000, nb])
        consumption_by_role_series = [
            {"name": role_map[role], "data": role_series_map[role]} for role in ['primary','spouse','child']
        ]

        # --- Séries avancées ---
        from django.db.models import F

        principals = InsuredEmployer.objects.filter(policy_id=policy_id, role='primary')
        family_consumptions = []
        for principal in principals:
            # IDs de la famille = principal + bénéficiaires liés
            family_ids = [principal.insured_id] + list(
                InsuredEmployer.objects.filter(
                    policy_id=policy_id,
                    primary_insured_ref=principal.insured_id
                ).values_list('insured_id', flat=True)
            )
            total = Claim.objects.filter(
                policy_id=policy_id,
                insured_id__in=family_ids,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False
            ).aggregate(total=Sum('invoice__reimbursed_amount'))['total'] or 0
            family_consumptions.append({
                'principal': principal.insured.name,
                'family_ids': family_ids,
                'total': float(total)
            })
        # Top 5 familles
        top_families = sorted(family_consumptions, key=lambda x: x['total'], reverse=True)[:5]
        # Séries temporelles
        family_consumption_series = []
        for fam in top_families:
            claims = (
                Claim.objects.filter(
                    policy_id=policy_id,
                    insured_id__in=fam['family_ids'],
                    settlement_date__range=(date_start, date_end),
                    invoice__isnull=False
                )
                .annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(total=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            serie = {
                "name": fam['principal'],
                "data": [
                    [int(period['period'].timestamp()) * 1000, float(period['total'] or 0)]
                    for period in claims
                ]
            }
            family_consumption_series.append(serie)
        # 2. Top 5 partenaires
        partners = (
            Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False,
                partner__isnull=False
            )
            .values('partner', 'partner__name')
            .annotate(total=Sum('invoice__reimbursed_amount'))
            .order_by('-total')[:5]
        )
        partner_tuples = [(p['partner'], p['partner__name']) for p in partners]
        partner_consumption_series = []
        for partner_id, pname in partner_tuples:
            claims = (
                Claim.objects.filter(
                    policy_id=policy_id,
                    settlement_date__range=(date_start, date_end),
                    invoice__isnull=False,
                    partner__name=pname
                )
                .annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(total=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            serie = {
                "name": pname,
                "data": [
                    [int(period['period'].timestamp()) * 1000, float(period['total'] or 0)]
                    for period in claims
                ]
            }
            partner_consumption_series.append(serie)
        # 3. Top 5 actes
        acts = (
            Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False,
                act__isnull=False
            )
            .values('act__label')
            .annotate(total=Sum('invoice__reimbursed_amount'))
            .order_by('-total')[:5]
        )
        act_names = [a['act__label'] for a in acts]
        act_consumption_series = []
        for aname in act_names:
            claims = (
                Claim.objects.filter(
                    policy_id=policy_id,
                    settlement_date__range=(date_start, date_end),
                    invoice__isnull=False,
                    act__label=aname
                )
                .annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(total=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            serie = {
                "name": aname,
                "data": [
                    [int(period['period'].timestamp()) * 1000, float(period['total'] or 0)]
                    for period in claims
                ]
            }
            act_consumption_series.append(serie)
        # 4. Tableau top partenaires
        top_partners_table = []
        for partner_id, pname in partner_tuples:
            agg = Claim.objects.filter(
                policy_id=policy_id,
                settlement_date__range=(date_start, date_end),
                invoice__isnull=False,
                partner__name=pname
            ).aggregate(
                total_claimed=Sum('invoice__claimed_amount'),
                total_reimbursed=Sum('invoice__reimbursed_amount')
            )
            top_partners_table.append({
                "partner_id": partner_id,
                "partner": pname,
                "total_claimed": float(agg['total_claimed'] or 0),
                "total_reimbursed": float(agg['total_reimbursed'] or 0)
            })
        return Response({
            "granularity": granularity,
            "consumption_series": consumption_series,
            "nb_primary_series": nb_primary_series,
            "nb_beneficiary_series": nb_beneficiary_series,
            "insured_percent_series": insured_percent_series,
            "consumption_by_role_series": consumption_by_role_series,
            "family_consumption_series": family_consumption_series,
            "partner_consumption_series": partner_consumption_series,
            "act_consumption_series": act_consumption_series,
            "top_partners_table": top_partners_table,
        }, status=status.HTTP_200_OK)



class CountriesCommomStatisticsView(APIView):
    """
    Vue pour récupérer les statistiques globales sur tous les pays, sur une période donnée.
    """
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def post(self, request):
        try:
            date_start = request.data.get('date_start')
            date_end = request.data.get('date_end')
            if not (date_start and date_end):
                return Response({"error": "date_start et date_end sont requis."}, status=status.HTTP_400_BAD_REQUEST)
            try:
                date_start = tz.localize(datetime.strptime(date_start, "%Y-%m-%d"))
                date_end = tz.localize(datetime.strptime(date_end, "%Y-%m-%d"))
            except ValueError:
                return Response({"error": "Format de date invalide. Utilisez YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

            # Granularité
            granularity = get_granularity(date_start, date_end)
            if granularity == 'day':
                trunc = TruncDay
            elif granularity == 'month':
                trunc = TruncMonth
            elif granularity == 'quarter':
                trunc = TruncQuarter
            else:
                trunc = TruncYear

            # Pas de filtre par pays : on prend tout
            clients = Client.objects.all()
            client_ids = clients.values_list('id', flat=True)
            policies = Policy.objects.filter(client_id__in=client_ids)
            policy_ids = policies.values_list('id', flat=True)

            # 1. Evolution du nombre de clients (tous pays)
            clients_series = (
                clients.filter(creation_date__range=(date_start, date_end))
                .annotate(period=trunc('creation_date'))
                .values('period')
                .annotate(value=Count('id'))
                .order_by('period')
            )
            clients_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in clients_series]

            # 2. Evolution de la prime globale (tous pays)
            primes_series = (
                clients.filter(creation_date__range=(date_start, date_end))
                .annotate(period=trunc('creation_date'))
                .values('period')
                .annotate(value=Sum('prime'))
                .order_by('period')
            )
            primes_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)} for c in primes_series]

            # 3. Evolution du montant remboursé total (tous pays)
            claims = Claim.objects.filter(policy_id__in=policy_ids, settlement_date__range=(date_start, date_end), invoice__isnull=False)
            rembourse_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            rembourse_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)} for c in rembourse_series]

            # 4. Montant réclamé (comme montant remboursé)
            reclamation_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Sum('invoice__claimed_amount'))
                .order_by('period')
            )
            reclamation_series = [
                {"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value'] or 0}
                for c in reclamation_series
            ]

            # 5. Evolution du nombre de partenaires (distincts dans les claims)
            partenaires_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Count('invoice__provider', distinct=True))
                .order_by('period')
            )
            partenaires_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in partenaires_series]

            # 6. Evolution du ratio S/P (consommation / prime)
            ratio_sp_series = []
            primes_by_period = {c['period']: float(c['value'] or 0) for c in primes_series}
            rembourse_by_period = {c['period']: float(c['value'] or 0) for c in rembourse_series}
            all_periods = sorted(set(primes_by_period.keys()) | set(rembourse_by_period.keys()))
            for period in all_periods:
                prime = primes_by_period.get(period, 0)
                remboursement = rembourse_by_period.get(period, 0)
                ratio = remboursement / prime if prime else None
                ratio_sp_series.append({"period": period, "value": ratio})

            # 7. Evolution du nombre d'assurés principaux
            nb_principal_series = (
                InsuredEmployer.objects.filter(role='primary', insured__creation_date__range=(date_start, date_end))
                .annotate(period=trunc('insured__creation_date'))
                .values('period')
                .annotate(value=Count('insured_id', distinct=True))
                .order_by('period')
            )
            nb_principal_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in nb_principal_series]

            # 8. Evolution du nombre d'assurés total
            nb_total_series = (
                InsuredEmployer.objects.filter(insured__creation_date__range=(date_start, date_end))
                .annotate(period=trunc('insured__creation_date'))
                .values('period')
                .annotate(value=Count('insured_id', distinct=True))
                .order_by('period')
            )
            nb_total_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in nb_total_series]

            # 9. Evolution du nombre de chaque type d'assurés
            nb_by_role = {}
            for role in ['primary', 'spouse', 'child', 'other']:
                role_series = (
                    InsuredEmployer.objects.filter(role=role, insured__creation_date__range=(date_start, date_end))
                    .annotate(period=trunc('insured__creation_date'))
                    .values('period')
                    .annotate(value=Count('insured_id', distinct=True))
                    .order_by('period')
                )
                nb_by_role[role] = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in role_series]

            # 10. Top 5 pays ayant le plus de consommation (remboursée)
            top_countries = (
                Claim.objects.filter(settlement_date__range=(date_start, date_end), invoice__isnull=False)
                .values('policy__client__country_id')
                .annotate(total_conso=Sum('invoice__reimbursed_amount'))
                .order_by('-total_conso')[:5]
            )
            top_country_ids = [c['policy__client__country_id'] for c in top_countries]
            from users.models import Country
            country_names = {c.id: c.name for c in Country.objects.filter(id__in=top_country_ids)}

            def generate_periods(date_start, date_end, granularity):
                periods = []
                current = date_start
                while current <= date_end:
                    periods.append(current)
                    if granularity == 'day':
                        current += timedelta(days=1)
                    elif granularity == 'month':
                        current += relativedelta(months=1)
                    elif granularity == 'quarter':
                        current += relativedelta(months=3)
                    else:
                        current += relativedelta(years=1)
                return periods

            def fill_full_series(periods, serie):
                def to_date(obj):
                    if hasattr(obj, 'date'):
                        return obj.date()
                    elif isinstance(obj, datetime):
                        return obj.date()
                    return obj
                value_map = {to_date(point['period']): point['value'] for point in serie}
                last_value = None
                result = []
                for period in periods:
                    period_date = to_date(period)
                    if period_date in value_map:
                        last_value = value_map[period_date]
                    result.append({'period': period, 'value': last_value})
                return result

            # Générer la série temporelle remboursée pour chaque pays du top 5
            periods = generate_periods(date_start, date_end, granularity)
            top_countries_series = []
            for country_id in top_country_ids:
                # Série brute pour ce pays
                country_claims = Claim.objects.filter(
                    policy__client__country_id=country_id,
                    settlement_date__range=(date_start, date_end),
                    invoice__isnull=False
                ).annotate(period=trunc('settlement_date'))\
                 .values('period')\
                 .annotate(value=Sum('invoice__reimbursed_amount'))\
                 .order_by('period')
                country_series = [
                    {"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)}
                    for c in country_claims
                ]
                # Série complète alignée sur toutes les périodes
                country_series_full = fill_full_series(periods, country_series)
                # Tableau de valeurs pour chaque période (pour le front)
                data = [float(point['value'] or 0) for point in country_series_full]
                top_countries_series.append({
                    "name": country_names.get(country_id, str(country_id)),
                    "data": data
                })

            # Helpers pour séries temporelles et taux d'évolution
            def to_timestamp_ms(dt):
                if hasattr(dt, 'timestamp'):
                    return int(dt.timestamp() * 1000)
                elif isinstance(dt, date):
                    return int(datetime(dt.year, dt.month, dt.day).timestamp() * 1000)
                else:
                    return int(dt)
            def serie_to_pairs(serie):
                return [[to_timestamp_ms(point['period']), float(point['value'] or 0)] for point in serie]
            
            def fill_full_series(periods, serie):
                def to_date(obj):
                    if hasattr(obj, 'date'):
                        return obj.date()
                    elif isinstance(obj, datetime):
                        return obj.date()
                    return obj
                value_map = {to_date(point['period']): point['value'] for point in serie}
                last_value = None
                result = []
                for period in periods:
                    period_date = to_date(period)
                    if period_date in value_map:
                        last_value = value_map[period_date]
                    result.append({'period': period, 'value': last_value})
                return result
            def compute_evolution_rate(series):
                if not series or len(series) == 0:
                    return 0.0
                if len(series) == 1:
                    first = last = float(series[0]['value'] or 0)
                else:
                    first = float(series[0]['value'] or 0)
                    last = float(series[-1]['value'] or 0)
                if first == 0:
                    if last == 0:
                        return 0.0
                    else:
                        return "Nouveau"
                return round(100 * (last - first) / abs(first), 2)
            def date_label(dt, granularity):
                if granularity == 'day':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%a')
                    return str(dt)
                elif granularity == 'month':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%Y-%m')
                    return str(dt)
                elif granularity == 'year':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%Y')
                    return str(dt)
                elif granularity == 'quarter':
                    if hasattr(dt, 'year') and hasattr(dt, 'month'):
                        quarter = (dt.month - 1) // 3 + 1
                        return f"{dt.year}-Q{quarter}"
                    return str(dt)
                return str(dt)

            # Générer toutes les périodes
            periods = generate_periods(date_start, date_end, granularity)
            clients_series_full = fill_full_series(periods, clients_series)
            primes_series_full = fill_full_series(periods, primes_series)
            rembourse_series_full = fill_full_series(periods, rembourse_series)
            reclamation_series_full = fill_full_series(periods, reclamation_series)
            nb_principal_series_full = fill_full_series(periods, nb_principal_series)
            nb_total_series_full = fill_full_series(periods, nb_total_series)

            # Convertir en pairs
            clients_series_pairs = serie_to_pairs(clients_series_full)
            primes_series_pairs = serie_to_pairs(primes_series_full)
            rembourse_series_pairs = serie_to_pairs(rembourse_series_full)
            reclamation_series_pairs = serie_to_pairs(reclamation_series_full)
            nb_principal_series_pairs = serie_to_pairs(nb_principal_series_full)
            nb_total_series_pairs = serie_to_pairs(nb_total_series_full)
            partenaires_series_pairs = serie_to_pairs(partenaires_series)
            ratio_sp_series_pairs = serie_to_pairs(ratio_sp_series)

            # Séries par type d'assuré (format spécial pour ApexCharts multi-lignes)
            role_labels = {
                'primary': 'Assurés Principaux',
                'spouse': 'Assurés conjoints',
                'child': 'Assurés enfants',
                'other': 'Autres assurés',
            }
            nb_by_role_series = []
            for role, serie in nb_by_role.items():
                label = role_labels.get(role, role)
                periods_role = generate_periods(date_start, date_end, granularity)
                def to_date(obj):
                    if hasattr(obj, 'date'):
                        return obj.date()
                    return obj
                period_dates = set([to_date(p) for p in periods_role])
                value_map = {to_date(point['period']): float(point['value'] or 0) for point in serie}
                extra_dates = set(value_map.keys()) - period_dates
                all_dates = sorted(period_dates | extra_dates)
                data = []
                for d in all_dates:
                    if d in period_dates:
                        x = date_label(d, granularity)
                    else:
                        x = f"EXTRA {d}"
                    y = value_map.get(d, 0)
                    data.append({'x': x, 'y': y})
                nb_by_role_series.append({'name': label, 'data': data})
                categories_labels = [date_label(p, granularity) for p in periods_role]

            # Valeurs instantanées globales
            actual_montant_reclame_value = float(reclamation_series_full[-1]['value'] if reclamation_series_full else 0)
            actual_nb_clients_value = float(nb_total_series[-1]['value'] if nb_total_series else 0)
            actual_prime_globale_value = float(primes_series[-1]['value'] if primes_series else 0)
            actual_montant_rembourse_value = float(rembourse_series[-1]['value'] if rembourse_series else 0)
            actual_nb_assures_principaux_value = float(nb_principal_series[-1]['value'] if nb_principal_series else 0)
            actual_nb_assures_total_value = float(nb_total_series[-1]['value'] if nb_total_series else 0)

            # Taux d'évolution globaux
            clients_evolution_rate = compute_evolution_rate(clients_series)
            prime_globale_evolution_rate = compute_evolution_rate(primes_series)
            montant_rembourse_evolution_rate = compute_evolution_rate(rembourse_series)
            montant_reclame_evolution_rate = compute_evolution_rate(reclamation_series)
            nb_assures_principaux_evolution_rate = compute_evolution_rate(nb_principal_series)
            nb_assures_total_evolution_rate = compute_evolution_rate(nb_total_series)

            return Response({
                "granularity": granularity,
                "clients_series": clients_series_pairs,
                "prime_globale_series": primes_series_pairs,
                "montant_rembourse_series": rembourse_series_pairs,
                "montant_reclame_series": reclamation_series_pairs,
                "partenaires_series": partenaires_series_pairs,
                "ratio_sp_series": ratio_sp_series_pairs,
                "nb_assures_principaux_series": nb_principal_series_pairs,
                "nb_assures_total_series": nb_total_series_pairs,
                "nb_assures_par_type_series": nb_by_role_series,
                "top5_countries_conso": top_countries_series,
                "top5_countries_conso_categories": categories_labels,
                "actual_nb_clients_value": actual_nb_clients_value,
                "actual_prime_globale_value": actual_prime_globale_value,
                "actual_montant_rembourse_value": actual_montant_rembourse_value,
                "actual_montant_reclame_value": actual_montant_reclame_value,
                "actual_nb_assures_principaux_value": actual_nb_assures_principaux_value,
                "actual_nb_assures_total_value": actual_nb_assures_total_value,
                "clients_evolution_rate": clients_evolution_rate,
                "prime_globale_evolution_rate": prime_globale_evolution_rate,
                "montant_rembourse_evolution_rate": montant_rembourse_evolution_rate,
                "montant_reclame_evolution_rate": montant_reclame_evolution_rate,
                "nb_assures_principaux_evolution_rate": nb_assures_principaux_evolution_rate,
                "nb_assures_total_evolution_rate": nb_assures_total_evolution_rate
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("ERREUR API CountriesCommomStatisticsView:", str(e))
            import traceback
            traceback.print_exc()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)




class CountriesListStatisticsView(APIView):
    """
    Vue pour récupérer les statistiques pays :
    - nom
    - prime globale
    - consommation globale
    - ratio S/P
    - nombre d'assurés
    - nombre de clients
    """
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

    def get(self, request):
        from file_upload.models import Client, InsuredEmployer, Claim, Invoice
        from users.models import Country
        from django.db.models import Sum, Count, Q

        countries = Country.objects.all()
        results = []
        for country in countries:
            clients = Client.objects.filter(country=country)
            nb_clients = clients.count()
            prime_globale = clients.aggregate(total=Sum('prime'))['total'] or 0

            # Récupérer tous les ids de clients du pays
            client_ids = clients.values_list('id', flat=True)

            # Nombre d'assurés du pays (distincts)
            nb_assures = InsuredEmployer.objects.filter(employer_id__in=client_ids).values('insured_id').distinct().count()

            # Consommation globale : somme des montants remboursés des claims dont la policy appartient à un client du pays
            # Claims -> Policy -> Client (policy.client_id in client_ids)
            claim_ids = Claim.objects.filter(policy__client_id__in=client_ids).values_list('invoice_id', flat=True)
            consommation_globale = Invoice.objects.filter(id__in=claim_ids).aggregate(total=Sum('reimbursed_amount'))['total'] or 0

            # Ratio S/P
            ratio_sp = float(prime_globale) / float(consommation_globale) if consommation_globale else None

            results.append({
                'country_id': country.id,
                'country_name': country.name,
                'prime_globale': float(prime_globale),
                'consommation_globale': float(consommation_globale),
                'ratio_sp': float(ratio_sp) if ratio_sp is not None else None,
                'nb_assures': nb_assures,
                'nb_clients': nb_clients,
            })
        return Response(results, status=status.HTTP_200_OK)


class CountryStatisticsDetailView(APIView):
    """
    Vue pour récupérer les séries temporelles statistiques d'un pays donné sur une période.
    """
    permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin | IsTerritorialAdmin]

    def post(self, request, country_id):
        try:
            date_start = request.data.get('date_start')
            date_end = request.data.get('date_end')
            if not (date_start and date_end):
                return Response({"error": "date_start et date_end sont requis."}, status=status.HTTP_400_BAD_REQUEST)
            
            try:
                date_start = tz.localize(datetime.strptime(date_start, "%Y-%m-%d"))
                date_end = tz.localize(datetime.strptime(date_end, "%Y-%m-%d"))
            except ValueError:
                return Response({"error": "Format de date invalide. Utilisez YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

            # Choix de la granularité
            granularity = get_granularity(date_start, date_end)
            if granularity == 'day':
                trunc = TruncDay
            elif granularity == 'month':
                trunc = TruncMonth
            elif granularity == 'quarter':
                trunc = TruncQuarter
            else:
                trunc = TruncYear

            # Préparation des filtres
            clients = Client.objects.filter(country_id=country_id)
            client_ids = clients.values_list('id', flat=True)
            policies = Policy.objects.filter(client_id__in=client_ids)
            policy_ids = policies.values_list('id', flat=True)

            # 1. Evolution du nombre de clients
            clients_series = (
                clients.filter(creation_date__range=(date_start, date_end))
                .annotate(period=trunc('creation_date'))
                .values('period')
                .annotate(value=Count('id'))
                .order_by('period')
            )
            clients_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in clients_series]

            # 2. Evolution de la prime globale
            primes_series = (
                clients.filter(creation_date__range=(date_start, date_end))
                .annotate(period=trunc('creation_date'))
                .values('period')
                .annotate(value=Sum('prime'))
                .order_by('period')
            )
            primes_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)} for c in primes_series]

            # 3. Evolution du montant remboursé total
            claims = Claim.objects.filter(policy_id__in=policy_ids, settlement_date__range=(date_start, date_end), invoice__isnull=False)
            rembourse_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Sum('invoice__reimbursed_amount'))
                .order_by('period')
            )
            rembourse_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)} for c in rembourse_series]

    # Montant réclamé (comme montant remboursé)
            reclamation_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Sum('invoice__claimed_amount'))
                .order_by('period')
            )
            reclamation_series = [
                {"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value'] or 0}
                for c in reclamation_series
            ]

            # 4. Evolution du nombre de partenaires (distincts dans les claims)
            partenaires_series = (
                claims.annotate(period=trunc('settlement_date'))
                .values('period')
                .annotate(value=Count('invoice__provider', distinct=True))
                .order_by('period')
            )
            partenaires_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in partenaires_series]

            # 5. Evolution du ratio S/P (consommation / prime)
            ratio_sp_series = []
            primes_by_period = {c['period']: float(c['value'] or 0) for c in primes_series}
            rembourse_by_period = {c['period']: float(c['value'] or 0) for c in rembourse_series}
            all_periods = sorted(set(primes_by_period.keys()) | set(rembourse_by_period.keys()))
            for period in all_periods:
                prime = primes_by_period.get(period, 0)
                remboursement = rembourse_by_period.get(period, 0)
                ratio = remboursement / prime if prime else None
                ratio_sp_series.append({"period": period, "value": ratio})

            # 6. Evolution du nombre d'assurés principaux
            nb_principal_series = (
                InsuredEmployer.objects.filter(employer_id__in=client_ids, role='primary', insured__creation_date__range=(date_start, date_end))
                .annotate(period=trunc('insured__creation_date'))
                .values('period')
                .annotate(value=Count('insured_id', distinct=True))
                .order_by('period')
            )
            nb_principal_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in nb_principal_series]

            # 7. Evolution du nombre d'assurés total
            nb_total_series = (
                InsuredEmployer.objects.filter(employer_id__in=client_ids, insured__creation_date__range=(date_start, date_end))
                .annotate(period=trunc('insured__creation_date'))
                .values('period')
                .annotate(value=Count('insured_id', distinct=True))
                .order_by('period')
            )
            nb_total_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in nb_total_series]

            # 8. Evolution du nombre de chaque type d'assurés
            nb_by_role = {}
            for role in ['primary', 'spouse', 'child', 'other']:
                role_series = (
                    InsuredEmployer.objects.filter(employer_id__in=client_ids, role=role, insured__creation_date__range=(date_start, date_end))
                    .annotate(period=trunc('insured__creation_date'))
                    .values('period')
                    .annotate(value=Count('insured_id', distinct=True))
                    .order_by('period')
                )
                nb_by_role[role] = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": c['value']} for c in role_series]

            # 9. Evolution du top 5 clients ayant le plus consommé
            top_clients = (
                claims.values('policy__client_id')
                .annotate(total_conso=Sum('invoice__reimbursed_amount'))
                .order_by('-total_conso')[:5]
            )
            top_client_ids = [c['policy__client_id'] for c in top_clients]
            top_clients_map = {c['policy__client_id']: float(c['total_conso'] or 0) for c in top_clients}
            client_names = {c.id: c.name for c in Client.objects.filter(id__in=top_client_ids)}
            top_clients_series = []
            for client_id in top_client_ids:
                client_claims = claims.filter(policy__client_id=client_id)
                client_series = (
                    client_claims.annotate(period=trunc('settlement_date'))
                    .values('period')
                    .annotate(value=Sum('invoice__reimbursed_amount'))
                    .order_by('period')
                )
                client_series = [{"period": c['period'].date() if hasattr(c['period'], 'date') else c['period'], "value": float(c['value'] or 0)} for c in client_series]
                top_clients_series.append({
                    "client_id": client_id,
                    "client_name": client_names.get(client_id, str(client_id)),
                    "series": client_series
                })

            # Helper pour convertir une date en timestamp ms
            def to_timestamp_ms(dt):
                if hasattr(dt, 'timestamp'):
                    return int(dt.timestamp() * 1000)
                elif isinstance(dt, date):
                    return int(datetime(dt.year, dt.month, dt.day).timestamp() * 1000)
                else:
                    return int(dt)

            def serie_to_pairs(serie):
                return [[to_timestamp_ms(point['period']), float(point['value'] or 0)] for point in serie]

            # --- Helper pour générer toutes les périodes de la granularité ---
            def generate_periods(date_start, date_end, granularity):
                periods = []
                current = date_start
                while current <= date_end:
                    periods.append(current)
                    if granularity == 'day':
                        current += timedelta(days=1)
                    elif granularity == 'month':
                        current += relativedelta(months=1)
                    elif granularity == 'quarter':
                        current += relativedelta(months=3)
                    else:  # year
                        current += relativedelta(years=1)
                return periods

            # --- Helper pour remplir la série sur toutes les périodes ---
            def fill_full_series(periods, serie):
                # On convertit toutes les périodes en datetime.date pour la clé
                def to_date(obj):
                    if hasattr(obj, 'date'):
                        return obj.date()
                    elif isinstance(obj, datetime):
                        return obj.date()
                    return obj
                
                value_map = {to_date(point['period']): point['value'] for point in serie}
                last_value = None
                result = []
                for period in periods:
                    period_date = to_date(period)
                    if period_date in value_map:
                        last_value = value_map[period_date]
                    result.append({'period': period, 'value': last_value})
                return result

            # Générer toutes les périodes
            periods = generate_periods(date_start, date_end, granularity)

            # Appliquer le remplissage aux séries sélectionnées
            clients_series_full = fill_full_series(periods, clients_series)
            primes_series_full = fill_full_series(periods, primes_series)
            rembourse_series_full = fill_full_series(periods, rembourse_series)
            reclamation_series_full = fill_full_series(periods, reclamation_series)
            nb_principal_series_full = fill_full_series(periods, nb_principal_series)
            nb_total_series_full = fill_full_series(periods, nb_total_series)

            # Convertir en pairs
            clients_series_pairs = serie_to_pairs(clients_series_full)
            primes_series_pairs = serie_to_pairs(primes_series_full)
            rembourse_series_pairs = serie_to_pairs(rembourse_series_full)
            reclamation_series_pairs = serie_to_pairs(reclamation_series_full)
            nb_principal_series_pairs = serie_to_pairs(nb_principal_series_full)
            nb_total_series_pairs = serie_to_pairs(nb_total_series_full)

            # Les autres séries restent inchangées
            partenaires_series_pairs = serie_to_pairs(partenaires_series)
            ratio_sp_series_pairs = serie_to_pairs(ratio_sp_series)

            # Séries par type d'assuré : format spécial pour ApexCharts multi-lignes
            role_labels = {
                'primary': 'Assurés Principaux',
                'spouse': 'Assurés conjoints',
                'child': 'Assurés enfants',
                'other': 'Autres assurés',
            }
            def date_label(dt, granularity):
                if granularity == 'day':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%a')  # 'Mon', 'Tue', ...
                    return str(dt)
                elif granularity == 'month':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%Y-%m')
                    return str(dt)
                elif granularity == 'year':
                    if hasattr(dt, 'strftime'):
                        return dt.strftime('%Y')
                    return str(dt)
                elif granularity == 'quarter':
                    if hasattr(dt, 'year') and hasattr(dt, 'month'):
                        quarter = (dt.month - 1) // 3 + 1
                        return f"{dt.year}-Q{quarter}"
                    return str(dt)
                return str(dt)
            nb_by_role_series = []
            for role, serie in nb_by_role.items():
                label = role_labels.get(role, role)
                # Génère la liste des périodes de la granularité
                periods = generate_periods(date_start, date_end, granularity)
                # On convertit tout en datetime.date pour la clé
                def to_date(obj):
                    if hasattr(obj, 'date'):
                        return obj.date()
                    return obj
                period_dates = set([to_date(p) for p in periods])
                # Index des valeurs de la série d'origine
                value_map = {to_date(point['period']): float(point['value'] or 0) for point in serie}
                # Points hors-grille
                extra_dates = set(value_map.keys()) - period_dates
                # Fusionne et trie toutes les dates
                all_dates = sorted(period_dates | extra_dates)
                data = []
                for d in all_dates:
                    if d in period_dates:
                        x = date_label(d, granularity)
                    else:
                        # Label spécial pour hors-grille
                        x = f"EXTRA {d}"
                    y = value_map.get(d, 0)
                    data.append({'x': x, 'y': y})
                nb_by_role_series.append({'name': label, 'data': data})

            # Top 5 clients consommation (format multi-series pour ApexCharts)
            periods = generate_periods(date_start, date_end, granularity)
            def to_date(obj):
                if hasattr(obj, 'date'):
                    return obj.date()
                return obj
            period_dates = [to_date(p) for p in periods]
            top_clients_series_multi = []
            for top in top_clients_series:
                name = top.get("client_name") or str(top.get("client_id"))
                value_map = {to_date(point['period']): float(point['value'] or 0) for point in top["series"]}
                data = [value_map.get(p, 0) for p in period_dates]
                top_clients_series_multi.append({"name": name, "data": data})
            # Génère la liste des labels pour l'axe X
            top_clients_series_categories = [date_label(p, granularity) for p in period_dates]

            

            actual_montant_reclame_value = float(reclamation_series_full[-1]['value'] if reclamation_series_full else 0)

            actual_nb_clients_value = float(nb_total_series[-1]['value'] if nb_total_series else 0)
            actual_prime_globale_value = float(primes_series[-1]['value'] if primes_series else 0)
            actual_montant_rembourse_value = float(rembourse_series[-1]['value'] if rembourse_series else 0)
            
            actual_nb_assures_principaux_value = float(nb_principal_series[-1]['value'] if nb_principal_series else 0)
            actual_nb_assures_total_value = float(nb_total_series[-1]['value'] if nb_total_series else 0)


            def compute_evolution_rate(series):
                if not series or len(series) == 0:
                    return 0.0
                if len(series) == 1:
                    first = last = float(series[0]['value'] or 0)
                else:
                    first = float(series[0]['value'] or 0)
                    last = float(series[-1]['value'] or 0)
                if first == 0:
                    if last == 0:
                        return 0.0
                    else:
                        return "Nouveau"
                return round(100 * (last - first) / abs(first), 2)

            clients_evolution_rate = compute_evolution_rate(clients_series)
            prime_globale_evolution_rate = compute_evolution_rate(primes_series)
            montant_rembourse_evolution_rate = compute_evolution_rate(rembourse_series)
            montant_reclame_evolution_rate = compute_evolution_rate(reclamation_series)
            nb_assures_principaux_evolution_rate = compute_evolution_rate(nb_principal_series)
            nb_assures_total_evolution_rate = compute_evolution_rate(nb_total_series)


            return Response({
                "granularity": granularity,

                "clients_series": clients_series_pairs,
                "prime_globale_series": primes_series_pairs,
                "montant_rembourse_series": rembourse_series_pairs,
                "montant_reclame_series": reclamation_series_pairs,
                "partenaires_series": partenaires_series_pairs,
                "ratio_sp_series": ratio_sp_series_pairs,
                "nb_assures_principaux_series": nb_principal_series_pairs,
                "nb_assures_total_series": nb_total_series_pairs,
                "nb_assures_par_type_series": nb_by_role_series,
                "top5_clients_conso_series": top_clients_series_multi,

                "top5_clients_conso_categories": top_clients_series_categories,

                "actual_nb_clients_value": actual_nb_clients_value,
                "actual_prime_globale_value": actual_prime_globale_value,
                "actual_montant_rembourse_value": actual_montant_rembourse_value,
                "actual_montant_reclame_value": actual_montant_reclame_value,
                "actual_nb_assures_principaux_value": actual_nb_assures_principaux_value,
                "actual_nb_assures_total_value": actual_nb_assures_total_value,

                "clients_evolution_rate": clients_evolution_rate,
                "prime_globale_evolution_rate": prime_globale_evolution_rate,
                "montant_rembourse_evolution_rate": montant_rembourse_evolution_rate,
                "montant_reclame_evolution_rate": montant_reclame_evolution_rate,
                "nb_assures_principaux_evolution_rate": nb_assures_principaux_evolution_rate,
                "nb_assures_total_evolution_rate": nb_assures_total_evolution_rate
            }, status=status.HTTP_200_OK)

        except Exception as e:
            print("ERREUR API CountryStatisticsDetailView:", str(e))
            traceback.print_exc()
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



"""
def date_label(dt, granularity):
    if granularity == 'day':
        # dt peut être datetime ou date
        if hasattr(dt, 'strftime'):
            return dt.strftime('%a')  # 'Mon', 'Tue', ...
        return str(dt)
    elif granularity == 'month':
        if hasattr(dt, 'strftime'):
            return dt.strftime('%Y-%m')
        return str(dt)
    elif granularity == 'year':
        if hasattr(dt, 'strftime'):
            return dt.strftime('%Y')
        return str(dt)
    elif granularity == 'quarter':
        # Pas standard, on encode '2023-Q1' etc.
        if hasattr(dt, 'year') and hasattr(dt, 'month'):
            quarter = (dt.month - 1) // 3 + 1
            return f"{dt.year}-Q{quarter}"
        return str(dt)
    return str(dt)
"""