from django.db.models import Sum
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from users.models import Country, CustomUser
from users.permissions import IsSuperUser, IsGlobalAdmin, IsTerritorialAdmin, IsChefDeptTech, IsResponsableOperateur
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
                # Contrôle strict : refuse si un autre country_id est envoyé
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
            print(f"Client: {client.name} ({client.id})")
            nb_policies = Policy.objects.filter(client=client).count()
            insured_links = InsuredEmployer.objects.filter(employer=client)
            print(f"  insured_links: {insured_links.count()}")
            nb_primary = insured_links.filter(role='primary').count()
            nb_total = insured_links.count()
            insured_ids = list(insured_links.values_list('insured_id', flat=True))
            print(f"  insured_ids: {insured_ids}")
            claims = Claim.objects.filter(
                insured_id__in=insured_ids,
                claim_date__range=(date_start, date_end)
            )
            print(f"  claims: {claims.count()}")
            invoice_ids = list(claims.values_list('invoice_id', flat=True))
            print(f"  invoice_ids: {invoice_ids}")
            total_consumption = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('claimed_amount'))['total'] or 0
            total_reimbursement = Invoice.objects.filter(id__in=invoice_ids).aggregate(total=Sum('reimbursed_amount'))['total'] or 0
            print(f"  total_consumption: {total_consumption}, total_reimbursement: {total_reimbursement}")
            # ... reste du code ...

            results.append({
                "client_id": client.id,
                "client_name": client.name,
                "contact": client.contact,
                "nb_policies": nb_policies,
                "nb_primary_insured": nb_primary,
                "nb_total_insured": nb_total,
                "total_consumption": str(total_consumption),
               "total_reimbursement": str(total_reimbursement),
                "type total consumption": type(str(total_consumption)).__name__,
                "type total reimbursement": type(str(total_reimbursement)).__name__,
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
    permission_classes = [IsAuthenticated]

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
    pass


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
    # permission_classes = [IsAuthenticated, IsSuperUser | IsGlobalAdmin]

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