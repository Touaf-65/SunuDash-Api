import pandas as pd

from .models import (
    File, Client, Policy, Insured, InsuredEmployer, Invoice, Partner, 
    PaymentMethod, Operator, Claim, Act, ActFamily, ActCategory
)
from users.models import Country
from datetime import datetime
from django.utils.timezone import make_aware, is_naive


def get_or_create_category(label, file):
    if isinstance(label, str):
        label = label.strip()
    else:
        label = " "
    return ActCategory.objects.get_or_create(label=label.strip())[0]

def get_or_create_family(label, category, file):
    if isinstance(label, str):
        label = label.strip()
    else:
        label = " "
    return ActFamily.objects.get_or_create(label=label.strip(), category=category)[0]

def get_or_create_act(label, family, category, file=None):
    if isinstance(label, str):
        label = label.strip()
    else:
        label = " "
    return Act.objects.get_or_create(label=label, family=family)[0]


def get_or_create_partner(name, country_name, user, file):
    if isinstance(country_name, str):
        country_name = country_name.strip()
    else:
        country_name = None

    country = Country.objects.filter(name__iexact=country_name).first() or user.country
    return Partner.objects.get_or_create(name=name.strip(), country=country)[0]

def get_or_create_client(name, country, file):
    return Client.objects.get_or_create(name=name.strip(), country=country, file=file)[0]

def get_or_create_policy(number, client, file):
    return Policy.objects.get_or_create(policy_number=number.strip(), client=client, file=file)[0]

def get_or_create_insured(name, statut, principal_name, insured_dict, file):
    primary_insured = insured_dict.get(principal_name.strip()) if principal_name else None
    is_primary = statut == "A"
    is_spouse = statut == "C"
    is_child = statut == "E"
    insured, _ = Insured.objects.get_or_create(
        name=name.strip(),
        defaults=dict(
            is_primary_insured=is_primary,
            is_spouse=is_spouse,
            is_child=is_child,
            primary_insured=primary_insured,
            file=file
        )
    )
    return insured

def get_or_create_invoice(number, claimed, reimbursed, provider, insured, file):
    return Invoice.objects.get_or_create(
        invoice_number=number.strip(),
        provider=provider,
        insured=insured,
        defaults=dict(
            claimed_amount=claimed,
            reimbursed_amount=reimbursed,
            file=file
        )
    )[0]

def get_or_create_operator(name):
    if isinstance(name, str):
        name = name.strip()
    else:
        name = " "
    return Operator.objects.get_or_create(name=name.strip())[0]

def get_or_create_payment_method(number, date, provider, file):
    if isinstance(date, str):
        try:
            date = make_aware(datetime.strptime(date, "%m/%d/%Y"))
        except ValueError:
            try:
                date = make_aware(datetime.strptime(date, "%Y-%m-%d"))
            except ValueError:
                date = make_aware(pd.to_datetime(date).to_pydatetime())

    elif isinstance(date, (pd.Timestamp, datetime)):
        date = make_aware(pd.to_datetime(date).to_pydatetime())

    elif isinstance(date, (int, float)):
        date = make_aware(pd.to_datetime(date, unit='d', origin='1899-12-30').to_pydatetime())

    else:
        raise ValueError(f"Format de date non reconnu : {type(date)}")

    return PaymentMethod.objects.get_or_create(
        payment_number=number.strip(),
        provider=provider,
        defaults=dict(emission_date=date)
    )[0]


def get_or_create_claim(claim_id, status, date_claim, settlement_date, invoice, act, operator, insured, partner, policy, file):
    if isinstance(date_claim, str):
        try:
            date_claim = make_aware(datetime.strptime(date_claim, "%m/%d/%Y"))
        except ValueError:
            try:
                date_claim = make_aware(datetime.strptime(date_claim, "%Y-%m-%d"))
            except ValueError:
                date_claim = make_aware(pd.to_datetime(date_claim).to_pydatetime())

    elif isinstance(date_claim, (pd.Timestamp, datetime)):
        date_claim = make_aware(pd.to_datetime(date_claim).to_pydatetime())

    elif isinstance(date_claim, (int, float)):
        date_claim = make_aware(pd.to_datetime(date_claim, unit='d', origin='1899-12-30').to_pydatetime())

    else:
        raise ValueError(f"Format de date non reconnu : {type(date_claim)}")
    return Claim.objects.update_or_create(
        id=claim_id.strip(),
        defaults=dict(
            status=status[0],
            claim_date=date_claim,
            settlement_date = make_aware(settlement_date) if is_naive(settlement_date) else settlement_date,
            invoice=invoice,
            act=act,
            operator=operator,
            insured=insured,
            partner=partner,
            policy=policy,
            file=file
        )
    )[0]

def import_data(df, user, file):
    insured_dict = {}
    for _, row in df.iterrows():
        cat = get_or_create_category(row["Categorie d'acte"], file)

        fam = get_or_create_family(row["Famille Acte"], cat, file)

        act = get_or_create_act(row["Nom Acte"], fam, cat, file)

        partner = get_or_create_partner(row["Nom du partenaire"], row["Pays du partenaire"], user, file)

        client = get_or_create_client(row["Nom Employeur"], user.country, file)

        policy = get_or_create_policy(row["Numero de police"], client, file)

        insured = get_or_create_insured(row["Nom bénéficiaire"], row["Statut Assuré"], row.get("Nom Assuré Principal", ""), insured_dict, file)
        insured_dict[insured.name] = insured

        InsuredEmployer.objects.get_or_create(
            insured=insured,
            employer=client,
            policy=policy,
            defaults=dict(
                role={'A': 'primary', 'C': 'spouse', 'E': 'child'}.get(row["Statut Assuré"], 'other'),
                primary_insured_ref=insured.primary_insured,
                file=file
            )
        )

        invoice = get_or_create_invoice(
            row["Numero de Facture"],
            row["Montant facturé"],
            float(str(row.get("Montant remboursé", 0)).replace(',', '').strip()),
            provider=partner,
            insured=insured,
            file=file
        )

        operator = get_or_create_operator(row["Modifié par"])

        if pd.notna(row["N°cheque/Autre_Moyent_de_payement"]) and pd.notna(row["Date de règlement"]):
            get_or_create_payment_method(row["N°cheque/Autre_Moyent_de_payement"], row["Date de règlement"], partner, file)

        get_or_create_claim(
            row["Numéro de sinistre"],
            row["Statut"],
            row["Date de sinistre"],
            row["Date de règlement"],
            invoice,
            act,
            operator,
            insured,
            partner,
            policy,
            file
        )
