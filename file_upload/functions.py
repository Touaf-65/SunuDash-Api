import pandas as pd
from rest_framework.response import Response

def open_excel_csv(file):

    if file.name.endswith('.xlsx') or file.name.endswith('.xls'):
        df = pd.read_excel(file)
    elif file.name.endswith('.csv'):
        df = pd.read_csv(file)
    return df

def replace_invalid_numeric_values(df,column):
    df[column] = pd.to_numeric(df[column], errors='coerce').fillna(0)


def convert_dates_datetime(df, column):
    column_type = df[column].dtype

    if column_type == 'object':
        df[column] = pd.to_datetime(df[column], errors='coerce', dayfirst=True)
    elif column_type in ['int64', 'int32']:
        df[column] = pd.to_datetime(df[column], origin='1899-12-30', unit='D', dayfirst=True)
    return df

def concat_uniques(series):
        return ', '.join(str(x) for x in series.dropna().unique())


def grouper_static_by_sinistre(df):

    grouped = df.groupby('Numero de sinistre').agg({
        'Nom bénéficiaire': 'first',
        'Nom Assuré Principal': 'first',
        'Numero de police': 'first',
        'Nom du partenaire': 'first',
        'Date de sinistre': 'first',
        'Date de règlement': 'first',
        'Statut': 'first',
        'Montant facturé': 'sum',
        'Montant remboursé': 'sum',
        'Nom Acte': concat_uniques,
        'Categorie d\'acte': concat_uniques,
        'Famille Acte': concat_uniques,
    }).reset_index()
    return grouped

def convert_to_upper(df, column):
    df[column] = df[column].str.upper()
    return df

def verifier_conformite(row):
    if -5 < abs(row["Écart facturé"]) < 5 and -5 < abs(row["Écart remboursé"]) < 5:
        return "Conforme"
    else:
        return "Non conforme"

def df_no_conformity_by_sinistre(df):
    grouped = df.groupby('Numéro de sinistre').agg({
        'Nom bénéficiaire': 'first',
        'Nom Assuré Principal': 'first',
        'Numero de police': 'first',
        'Nom du partenaire': 'first',
        'Date de sinistre': 'first',
        'Date de règlement': 'first',
        'Statut': 'first',
        'Total facturé': 'first',
        'Total remboursé': 'first',
        'Nom Acte': concat_uniques,
        'Categorie d\'acte': concat_uniques,
        'Famille Acte': concat_uniques,
        'Employeur': 'first',
        'N°_police': 'first',
        'Total facturé rapprochement': 'sum',
        'Total remboursé rapprochement': 'sum',
        'NumFacture': 'first',
        'Note': 'first',
    }).reset_index()
    return grouped

def delete_conform_rows(df):
    df_filtre = df[~((df['Total facturé'] == df['Total facturé rapprochement']) & 
                     (df['Total remboursé'] == df['Total remboursé rapprochement']))]
    return df_filtre