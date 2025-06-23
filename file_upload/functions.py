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


def group_statistic_by_sinistre(df):

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

def check_conformity(row):
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

def string_to_upper(df):
    for col in df.columns:
        if df[col].dtype == 'object':  
            df[col] = df[col].str.upper()

    return df

def generate_observation(row):
    observations = []

    ecart_facture = row["Écart facturé"]
    ecart_rembourse = row["Écart remboursé"]
    
    if ecart_facture > 0 and ecart_rembourse == 0:
        observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
    if ecart_facture < 0 and ecart_rembourse == 0:
        observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
    if ecart_rembourse > 0 and ecart_facture == 0:
        observations.append("Montant remboursé statistique > montant remboursé rapprochement.")
    
    if ecart_rembourse < 0 and ecart_facture == 0:
        observations.append("Montant remboursé statistique < montant remboursé rapprochement.")
    
    if (ecart_facture > 0 and ecart_rembourse < 0) or (ecart_facture > 0 and ecart_rembourse < 0):
        observations.append("Montants facturés et remboursés non conformes.")

    return "; ".join(observations) if observations else "Non conforme en raison d'écarts."


def generate_no_conformity_excel(df, df_stat, df_recap):

    file_name = 'rapports_sinistres.xlsx'

    numeros_sinistre = df['Numéro de sinistre'].unique()

    df_stat_filtered = df_stat[df_stat['Numéro de sinistre'].isin(numeros_sinistre)]
    df_recap_filtered = df_recap[df_recap['Numéro de sinistre'].isin(numeros_sinistre)]

    try:
        with pd.ExcelWriter(file_name) as writer:
            df.to_excel(writer, sheet_name='No Conformité', index=False)
            df_stat_filtered.to_excel(writer, sheet_name='Statistiques Filtrées', index=False)
            df_recap_filtered.to_excel(writer, sheet_name='Récapitulatif Filtré', index=False)
    except Exception as e:
        return str(e)
