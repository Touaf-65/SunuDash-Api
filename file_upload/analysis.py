import pandas as pd
from .functions import replace_invalid_numeric_values, convert_dates_datetime


def clean_recap_data(df):

    df.dropna(how='all')

    numeric_columns = ['totalmttreclame', 'totalmttrembourse']
    
    for col in numeric_columns:
        replace_invalid_numeric_values(df, col)
        
    df = convert_dates_datetime(df, 'date_reglement')

    df['N°_Cheque'] = df['N°_Cheque'].astype(object)

    df['autres_Moyen_de_payement'] = df['autres_Moyen_de_payement'].astype(object)

    
    return df


def clean_statistic_file(file):
    df = pd.read_excel(file)

    df.dropna(how='all')

    columns_to_check = ['Unnamed: 1', 'Broker Name', 'Broker_SunuId', 'Adresse du Partenaire']
    existing_columns = [col for col in columns_to_check if col in df.columns]
  
    numeric_columns = ['Montant facturé', 'Montant remboursé']

    if existing_columns:
        df = df.drop(columns=existing_columns)
    
    for col in numeric_columns:
        replace_invalid_numeric_values(df, col)

    date_columns = ['Date de sinistre', 'Date de règlement']
        
    for col in date_columns:
        convert_dates_datetime(df, col)

    return df