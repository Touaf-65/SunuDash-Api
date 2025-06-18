import pandas as pd
from rest_framework.response import Response

def open_excel_csv(file):

    if file.name.endswith('.xlsx') or file.name.endswith('.xls'):
        df = pd.read_excel(file)
    elif file.name.endswith('.csv'):
        df = pd.read_csv(file)
    else:
        return Response({"error": "Le fichier récap doit être au format Excel (xlsx/xls) ou CSV."},)
    return df

def replace_invalid_numeric_values(df,column):
    df[column] = pd.to_numeric(df[column], errors='coerce').fillna(0)


def convert_dates_datetime(df, column):
    column_type = df[column].dtype

    if column_type == 'object':
        df[column] = pd.to_datetime(df[column], errors='coerce')
    elif column_type in ['int64', 'int32']:
        df[column] = pd.to_datetime(df[column], origin='1899-12-30', unit='D')
    return df

    