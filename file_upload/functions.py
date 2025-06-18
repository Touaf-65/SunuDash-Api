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

def replace_invalid_numeric_values(rec,column):
    rec[column] = pd.to_numeric(rec[column], errors='coerce').fillna(0)


def convert_dates_datetime(rec, column):
    column_type = rec[column].dtype

    if column_type == 'object':
        rec[column] = pd.to_datetime(rec[column], errors='coerce')
    elif column_type in ['int64', 'int32']:
        rec[column] = pd.to_datetime(rec[column], origin='1899-12-30', unit='D')
    else:
        pass
    return rec

    