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