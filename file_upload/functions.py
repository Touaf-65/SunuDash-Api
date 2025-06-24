import pandas as pd
import os
from datetime import datetime
from rest_framework.response import Response

def open_excel_csv(file):
    """
    Opens an Excel or CSV file and loads it into a DataFrame.

    Args:
        file: The file to open, which can be an Excel file (.xlsx, .xls) or a CSV file (.csv).

    Returns:
        pd.DataFrame: The DataFrame containing the data from the file.

    Raises:
        ValueError: If the file format is unsupported or cannot be opened.
    """
    try:
        if file.name.endswith('.xlsx') or file.name.endswith('.xls'):
            df = pd.read_excel(file)
        elif file.name.endswith('.csv'):
            df = pd.read_csv(file)
        else:
            raise ValueError("Unsupported file format.")
        return df
    except Exception as e:
        raise ValueError(f"Error opening file: {e}")

def replace_invalid_numeric_values(df, column):
    """
    Replaces non-numeric values in a column with 0.

    Args:
        df (pd.DataFrame): The DataFrame to modify.
        column (str): The name of the column to process.

    Raises:
        KeyError: If the specified column does not exist in the DataFrame.
    """
    if column in df.columns:
        df[column] = pd.to_numeric(df[column], errors='coerce').fillna(0)
    else:
        raise KeyError(f"Column '{column}' does not exist in DataFrame.")

def convert_dates_datetime(df, column):
    """
    Converts a column to datetime type.

    Args:
        df (pd.DataFrame): The DataFrame to modify.
        column (str): The name of the column to convert.

    Returns:
        pd.DataFrame: The DataFrame with the converted column.
    """
    if column in df.columns:
        column_type = df[column].dtype

        if column_type == 'object':
            df[column] = pd.to_datetime(df[column], errors='coerce', dayfirst=True)
        elif column_type in ['int64', 'int32']:
            df[column] = pd.to_datetime(df[column], origin='1899-12-30', unit='D', dayfirst=True)
    else:
        raise KeyError(f"Column '{column}' does not exist in DataFrame.")
    return df

def concat_uniques(series):
    """
    Concatenates unique values from a series into a string.

    Args:
        series (pd.Series): The series to process.

    Returns:
        str: A string containing the unique values.
    """
    return ', '.join(str(x) for x in series.dropna().unique())

def group_statistic_by_sinistre(df):
    """
    Groups data by claim number and aggregates the information.

    Args:
        df (pd.DataFrame): The DataFrame to group.

    Returns:
        pd.DataFrame: A DataFrame grouped by claim number.

    Raises:
        KeyError: If required columns are missing.
    """
    required_columns = ['Numéro de sinistre', 'Nom bénéficiaire', 'Nom Assuré Principal', 
                        'Numero de police', 'Nom du partenaire', 'Date de sinistre', 
                        'Date de règlement', 'Statut', 'Montant facturé', 'Montant remboursé']
    
    if not all(col in df.columns for col in required_columns):
        raise KeyError("One or more required columns are missing.")

    grouped = df.groupby('Numéro de sinistre').agg({
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
    """
    Converts all values in a specified column to uppercase.

    Args:
        df (pd.DataFrame): The DataFrame to modify.
        column (str): The name of the column to convert.

    Returns:
        pd.DataFrame: The modified DataFrame.
    """
    if column in df.columns:
        df[column] = df[column].str.upper()
    else:
        raise KeyError(f"Column '{column}' does not exist in DataFrame.")
    return df

def check_conformity(row):
    """
    Checks the conformity of billed and reimbursed amounts based on defined criteria.

    Args:
        row (pd.Series): A row of the DataFrame containing the relevant columns.

    Returns:
        str: 'Conforme' if the row is conforming, 'Non conforme' otherwise.
    """
    if -5 < abs(row["Écart facturé"]) < 5 and -5 < abs(row["Écart remboursé"]) < 5:
        return "Conforme"
    else:
        return "Non conforme"

def df_no_conformity_by_sinistre(df):
    """
    Groups non-conforming data by claim number and aggregates the information.

    Args:
        df (pd.DataFrame): The DataFrame to process.

    Returns:
        pd.DataFrame: A DataFrame of non-conforming data grouped by claim number.
    """
    grouped = df.groupby('Numéro de sinistre').agg({
        'Nom bénéficiaire': 'first',
        'Nom Assuré Principal': 'first',
        'Numero de police': 'first',
        'Nom du partenaire': 'first',
        'Date de sinistre': 'first',
        'Date de règlement': 'first',
        'Statut': 'first',
        'Montant facturé': 'first',
        'Montant remboursé': 'first',
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
    """
    Deletes conforming rows from the DataFrame.

    Args:
        df (pd.DataFrame): The DataFrame to filter.

    Returns:
        pd.DataFrame: The filtered DataFrame without conforming rows.
    """
    df_filtre = df[~((df['Montant facturé'] == df['Total facturé rapprochement']) & 
                     (df['Montant remboursé'] == df['Total remboursé rapprochement']))]
    return df_filtre

def string_to_upper(df):
    """
    Converts all string values in all object-type columns to uppercase.

    Args:
        df (pd.DataFrame): The DataFrame to modify.

    Returns:
        pd.DataFrame: The modified DataFrame.
    """
    for col in df.columns:
        if df[col].dtype == 'object':  
            df[col] = df[col].str.upper()
    return df

def generate_observation(row):
    """
    Generates observations based on discrepancies in billed and reimbursed amounts.

    Args:
        row (pd.Series): A row of the DataFrame containing the relevant columns.

    Returns:
        str: A string of observations or a message indicating non-conformity.
    """
    observations = []

    ecart_facture = row.get("Écart facturé", 0)
    ecart_rembourse = row.get("Écart remboursé", 0)
    
    if ecart_facture > 0 and ecart_rembourse == 0:
        observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
    if ecart_facture < 0 and ecart_rembourse == 0:
        observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
    if ecart_rembourse > 0 and ecart_facture == 0:
        observations.append("Montant remboursé statistique > montant remboursé rapprochement.")
    
    if ecart_rembourse < 0 and ecart_facture == 0:
        observations.append("Montant remboursé statistique < montant remboursé rapprochement.")
    
    if (ecart_facture > 0 and ecart_rembourse < 0) or (ecart_facture < 0 and ecart_rembourse > 0):
        observations.append("Montants facturés et remboursés non conformes.")

    return "; ".join(observations) if observations else "Non conforme en raison d'écarts."

def generate_no_conformity_excel(df, df_stat, df_recap):
    """
    Generates an Excel file with multiple sheets for non-conformity data.

    Args:
        df (pd.DataFrame): The non-conforming DataFrame.
        df_stat (pd.DataFrame): The statistics DataFrame.
        df_recap (pd.DataFrame): The recap DataFrame.

    Returns:
        str: An error message if an exception occurs, otherwise the file path.
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    file_name = f'rapports_sinistres_{timestamp}.xlsx'
    file_path = os.path.join('downloads', file_name)

    # Ensure the downloads directory exists
    os.makedirs('downloads', exist_ok=True)

    numeros_sinistre = df['Numéro de sinistre'].unique()

    df_stat_filtered = df_stat[df_stat['Numéro de sinistre'].isin(numeros_sinistre)]
    df_recap_filtered = df_recap[df_recap['Numéro de sinistre'].isin(numeros_sinistre)]

    try:
        with pd.ExcelWriter(file_path) as writer:
            df.to_excel(writer, sheet_name='No Conformité', index=False)
            df_stat_filtered.to_excel(writer, sheet_name='Statistiques Filtrées', index=False)
            df_recap_filtered.to_excel(writer, sheet_name='Récapitulatif Filtré', index=False)
    except Exception as e:
        return str(e)
    return file_path

















# import pandas as pd
# import os
# from datetime import datetime
# from rest_framework.response import Response

# def open_excel_csv(file):
#     """
#     Opens an Excel or CSV file and loads it into a DataFrame.

#     Args:
#         file: The file to open, which can be an Excel file (.xlsx, .xls) or a CSV file (.csv).

#     Returns:
#         pd.DataFrame: The DataFrame containing the data from the file.
#     """

#     if file.name.endswith('.xlsx') or file.name.endswith('.xls'):
#         df = pd.read_excel(file)
#     elif file.name.endswith('.csv'):
#         df = pd.read_csv(file)
#     return df

# def replace_invalid_numeric_values(df,column):
#     """
#     Replaces non-numeric values in a column with 0.

#     Args:
#         df (pd.DataFrame): The DataFrame to modify.
#         column (str): The name of the column to process.
#     """
#     df[column] = pd.to_numeric(df[column], errors='coerce').fillna(0)


# def convert_dates_datetime(df, column):
#     """
#     Converts a column to datetime type.

#     Args:
#         df (pd.DataFrame): The DataFrame to modify.
#         column (str): The name of the column to convert.

#     Returns:
#         pd.DataFrame: The DataFrame with the converted column.
#     """
#     column_type = df[column].dtype

#     if column_type == 'object':
#         df[column] = pd.to_datetime(df[column], errors='coerce', dayfirst=True)
#     elif column_type in ['int64', 'int32']:
#         df[column] = pd.to_datetime(df[column], origin='1899-12-30', unit='D', dayfirst=True)
#     return df

# def concat_uniques(series):
#     """
#     Concatenates unique values from a series into a string.

#     Args:
#         series (pd.Series): The series to process.

#     Returns:
#         str: A string containing the unique values.
#     """
#     return ', '.join(str(x) for x in series.dropna().unique())


# def group_statistic_by_sinistre(df):
#     """
#     Groups data by claim number and aggregates the information.

#     Args:
#         df (pd.DataFrame): The DataFrame to group.

#     Returns:
#         pd.DataFrame: A DataFrame grouped by claim number.
#     """
#     grouped = df.groupby('Numero de sinistre').agg({
#         'Nom bénéficiaire': 'first',
#         'Nom Assuré Principal': 'first',
#         'Numero de police': 'first',
#         'Nom du partenaire': 'first',
#         'Date de sinistre': 'first',
#         'Date de règlement': 'first',
#         'Statut': 'first',
#         'Montant facturé': 'sum',
#         'Montant remboursé': 'sum',
#         'Nom Acte': concat_uniques,
#         'Categorie d\'acte': concat_uniques,
#         'Famille Acte': concat_uniques,
#     }).reset_index()
#     return grouped

# def convert_to_upper(df, column):
#     """
#     Converts all values in a specified column to uppercase.

#     Args:
#         df (pd.DataFrame): The DataFrame to modify.
#         column (str): The name of the column to convert.

#     Returns:
#         pd.DataFrame: The modified DataFrame.
#     """
#     df[column] = df[column].str.upper()
#     return df

# def check_conformity(row):
#     """
#     Checks the conformity of billed and reimbursed amounts based on defined criteria.

#     Args:
#         row (pd.Series): A row of the DataFrame containing the relevant columns.

#     Returns:
#         str: 'Conforme' if the row is conforming, 'Non conforme' otherwise.
#     """
#     if -5 < abs(row["Écart facturé"]) < 5 and -5 < abs(row["Écart remboursé"]) < 5:
#         return "Conforme"
#     else:
#         return "Non conforme"

# def df_no_conformity_by_sinistre(df):
#     """
#     Groups non-conforming data by claim number and aggregates the information.

#     Args:
#         df (pd.DataFrame): The DataFrame to process.

#     Returns:
#         pd.DataFrame: A DataFrame of non-conforming data grouped by claim number.
#     """
#     grouped = df.groupby('Numéro de sinistre').agg({
#         'Nom bénéficiaire': 'first',
#         'Nom Assuré Principal': 'first',
#         'Numero de police': 'first',
#         'Nom du partenaire': 'first',
#         'Date de sinistre': 'first',
#         'Date de règlement': 'first',
#         'Statut': 'first',
#         'Total facturé': 'first',
#         'Total remboursé': 'first',
#         'Nom Acte': concat_uniques,
#         'Categorie d\'acte': concat_uniques,
#         'Famille Acte': concat_uniques,
#         'Employeur': 'first',
#         'N°_police': 'first',
#         'Total facturé rapprochement': 'sum',
#         'Total remboursé rapprochement': 'sum',
#         'NumFacture': 'first',
#         'Note': 'first',
#     }).reset_index()
#     return grouped

# def delete_conform_rows(df):
#     """
#     Deletes conforming rows from the DataFrame.

#     Args:
#         df (pd.DataFrame): The DataFrame to filter.

#     Returns:
#         pd.DataFrame: The filtered DataFrame without conforming rows.
#     """
#     df_filtre = df[~((df['Total facturé'] == df['Total facturé rapprochement']) & 
#                      (df['Total remboursé'] == df['Total remboursé rapprochement']))]
#     return df_filtre

# def string_to_upper(df):
#     """
#     Converts all string values in all object-type columns to uppercase.

#     Args:
#         df (pd.DataFrame): The DataFrame to modify.

#     Returns:
#         pd.DataFrame: The modified DataFrame.
#     """
#     for col in df.columns:
#         if df[col].dtype == 'object':  
#             df[col] = df[col].str.upper()

#     return df

# def generate_observation(row):
#     """
#     Generates observations based on discrepancies in billed and reimbursed amounts.

#     Args:
#         row (pd.Series): A row of the DataFrame containing the relevant columns.

#     Returns:
#         str: A string of observations or a message indicating non-conformity.
#     """
#     observations = []

#     ecart_facture = row["Écart facturé"]
#     ecart_rembourse = row["Écart remboursé"]
    
#     if ecart_facture > 0 and ecart_rembourse == 0:
#         observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
#     if ecart_facture < 0 and ecart_rembourse == 0:
#         observations.append("Montant facturé statistique < montant facturé rapprochement.")
    
#     if ecart_rembourse > 0 and ecart_facture == 0:
#         observations.append("Montant remboursé statistique > montant remboursé rapprochement.")
    
#     if ecart_rembourse < 0 and ecart_facture == 0:
#         observations.append("Montant remboursé statistique < montant remboursé rapprochement.")
    
#     if (ecart_facture > 0 and ecart_rembourse < 0) or (ecart_facture > 0 and ecart_rembourse < 0):
#         observations.append("Montants facturés et remboursés non conformes.")

#     return "; ".join(observations) if observations else "Non conforme en raison d'écarts."


# def generate_no_conformity_excel(df, df_stat, df_recap):
#     """
#     Generates an Excel file with multiple sheets for non-conformity data.

#     Args:
#         df (pd.DataFrame): The non-conforming DataFrame.
#         df_stat (pd.DataFrame): The statistics DataFrame.
#         df_recap (pd.DataFrame): The recap DataFrame.

#     Returns:
#         str: An error message if an exception occurs, otherwise None.
#     """
#     timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
#     file_name = f'rapports_sinistres_{timestamp}.xlsx'
#     file_path = os.path.join('downloads', file_name)

#     numeros_sinistre = df['Numéro de sinistre'].unique()

#     df_stat_filtered = df_stat[df_stat['Numéro de sinistre'].isin(numeros_sinistre)]
#     df_recap_filtered = df_recap[df_recap['Numéro de sinistre'].isin(numeros_sinistre)]

#     try:
#         with pd.ExcelWriter(file_name) as writer:
#             df.to_excel(writer, sheet_name='No Conformité', index=False)
#             df_stat_filtered.to_excel(writer, sheet_name='Statistiques Filtrées', index=False)
#             df_recap_filtered.to_excel(writer, sheet_name='Récapitulatif Filtré', index=False)
#     except Exception as e:
#         return str(e)
#     return file_path