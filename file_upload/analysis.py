import pandas as pd
from .functions import replace_invalid_numeric_values, convert_dates_datetime, group_statistic_by_sinistre, string_to_upper, check_conformity, delete_conform_rows, df_no_conformity_by_sinistre, generate_observation, generate_no_conformity_excel, convert_to_upper, get_date_range, get_common_date_range


def clean_recap_data(df):
    """
    Cleans recap data by removing empty rows and duplicates, replacing invalid numeric values,
    converting date columns, and normalizing string values.

    Args:
        df (pd.DataFrame): The recap DataFrame to clean.

    Returns:
        pd.DataFrame: The cleaned recap DataFrame.
    """

    df.dropna(how='all')
    
    df.drop_duplicates()

    numeric_columns = ['totalmttreclame', 'totalmttrembourse']
    
    for col in numeric_columns:
        replace_invalid_numeric_values(df, col)
        
    df = convert_dates_datetime(df, 'date_reglement')

    df['N°_Cheque'] = df['N°_Cheque'].astype(object)

    df['autres_Moyen_de_payement'] = df['autres_Moyen_de_payement'].astype(object)

    return df


def clean_statistic_data(df):
    """
    Cleans statistic data by removing empty rows and duplicates, 
    replacing invalid numeric values, converting date columns, and normalizing string values.

    Args:
        df (pd.DataFrame): The statistic DataFrame to clean.

    Returns:
        pd.DataFrame: The cleaned statistic DataFrame.
    """

    df = df.dropna(how='all')
    
    df = df.drop_duplicates()


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

def preparing_data(df_stat, df_recap):
    """
    Cleans and standardizes the statistical and reconciliation data before further processing.

    This function performs specific cleaning operations on the two input DataFrames:
    - `df_stat`: statistical data from the main file.
    - `df_recap`: reconciliation data from a secondary file.

    It also renames certain columns to ensure consistency between the datasets,
    particularly the "Numéro de sinistre" column used as a key for merging or comparison.

    Args:
    df_stat : pandas.DataFrame
        DataFrame containing raw statistical data.

    df_recap : pandas.DataFrame
        DataFrame containing raw reconciliation data.

    Returns:
    tuple of pandas.DataFrame
        A tuple `(df_stat, df_recap)` with the cleaned and standardized DataFrames.
    """

    df_stat = clean_statistic_data(df_stat)
    df_recap = clean_recap_data(df_recap)

    df_recap = df_recap.rename(columns={
        "reglementId": "Numéro de sinistre",
        "totalmttreclame": "Total facturé rapprochement",
        "totalmttrembourse": "Total remboursé rapprochement"
    })

    df_stat = df_stat.rename(columns={
        "Numero de sinistre": "Numéro de sinistre",
    })

    return df_stat, df_recap


def compare_data(df_stat, df_recap):
    """
    Compares statistic data with recap data, checking for conformity and generating a report
    of non-conformities if necessary.

    Args:
        df_stat (pd.DataFrame): The cleaned statistic DataFrame.
        df_recap (pd.DataFrame): The cleaned recap DataFrame.

    Returns:
        tuple: (df_conformes, df_non_conformes, common_range)
            - df_conformes (pd.DataFrame): DataFrame des lignes conformes à importer
            - df_non_conformes (pd.DataFrame): DataFrame des lignes non conformes à rapporter
            - common_range (tuple): Période commune de règlement utilisée pour filtrer
    """


    recap_range = get_date_range(df_recap, 'date_reglement')
    stat_range = get_date_range(df_stat, 'Date de règlement')

    common_range = get_common_date_range(stat_range, recap_range)

    if common_range is None:
        return pd.DataFrame(), pd.DataFrame(), None

    filtered_df_stat = df_stat[(df_stat['Date de règlement'] >= common_range[0]) & (df_stat['Date de règlement'] <= common_range[1])]
    filtered_df_recap = df_recap[(df_recap['date_reglement'] >= common_range[0]) & (df_recap['date_reglement'] <= common_range[1])]


    df_stat_grouped = group_statistic_by_sinistre(filtered_df_stat)
    df_stat_grouped = convert_to_upper(df_stat_grouped, "Numéro de sinistre")
    filtered_df_recap = convert_to_upper(filtered_df_recap, "Numéro de sinistre")


    df_comparaison = pd.merge(df_stat_grouped, filtered_df_recap, on="Numéro de sinistre", how="inner")
    df_comparaison.drop_duplicates(inplace=True)

    df_comparaison["Écart facturé"] = df_comparaison["Montant facturé"] - df_comparaison["Total facturé rapprochement"]
    df_comparaison["Écart remboursé"] = df_comparaison["Montant remboursé"] - df_comparaison["Total remboursé rapprochement"]
    df_comparaison["Conformité"] = df_comparaison.apply(check_conformity, axis=1)



    df_non_conformes = df_comparaison[df_comparaison['Conformité'] == 'Non conforme'].copy()

    df_conformes = df_comparaison[df_comparaison['Conformité'] == 'Conforme'].copy()



    if not df_non_conformes.empty:
        deleted_conformes = df_non_conformes[
            (df_non_conformes['Montant facturé'] == df_non_conformes['Total facturé rapprochement']) &
            (df_non_conformes['Montant remboursé'] == df_non_conformes['Total remboursé rapprochement'])
        ]

        df_non_conformes = delete_conform_rows(df_non_conformes)

        df_conformes = pd.concat([df_conformes, deleted_conformes]).drop_duplicates(subset=["Numéro de sinistre"])

        if not df_non_conformes.empty:
            df_non_conformes['Observation'] = df_non_conformes.apply(generate_observation, axis=1)

    sinistres_conformes = df_conformes["Numéro de sinistre"].unique()
    filtered_df_stat = convert_to_upper(filtered_df_stat, "Numéro de sinistre")
    df_conformes_complet = filtered_df_stat[filtered_df_stat["Numéro de sinistre"].isin(sinistres_conformes)].copy()



    return df_conformes_complet, df_non_conformes, common_range

