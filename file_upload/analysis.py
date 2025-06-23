import pandas as pd
from .functions import replace_invalid_numeric_values, convert_dates_datetime, group_statistic_by_sinistre, string_to_upper, check_conformity, delete_conform_rows, df_no_conformity_by_sinistre, generate_observation, generate_no_conformity_excel


def clean_recap_data(df):

    df.dropna(how='all')
    
    df.drop_duplicates()

    numeric_columns = ['totalmttreclame', 'totalmttrembourse']
    
    for col in numeric_columns:
        replace_invalid_numeric_values(df, col)
        
    df = convert_dates_datetime(df, 'date_reglement')

    df['N°_Cheque'] = df['N°_Cheque'].astype(object)

    df['autres_Moyen_de_payement'] = df['autres_Moyen_de_payement'].astype(object)

    df = string_to_upper(df)

    return df


def clean_statistic_data(df):

    df.dropna(how='all')
    
    df.drop_duplicates()


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

    df = string_to_upper(df)

    return df


def compare_data(df_stat, df_recap):
    df_stat = clean_statistic_data(df_stat)
    df_recap = clean_recap_data(df_recap)

    df_recap = df_recap.rename(columns={
    "reglementId": "Numéro de sinistre",
    "totalmttreclame": "Total facturé rapprochement",
    "totalmttrembourse": "Total remboursé rapprochement"
    })

    df_stat_grouped = group_statistic_by_sinistre(df_stat)

    df_comparaison = pd.merge(df_stat_grouped, df_recap, on="Numéro de sinistre", how="inner")
    df_comparaison.drop_duplicates()

    df_comparaison["Écart facturé"] = df_comparaison["Total facturé"] - df_comparaison["Total facturé rapprochement"]
    df_comparaison["Écart remboursé"] = df_comparaison["Total remboursé"] - df_comparaison["Total remboursé rapprochement"]

    df_comparaison["Conformité"] = df_comparaison.apply(check_conformity, axis=1)

    if df_comparaison['Conformité'].str.contains("non conforme", case=False, na=False).any():
        df_no_conformity = df_comparaison.loc[df_comparaison['Conformité'] == 'Non conforme']
        
        df_no_conformity = df_no_conformity_by_sinistre(df_no_conformity)
        
        df_no_conformity = delete_conform_rows(df_no_conformity)

        if not df_no_conformity.empty:
            df_no_conformity['Observation'] = df_no_conformity.apply(generate_observation, axis=1)
            
            generate_no_conformity_excel(df_no_conformity, df_stat, df_recap)
            return df_no_conformity
        
        return True
    pass
