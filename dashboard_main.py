import sqlite3
import pandas as pd
from datetime import datetime
import streamlit as st
import matplotlib.pyplot as plt
from collections import Counter, defaultdict
import ipaddress
from statistics import mean, stdev
#plik bierze z mojego generatora link do generatora gdzies tam podrzcuci
DB_FILE = "activity_logs.db"

@st.cache_data
def load_data():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM logs", conn, parse_dates=["timestamp"])
    conn.close()
    return df

def filter_data(df, user, action, date_from, date_to):
    if user:
        df = df[df["username"] == user]
    if action:
        df = df[df["action"] == action]
    if date_from:
        df = df[df["timestamp"] >= date_from]
    if date_to:
        df = df[df["timestamp"] <= date_to]
    return df

def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False

def main():
    st.title("Analizator Danych – Dashboard made by bsolecki")

    df = load_data()

    # sidebar filrty calsoc
    st.sidebar.header("Filtry")
    users = df["username"].unique()
    actions = df["action"].unique()

    selected_user = st.sidebar.selectbox("Użytkownik", options=["Wszyscy"] + list(users))
    selected_action = st.sidebar.selectbox("Akcja", options=["Wszystkie"] + list(actions))
    date_from = st.sidebar.date_input("Data od", value=None)
    date_to = st.sidebar.date_input("Data do", value=None)

    if selected_user == "Wszyscy":
        selected_user = None
    if selected_action == "Wszystkie":
        selected_action = None

                                                                                             # filt danych ///////
    filtered_df = filter_data(df, selected_user, selected_action,
                              date_from if isinstance(date_from, datetime) else None,
                              date_to if isinstance(date_to, datetime) else None)

    st.write(f"### Wyniki filtrowania — {len(filtered_df)} rekordów")

                                                                                        #tabela///////
    st.dataframe(filtered_df)

    if len(filtered_df) == 0:
        st.warning("Brak danych dla wybranych filtrów.")
        return

    # agr i staty
    total_actions = len(filtered_df)
    unique_days = filtered_df["timestamp"].dt.date.nunique()
    unique_users = filtered_df["username"].nunique()
    srednia_akcji_na_dzien = total_actions / unique_days if unique_days > 0 else 0
    najczestsze_akcje = filtered_df["action"].value_counts().head(5)

    st.subheader("Statystyki")
    st.markdown(f"- Łączna liczba akcji: **{total_actions}**")
    st.markdown(f"- Liczba dni: **{unique_days}**")
    st.markdown(f"- Średnia liczba akcji na dzień: **{srednia_akcji_na_dzien:.2f}**")
    st.markdown(f"- Liczba unikalnych użytkowników: **{unique_users}**")

    st.markdown("**Najczęstsze akcje:**")
    st.bar_chart(najczestsze_akcje)

                                                                                                 # trendy aktywnosci na lini
    dzienne_aktyw = filtered_df.groupby(filtered_df["timestamp"].dt.date).size()
    fig, ax = plt.subplots(figsize=(10,5))
    dzienne_aktyw.plot(ax=ax, marker='o')
    ax.set_title("Trend aktywności (akcje na dzień)")
    ax.set_xlabel("Data")
    ax.set_ylabel("Liczba akcji")
    ax.grid(True)
    st.pyplot(fig)

    #anomalie
    st.subheader("Wykrywanie anomalii")

    godziny_pracy_start = 6
    godziny_pracy_koniec = 23

    # action poza godz pracy
    poza_godz_pracy = filtered_df[
        ~filtered_df["timestamp"].dt.hour.between(godziny_pracy_start, godziny_pracy_koniec - 1)
    ]

    st.markdown(f"- Akcje poza godzinami pracy (6:00–23:00): **{len(poza_godz_pracy)}**")
    if len(poza_godz_pracy) > 0:
        st.dataframe(poza_godz_pracy.head(10))

                                                                                                                    # publiczne ip - logi
    filtered_df["private_ip"] = filtered_df["ip_address"].apply(is_private_ip)
    ip_anonimowe = filtered_df[~filtered_df["private_ip"]]

    st.markdown(f"- Logowania z publicznych IP: **{len(ip_anonimowe)}**")
    if len(ip_anonimowe) > 0:
        st.dataframe(ip_anonimowe.head(10))

    # dziwne device (<1% wystąpien)
    urzadzenia = filtered_df["device"]
    prog_rzadkosci = len(urzadzenia) * 0.01
    urzadzenia_counter = urzadzenia.value_counts()
    rzadkie_urzadzenia = urzadzenia_counter[urzadzenia_counter < prog_rzadkosci].index.tolist()
    nietypowe_urzadzenia = filtered_df[filtered_df["device"].isin(rzadkie_urzadzenia)]

    st.markdown(f"- Nietypowe urządzenia (<1%): **{len(nietypowe_urzadzenia)}**")
    if len(nietypowe_urzadzenia) > 0:
        st.dataframe(nietypowe_urzadzenia.head(10))


    st.subheader("Eksport danych")
    if st.button("Eksportuj aktualne dane do CSV"):
        csv_data = filtered_df.to_csv(index=False)
        st.download_button(label="Pobierz CSV", data=csv_data, file_name="report.csv", mime="text/csv")

if __name__ == "__main__":
    main()