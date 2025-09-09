import sqlite3
from collections import Counter, defaultdict
from datetime import datetime
import matplotlib.pyplot as plt
from rich.console import Console
from rich.table import Table
from rich import box
import ipaddress
from statistics import mean, stdev

DB_FILE = "activity_logs.db"
console = Console()

def parse_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d")
    except:
        return None

def query_logs(username=None, action=None, date_from=None, date_to=None, order="ASC"):
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    sql = "SELECT id, username, action, timestamp, ip_address, device FROM logs"
    params = []
    conditions = []

    if username:
        conditions.append("username = ?")
        params.append(username)
    if action:
        conditions.append("action = ?")
        params.append(action)
    if date_from:
        conditions.append("timestamp >= ?")
        params.append(date_from.strftime("%Y-%m-%d 00:00:00"))
    if date_to:
        conditions.append("timestamp <= ?")
        params.append(date_to.strftime("%Y-%m-%d 23:59:59"))

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    sql += f" ORDER BY id {order}"

    cur.execute(sql, params)
    rows = cur.fetchall()
    conn.close()
    return rows

def print_logs(logs):
    if not logs:
        console.print("[red]Brak wyników do wyświetlenia.[/red]")
        return
    table = Table(title=f"Logi", box=box.SIMPLE_HEAD)
    table.add_column("ID", style="cyan", justify="right")
    table.add_column("Użytkownik", style="yellow")
    table.add_column("Akcja", style="green")
    table.add_column("Data", style="magenta")
    table.add_column("IP", style="cyan")
    table.add_column("Urządzenie", style="blue")
    for log in logs:
        table.add_row(*map(str, log))
    console.print(table)

def export_to_csv(logs, filename="report.csv"):
    if not logs:
        console.print("[red]Brak danych do eksportu.[/red]")
        return
    with open(filename, "w", newline="", encoding="utf-8") as f:
        import csv
        writer = csv.writer(f)
        writer.writerow(["ID", "Username", "Akcja", "Data", "IP", "Urządzenie"])
        writer.writerows(logs)
    console.print(f"[green]Raport zapisany do {filename}[/green]")

def agregacje_i_statystyki(logs):
    if not logs:
        console.print("[red]Brak danych w podanym zakresie dat lub filtrach.[/red]")
        return

    total_actions = len(logs)
    dates = [datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S").date() for row in logs]
    unique_days = set(dates)
    unique_users = set(row[1] for row in logs)
    actions = [row[2] for row in logs]

    srednia_akcji_na_dzien = total_actions / len(unique_days)
    liczba_unikalnych_uzytkownikow = len(unique_users)
    najczestsze_akcje = Counter(actions).most_common(5)

    console.print(f"[bold green]Agregacje i statystyki za wybrany okres:[/bold green]")
    console.print(f"Łączna liczba akcji: {total_actions}")
    console.print(f"Liczba dni: {len(unique_days)}")
    console.print(f"Średnia liczba akcji na dzień: {srednia_akcji_na_dzien:.2f}")
    console.print(f"Liczba unikalnych użytkowników: {liczba_unikalnych_uzytkownikow}")
    console.print("Najczęstsze akcje:")
    table = Table(box=box.SIMPLE)
    table.add_column("Akcja", style="cyan")
    table.add_column("Liczba", style="yellow")
    for akcja, ilosc in najczestsze_akcje:
        table.add_row(akcja, str(ilosc))
    console.print(table)

    # Trend aktywności (liczba akcji na dzień)
    dzienne_aktyw = defaultdict(int)
    for d in dates:
        dzienne_aktyw[d] += 1

    dates_sorted = sorted(dzienne_aktyw.keys())
    values = [dzienne_aktyw[d] for d in dates_sorted]

    plt.figure(figsize=(10,5))
    plt.plot(dates_sorted, values, marker='o')
    plt.title("Trend aktywności (akcje na dzień)")
    plt.xlabel("Data")
    plt.ylabel("Liczba akcji")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

def wykrywanie_anomalii(logs):
    if not logs:
        console.print("[red]Brak danych do analizy anomalii.[/red]")
        return

    godziny_pracy_start = 6
    godziny_pracy_koniec = 23

    # action poza godz pracy
    poza_godz_pracy = [row for row in logs if not (godziny_pracy_start <= datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S").hour < godziny_pracy_koniec)]

                                                                                    #sus ip
    def jest_typowe_ip(ip):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False

    ip_anonimowe = [row for row in logs if not jest_typowe_ip(row[4])]

                                                                                #susdev
    urzadzenia = [row[5] for row in logs]
    liczba_urzadzen = len(urzadzenia)
    prog_rzadkosci = liczba_urzadzen * 0.01
    urzadzenia_counter = Counter(urzadzenia)
    rzadkie_urzadzenia = set([u for u, c in urzadzenia_counter.items() if c < prog_rzadkosci])
    nietypowe_urzadzenia = [row for row in logs if row[5] in rzadkie_urzadzenia]

    # skok aktyw
    dzienne_aktyw = defaultdict(int)
    for row in logs:
        d = datetime.strptime(row[3], "%Y-%m-%d %H:%M:%S").date()
        dzienne_aktyw[d] +=1

    wartosci = list(dzienne_aktyw.values())
    if len(wartosci) > 1:
        srednia = mean(wartosci)
        odchylenie = stdev(wartosci)
        progi = srednia + 2*odchylenie
        skok_aktyw = [d for d, val in dzienne_aktyw.items() if val > progi]
    else:
        skok_aktyw = []

                                            #print wyniki
    console.print("\n[bold red]Wykrywanie anomalii:[/bold red]")

    console.print(f"\nAkcje poza godzinami pracy ({godziny_pracy_start}:00 - {godziny_pracy_koniec}:00): {len(poza_godz_pracy)}")
    if len(poza_godz_pracy) > 0:
        table = Table(box=box.MINIMAL)
        table.add_column("ID", style="cyan")
        table.add_column("Użytkownik", style="yellow")
        table.add_column("Akcja", style="green")
        table.add_column("Data", style="magenta")
        for row in poza_godz_pracy[:10]:
            table.add_row(str(row[0]), row[1], row[2], row[3])
        if len(poza_godz_pracy) > 10:
            console.print(f"... oraz {len(poza_godz_pracy)-10} więcej")
        console.print(table)
    else:
        console.print("Brak.")

    console.print(f"\nLogowania z nietypowych IP (publiczne): {len(ip_anonimowe)}")
    if len(ip_anonimowe) > 0:
        table = Table(box=box.MINIMAL)
        table.add_column("ID", style="cyan")
        table.add_column("Użytkownik", style="yellow")
        table.add_column("Akcja", style="green")
        table.add_column("IP", style="magenta")
        for row in ip_anonimowe[:10]:
            table.add_row(str(row[0]), row[1], row[2], row[4])
        if len(ip_anonimowe) > 10:
            console.print(f"... oraz {len(ip_anonimowe)-10} więcej")
        console.print(table)
    else:
        console.print("Brak.")

    console.print(f"\nNietypowe urządzenia (występujące rzadziej niż 1%): {len(nietypowe_urzadzenia)}")
    if len(nietypowe_urzadzenia) > 0:
        table = Table(box=box.MINIMAL)
        table.add_column("ID", style="cyan")
        table.add_column("Użytkownik", style="yellow")
        table.add_column("Akcja", style="green")
        table.add_column("Urządzenie", style="magenta")
        for row in nietypowe_urzadzenia[:10]:
            table.add_row(str(row[0]), row[1], row[2], row[5])
        if len(nietypowe_urzadzenia) > 10:
            console.print(f"... oraz {len(nietypowe_urzadzenia)-10} więcej")
        console.print(table)
    else:
        console.print("Brak.")

    console.print(f"\nDni z nagłym skokiem aktywności (> średnia + 2*std): {len(skok_aktyw)}")
    if len(skok_aktyw) > 0:
        for d in skok_aktyw:
            console.print(f" - {d} ({dzienne_aktyw[d]} akcji)")
    else:
        console.print("Brak.")

def menu():
    while True:
        console.print("\n[bold cyan]=== ANALIZATOR PRO – MENU ===[/bold cyan]")
        console.print("1. Pokaż logi (filtruj i sortuj)")
        console.print("2. Pokaż agregacje i statystyki za zakres dat")
        console.print("3. Wykryj anomalie za zakres dat")
        console.print("4. Eksportuj logi do CSV")
        console.print("0. Wyjdź")

        choice = input("Wybierz opcję: ").strip()
        if choice == "1":
            username = input("Filtr - użytkownik (enter = brak): ").strip() or None
            action = input("Filtr - akcja (enter = brak): ").strip() or None
            date_from_str = input("Filtr - data od (YYYY-MM-DD, enter = brak): ").strip()
            date_to_str = input("Filtr - data do (YYYY-MM-DD, enter = brak): ").strip()
            order = input("Sortowanie po ID (ASC/DESC) [ASC]: ").strip().upper() or "ASC"

            date_from = parse_date(date_from_str) if date_from_str else None
            date_to = parse_date(date_to_str) if date_to_str else None

            logs = query_logs(username, action, date_from, date_to, order)
            print_logs(logs)

        elif choice == "2":
            date_from_str = input("Data początkowa (YYYY-MM-DD, enter = brak): ").strip()
            date_to_str = input("Data końcowa (YYYY-MM-DD, enter = brak): ").strip()

            date_from = parse_date(date_from_str) if date_from_str else None
            date_to = parse_date(date_to_str) if date_to_str else None

            logs = query_logs(date_from=date_from, date_to=date_to)
            agregacje_i_statystyki(logs)

        elif choice == "3":
            date_from_str = input("Data początkowa (YYYY-MM-DD, enter = brak): ").strip()
            date_to_str = input("Data końcowa (YYYY-MM-DD, enter = brak): ").strip()

            date_from = parse_date(date_from_str) if date_from_str else None
            date_to = parse_date(date_to_str) if date_to_str else None

            logs = query_logs(date_from=date_from, date_to=date_to)
            wykrywanie_anomalii(logs)

        elif choice == "4":
            username = input("Eksportuj logi użytkownika (enter = wszystkie): ").strip() or None
            action = input("Eksportuj logi akcji (enter = wszystkie): ").strip() or None
            date_from_str = input("Data początkowa (YYYY-MM-DD, enter = brak): ").strip()
            date_to_str = input("Data końcowa (YYYY-MM-DD, enter = brak): ").strip()

            date_from = parse_date(date_from_str) if date_from_str else None
            date_to = parse_date(date_to_str) if date_to_str else None

            logs = query_logs(username, action, date_from, date_to)
            filename = input("Podaj nazwę pliku CSV [report.csv]: ").strip() or "report.csv"
            export_to_csv(logs, filename)

        elif choice == "0":
            console.print("[bold green]Do zobaczenia![/bold green]")
            break

        else:
            console.print("[red]Nieprawidłowa opcja, spróbuj ponownie.[/red]")

if __name__ == "__main__":

    menu()
