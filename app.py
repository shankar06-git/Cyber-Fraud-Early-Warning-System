import tkinter as tk
from tkinter import messagebox
import socket
import pickle
import difflib
import whois
from datetime import datetime
from urllib.parse import urlparse

from virustotal_checker import check_virustotal

# ==============================
# LOAD MODEL
# ==============================

model = pickle.load(open("model.pkl","rb"))
vectorizer = pickle.load(open("vectorizer.pkl","rb"))

scan_history = []

# ==============================
# HELPER FUNCTIONS
# ==============================

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc.replace("www.","")


def check_dns(domain):
    try:
        socket.gethostbyname(domain)
        return True
    except:
        return False


def check_https(url):
    return url.startswith("https")


def keyword_score(url):

    keywords = ["login","verify","account","update","secure","bank","paypal"]

    count = sum(word in url.lower() for word in keywords)

    return min(count*5,25)


def ml_score(url):

    vector = vectorizer.transform([url])
    probability = model.predict_proba(vector)[0][1]

    return probability * 100


def check_domain_age(url):

    try:
        domain = urlparse(url).netloc
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        if isinstance(creation_date,list):
            creation_date = creation_date[0]

        if creation_date:

            age_days = (datetime.now()-creation_date).days

            if age_days < 30:
                return 25
            elif age_days < 180:
                return 15
            else:
                return 0

        return 15

    except:
        return 20


def typosquatting_risk(domain):

    brands = [
    "amazon","google","facebook","netflix","paypal","microsoft",
    "apple","hdfc","axisbank","icicibank","sbi","flipkart"
    ]

    domain_name = domain.split(".")[0].lower()
    domain_name = domain_name.replace("-","")

    replacements = {"0":"o","1":"l","3":"e","5":"s"}

    for num,char in replacements.items():
        domain_name = domain_name.replace(num,char)

    highest_similarity = 0

    for brand in brands:

        similarity = difflib.SequenceMatcher(None,domain_name,brand).ratio()

        if similarity > highest_similarity:
            highest_similarity = similarity


    if highest_similarity > 0.85 and domain_name not in brands:
        return 70
    elif highest_similarity > 0.65:
        return 40
    return 0


# ==============================
# SECURITY METER
# ==============================

def update_meter(score):

    blocks = int(score/10)

    meter = "█"*blocks + "░"*(10-blocks)

    meter_var.set(f"SAFE  {meter}  DANGER")


# ==============================
# RESET FUNCTION
# ==============================

def reset_scan():

    url_entry.delete(0,tk.END)

    ml_var.set("")
    dns_var.set("")
    https_var.set("")
    keyword_var.set("")
    age_var.set("")
    typo_var.set("")
    vt_var.set("")
    score_var.set("")
    status_var.set("")

    meter_var.set("SAFE ░░░░░░░░░░ DANGER")


# ==============================
# EXPORT REPORT
# ==============================

def export_report():

    if not scan_history:
        messagebox.showwarning("No Data","No scans to export")
        return

    file = open("scan_report.txt","w")

    file.write("Cyber Fraud Detection Report\n")
    file.write("=============================\n\n")

    for item in scan_history:

        file.write(f"URL: {item['url']}\n")
        file.write(f"Risk Score: {item['risk']}%\n")
        file.write(f"Status: {item['status']}\n")
        file.write("-----------------------------\n")

    file.close()

    messagebox.showinfo("Export Complete","Report saved as scan_report.txt")


# ==============================
# UPDATE RESULTS
# ==============================

def update_results(ml,dns,https,keyword,age,typo,vt,score,status):

    ml_var.set(ml)
    dns_var.set(dns)
    https_var.set(https)
    keyword_var.set(keyword)
    age_var.set(age)
    typo_var.set(typo)
    vt_var.set(vt)
    score_var.set(score)
    status_var.set(status)

    score_value = float(score.replace("%",""))

    update_meter(score_value)


# ==============================
# SCAN URL
# ==============================

def scan_url():

    url = url_entry.get().strip()

    if not url:
        messagebox.showwarning("Input Error","Enter a URL")
        return

    if not url.startswith("http"):
        url = "http://" + url

    domain = extract_domain(url)

    vt_flag = check_virustotal(url)
    vt_risk = 40 if vt_flag else 0

    ml_risk = ml_score(url)

    dns_ok = check_dns(domain)
    dns_risk = 0 if dns_ok else 100

    https_ok = check_https(url)
    https_risk = 0 if https_ok else 30

    kw_risk = keyword_score(url)

    age_risk = check_domain_age(url)

    typo_risk = typosquatting_risk(domain)

    final_risk = (

    (ml_risk*0.25)+
    (dns_risk*0.10)+
    (https_risk*0.05)+
    (kw_risk*0.10)+
    (age_risk*0.10)+
    (typo_risk*0.20)+
    (vt_risk*0.20)

    )

    final_risk = min(final_risk,100)

    if final_risk > 70:
        status="HIGH RISK"
    elif final_risk > 40:
        status="MEDIUM RISK"
    else:
        status="LOW RISK"

    update_results(

    f"{round(ml_risk,2)}%",
    "Resolved" if dns_ok else "Not Resolved",
    "Secure" if https_ok else "Not Secure",
    f"{kw_risk}%",
    f"{age_risk}%",
    f"{typo_risk}%",
    "Flagged" if vt_flag else "Clean",
    f"{round(final_risk,2)}%",
    status

    )

    scan_history.append({

    "url":url,
    "risk":round(final_risk,2),
    "status":status

    })

    history_box.insert(tk.END,
    f"{url} | {round(final_risk,2)}% | {status}")


# ==============================
# GUI
# ==============================

root = tk.Tk()
root.title("Cyber Fraud Early Warning System")
root.geometry("760x700")
root.configure(bg="#0f172a")

title = tk.Label(root,
text="CYBER FRAUD EARLY WARNING SYSTEM",
font=("Consolas",20,"bold"),
fg="#22c55e",
bg="#0f172a")

title.pack(pady=10)

meter_var = tk.StringVar()

meter_title = tk.Label(root,
text="AI THREAT LEVEL",
font=("Consolas",14,"bold"),
fg="#38bdf8",
bg="#0f172a")

meter_title.pack()

meter_label = tk.Label(root,
textvariable=meter_var,
font=("Consolas",16,"bold"),
fg="white",
bg="#0f172a")

meter_label.pack(pady=10)

frame = tk.Frame(root,bg="#0f172a")
frame.pack(pady=10)

url_label = tk.Label(frame,
text="Enter URL:",
font=("Consolas",12),
fg="white",
bg="#0f172a")

url_label.grid(row=0,column=0,padx=5)

url_entry = tk.Entry(frame,width=50,font=("Consolas",12))
url_entry.grid(row=0,column=1,padx=5)

scan_btn = tk.Button(root,
text="SCAN URL",
font=("Consolas",12,"bold"),
bg="#22c55e",
fg="black",
width=20,
command=scan_url)

scan_btn.pack(pady=5)

reset_btn = tk.Button(root,
text="RESET / NEXT URL",
font=("Consolas",11,"bold"),
bg="#facc15",
fg="black",
width=20,
command=reset_scan)

reset_btn.pack(pady=5)

export_btn = tk.Button(root,
text="EXPORT REPORT",
font=("Consolas",11,"bold"),
bg="#38bdf8",
fg="black",
width=20,
command=export_report)

export_btn.pack(pady=5)

result_frame = tk.Frame(root,bg="#0f172a")
result_frame.pack(pady=10)

ml_var = tk.StringVar()
dns_var = tk.StringVar()
https_var = tk.StringVar()
keyword_var = tk.StringVar()
age_var = tk.StringVar()
typo_var = tk.StringVar()
vt_var = tk.StringVar()
score_var = tk.StringVar()
status_var = tk.StringVar()

def row(label,var,r):

    tk.Label(result_frame,
    text=label,
    font=("Consolas",11),
    fg="#cbd5f5",
    bg="#0f172a").grid(row=r,column=0,sticky="w")

    tk.Label(result_frame,
    textvariable=var,
    font=("Consolas",11,"bold"),
    fg="white",
    bg="#0f172a").grid(row=r,column=1,sticky="w")

row("ML Detection:",ml_var,0)
row("DNS Status:",dns_var,1)
row("HTTPS Security:",https_var,2)
row("Keyword Risk:",keyword_var,3)
row("Domain Age Risk:",age_var,4)
row("Typosquatting Risk:",typo_var,5)
row("VirusTotal:",vt_var,6)
row("Final Risk Score:",score_var,7)
row("Status:",status_var,8)

history_label = tk.Label(root,
text="Threat Logs",
font=("Consolas",12,"bold"),
fg="#38bdf8",
bg="#0f172a")

history_label.pack(pady=5)

history_box = tk.Listbox(root,
width=90,
height=8,
bg="black",
fg="#22c55e",
font=("Consolas",10))

history_box.pack(pady=5)

root.mainloop()