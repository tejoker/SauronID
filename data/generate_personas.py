"""
generate_personas.py
Generates personas.csv: 1000 synthetic people built from:
  - stats.csv      → net worth bounds per country/generation/tier
  - behavior.csv   → internet expense frequency distribution
  - expenses.csv   → monthly spending allocation per category
  - gender.csv     → male/female ratio per generation

Distribution:
  Nationality : 30% CHN, 30% USA, 10% FR, 10% UK, 10% IRE, 10% SWE
  Wealth tiers: 50% bottom_50, 25% top_25, 15% top_10, 10% top_1
  Generations : 35% gen_z, 38% millennial, 27% boomer (UN DESA proportions)
  Gender      : from gender.csv per generation
"""

import csv
import os
import random
import math
from config import N_PERSONAS, COUNTRY_TO_NATIONALITY, GENERATION_DOB_RANGE

random.seed(42)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
DIR          = os.path.dirname(__file__)
STATS_CSV    = os.path.join(DIR, "stats.csv")
BEHAVIOR_CSV = os.path.join(DIR, "behavior.csv")
EXPENSES_CSV = os.path.join(DIR, "expenses.csv")
GENDER_CSV   = os.path.join(DIR, "gender.csv")
OUTPUT_CSV   = os.path.join(DIR, "personas.csv")

# N_PERSONAS is imported from config.py — change it there

# ---------------------------------------------------------------------------
# Population weights
# ---------------------------------------------------------------------------
COUNTRY_WEIGHTS = {
    "china": 0.30, "usa": 0.30,
    "fr": 0.10, "uk": 0.10, "ire": 0.10, "swe": 0.10,
}
TIER_WEIGHTS = {
    "bottom_50": 0.50, "top_25": 0.25, "top_10": 0.15, "top_1": 0.10,
}
GENERATION_WEIGHTS = {
    "gen_z": 0.35, "millennial": 0.38, "boomer": 0.27,
}

# ---------------------------------------------------------------------------
# Country → stats.csv label mapping
# ---------------------------------------------------------------------------
COUNTRY_LABEL = {
    "usa":   "USA (USD)",
    "uk":    "UK (GBP)",
    "fr":    "FR (EUR)",
    "ire":   "IRE (EUR)",
    "swe":   "SWE (SEK)",
    "china": "CHN (RMB)",
}
GENERATION_LABEL = {
    "gen_z":      {"usa": "Gen Z (18", "uk": "Gen Z (16", "fr": "Gen Z (<", "ire": "Gen Z /", "swe": "Gen Z (18", "china": "Urban Gen"},
    "millennial": {"usa": "Millennia", "uk": "Millennia", "fr": "Millennia", "ire": "Millennia", "swe": "Millennia", "china": "Urban Mil"},
    "boomer":     {"usa": "Baby Boom", "uk": "Baby Boom", "fr": "Baby Boom", "ire": "Baby Boom", "swe": "Baby Boom", "china": "Urban Bab"},
}

# ---------------------------------------------------------------------------
# Name pools per country (first, last)
# ---------------------------------------------------------------------------
NAMES = {
    "usa": {
        "male":   ["James","John","Robert","Michael","William","David","Richard","Joseph","Thomas","Charles",
                   "Christopher","Daniel","Matthew","Anthony","Donald","Mark","Paul","Steven","Andrew","Kenneth"],
        "female": ["Mary","Patricia","Jennifer","Linda","Barbara","Elizabeth","Susan","Jessica","Sarah","Karen",
                   "Lisa","Nancy","Betty","Margaret","Sandra","Ashley","Dorothy","Kimberly","Emily","Donna"],
        "last":   ["Smith","Johnson","Williams","Brown","Jones","Garcia","Miller","Davis","Martinez","Wilson",
                   "Anderson","Taylor","Thomas","Hernandez","Moore","Martin","Jackson","Thompson","White","Lopez"],
    },
    "china": {
        "male":   ["Wei","Fang","Yang","Lei","Jian","Hao","Ming","Tao","Jun","Peng",
                   "Bo","Cheng","Gang","Hui","Long","Qiang","Rui","Xin","Yi","Zhen"],
        "female": ["Fang","Li","Na","Ting","Xia","Yan","Ying","Yu","Zhen","Jing",
                   "Lan","Mei","Qian","Rong","Shan","Shu","Xue","Yun","Zhi","Hui"],
        "last":   ["Wang","Li","Zhang","Liu","Chen","Yang","Huang","Zhao","Wu","Zhou",
                   "Xu","Sun","Ma","Zhu","Hu","Guo","He","Lin","Gao","Luo"],
    },
    "fr": {
        "male":   ["Pierre","Jean","Paul","Michel","Jacques","Andre","Philippe","Louis","Henri","Francois",
                   "Nicolas","Antoine","Julien","Thomas","Alexandre","Maxime","Baptiste","Romain","Hugo","Clement"],
        "female": ["Marie","Jeanne","Marguerite","Helene","Camille","Sophie","Isabelle","Celine","Aurelie","Lucie",
                   "Lea","Manon","Emma","Clara","Julie","Laura","Marine","Pauline","Amelie","Charlotte"],
        "last":   ["Martin","Bernard","Dubois","Thomas","Robert","Richard","Petit","Durand","Leroy","Moreau",
                   "Simon","Laurent","Lefebvre","Michel","Garcia","David","Bertrand","Roux","Vincent","Fournier"],
    },
    "uk": {
        "male":   ["Oliver","George","Harry","Jack","Charlie","Noah","Jacob","Oscar","Leo","Alfie",
                   "James","William","Henry","Freddie","Archie","Thomas","Ethan","Liam","Sebastian","Lucas"],
        "female": ["Amelia","Olivia","Isla","Emily","Poppy","Ava","Isabella","Jessica","Lily","Sophie",
                   "Grace","Freya","Evie","Mia","Ruby","Ella","Scarlett","Daisy","Lola","Chloe"],
        "last":   ["Smith","Jones","Williams","Taylor","Brown","Davies","Evans","Wilson","Thomas","Roberts",
                   "Johnson","Lewis","Walker","Robinson","Wood","Thompson","White","Watson","Jackson","Harris"],
    },
    "ire": {
        "male":   ["Liam","Sean","Conor","Patrick","Brendan","Cian","Finn","Darragh","Eoin","Cormac",
                   "Oisin","Ronan","Ciaran","Niall","Declan","Aidan","Shane","Kieran","Kevin","Brian"],
        "female": ["Aoife","Ciara","Niamh","Saoirse","Sinead","Orla","Aisling","Roisin","Caoimhe","Clodagh",
                   "Maeve","Siobhan","Deirdre","Grainne","Fiona","Eimear","Sorcha","Ailbhe","Riona","Muireann"],
        "last":   ["Murphy","Kelly","O'Sullivan","Walsh","Smith","O'Brien","Byrne","Ryan","O'Connor","O'Neill",
                   "O'Reilly","Doyle","McCarthy","Gallagher","Kennedy","Lynch","Murray","Quinn","Moore","McLoughlin"],
    },
    "swe": {
        "male":   ["Erik","Lars","Karl","Anders","Johan","Per","Nils","Gunnar","Bjorn","Sven",
                   "Mikael","Henrik","Mattias","Patrik","Jonas","Marcus","Oskar","Viktor","Anton","Filip"],
        "female": ["Anna","Maria","Kristina","Karin","Eva","Elisabeth","Ingrid","Sara","Emma","Johanna",
                   "Linnea","Maja","Lina","Klara","Hanna","Ida","Wilma","Alice","Ebba","Agnes"],
        "last":   ["Andersson","Johansson","Karlsson","Nilsson","Eriksson","Larsson","Olsson","Persson","Svensson","Gustafsson",
                   "Pettersson","Jonsson","Jansson","Hansson","Bengtsson","Lindstrom","Jakobsson","Magnusson","Lindberg","Lindqvist"],
    },
}

# Street components per country for fake addresses
STREETS = {
    "usa":   (["Main St","Oak Ave","Maple Dr","Cedar Ln","Elm St","Pine Rd","Park Ave","Lake Dr","Hill St","River Rd"],
              ["New York","Los Angeles","Chicago","Houston","Phoenix","Philadelphia","San Antonio","San Diego","Dallas","San Jose"]),
    "china": (["Nanjing Rd","Wangfujing St","Renmin Rd","Zhongshan Ave","Huaihai Rd","Changan Ave","Jiefang Rd","Dongfeng Rd","Xinhua St","Guanghua Rd"],
              ["Shanghai","Beijing","Shenzhen","Guangzhou","Chengdu","Hangzhou","Wuhan","Xi'an","Suzhou","Nanjing"]),
    "fr":    (["Rue de la Paix","Avenue Foch","Rue Saint-Honore","Boulevard Haussmann","Rue de Rivoli","Avenue Montaigne","Rue du Bac","Rue de Passy","Rue Nationale","Boulevard Saint-Germain"],
              ["Paris","Lyon","Marseille","Toulouse","Nice","Nantes","Strasbourg","Montpellier","Bordeaux","Lille"]),
    "uk":    (["High St","Church Rd","Victoria Rd","Green Lane","Manor Rd","Park Rd","Station Rd","Kings Rd","Queens Ave","Mill Lane"],
              ["London","Manchester","Birmingham","Leeds","Glasgow","Liverpool","Bristol","Sheffield","Edinburgh","Leicester"]),
    "ire":   (["O'Connell St","Grafton St","Dame St","Nassau St","Baggot St","Merrion Sq","Fitzwilliam Sq","South Circular Rd","North Circular Rd","Clontarf Rd"],
              ["Dublin","Cork","Galway","Limerick","Waterford","Drogheda","Dundalk","Swords","Bray","Kilkenny"]),
    "swe":   (["Storgatan","Kungsgatan","Drottninggatan","Vasagatan","Hornsgatan","Gotgatan","Sveavagen","Birger Jarlsgatan","Odengatan","Karlavagen"],
              ["Stockholm","Gothenburg","Malmo","Uppsala","Vasteras","Orebro","Linkoping","Helsingborg","Jonkoping","Norrkoping"]),
}

COUNTRY_DOMAIN = {
    "usa": "us", "china": "cn", "fr": "fr", "uk": "uk", "ire": "ie", "swe": "se",
}

# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_stats() -> dict:
    """Returns {(country_label, gen_prefix): {median, top25, top10, top1}} in USD."""
    data = {}
    with open(STATS_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["country_currency"].strip(), row["generation_bracket"].strip()[:9])
            data[key] = {
                "median": float(row["median_net_worth_usd"] or 0),
                "top25":  float(row["top25_threshold_usd"] or 0),
                "top10":  float(row["top10_threshold_usd"] or 0),
                "top1":   float(row["top1_threshold_usd"] or 0),
            }
    return data


def load_behavior() -> dict:
    """Returns {(country, wealth_tier, generation): row_dict}."""
    data = {}
    with open(BEHAVIOR_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["country"], row["wealth_tier"], row["generation"])
            data[key] = row
    return data


def load_expenses() -> dict:
    """Returns {(country, wealth_tier, generation): row_dict}."""
    data = {}
    with open(EXPENSES_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = (row["country"], row["wealth_tier"], row["generation"])
            data[key] = row
    return data


def load_gender() -> dict:
    """Returns {generation: (male_pct, female_pct)}."""
    data = {}
    with open(GENDER_CSV, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gen = row["generation"]
            # Normalise gender.csv generation labels to our keys
            if "gen_z" in gen:     key = "gen_z"
            elif "millennial" in gen: key = "millennial"
            elif "boomer" in gen:  key = "boomer"
            else:                  key = gen
            data[key] = (float(row["global_male_pct"]), float(row["global_female_pct"]))
    return data

# ---------------------------------------------------------------------------
# Sampling helpers
# ---------------------------------------------------------------------------

def weighted_choice(weights: dict) -> str:
    keys = list(weights.keys())
    vals = list(weights.values())
    return random.choices(keys, weights=vals, k=1)[0]


def sample_net_worth(tier: str, stats_row: dict) -> float:
    """Sample a net worth value within the tier's range."""
    if tier == "bottom_50":
        lo, hi = 0, stats_row["top25"]
    elif tier == "top_25":
        lo, hi = stats_row["top25"], stats_row["top10"]
    elif tier == "top_10":
        lo, hi = stats_row["top10"], stats_row["top1"]
    else:  # top_1
        lo, hi = stats_row["top1"], stats_row["top1"] * 3.0
    return round(random.uniform(lo, hi), 2)


def sample_frequency(brow: dict) -> str:
    cats  = ["once", "sometimes", "often", "always"]
    probs = [float(brow[f"p_{c}"]) for c in cats]
    return random.choices(cats, weights=probs, k=1)[0]


def sample_internet_spend(brow: dict) -> float:
    lo  = float(brow["monthly_spend_low_usd"])
    mid = float(brow["monthly_spend_mid_usd"])
    hi  = float(brow["monthly_spend_high_usd"])
    # Triangular distribution between lo and hi, mode at mid
    return round(random.triangular(lo, hi, mid), 2)


def sample_expense_pcts(erow: dict) -> dict:
    cats   = ["food_living", "tech", "lifestyle", "travel", "investment"]
    means  = [float(erow[f"{c}_mean_pct"]) for c in cats]
    stds   = [float(erow[f"{c}_std_pct"])  for c in cats]
    # Sample from truncated normal via rejection (max 20 tries, then use mean)
    sampled = []
    for m, s in zip(means, stds):
        if s == 0:
            sampled.append(m)
            continue
        for _ in range(20):
            v = random.gauss(m, s)
            if v >= 0:
                sampled.append(v)
                break
        else:
            sampled.append(m)
    total = sum(sampled)
    pcts  = {c: round(v * 100.0 / total, 2) for c, v in zip(cats, sampled)}
    # Fix rounding
    diff = round(100.0 - sum(pcts.values()), 2)
    pcts["food_living"] = round(pcts["food_living"] + diff, 2)
    return pcts


def make_address(country: str) -> str:
    streets, cities = STREETS[country]
    number  = random.randint(1, 200)
    street  = random.choice(streets)
    city    = random.choice(cities)
    return f"{number} {street}, {city}"


def make_email(first: str, last: str, country: str) -> str:
    first_clean = first.lower().replace("'", "").replace(" ", "")
    last_clean  = last.lower().replace("'", "").replace(" ", "")
    domain      = COUNTRY_DOMAIN[country]
    suffix      = random.randint(1, 999)
    return f"{first_clean}.{last_clean}{suffix}.{domain}@gmail.com"


def get_stats_row(country: str, generation: str, stats: dict) -> dict:
    label    = COUNTRY_LABEL[country]
    gen_pfx  = GENERATION_LABEL[generation][country]
    # Match by prefix
    for (clabel, gpfx), row in stats.items():
        if clabel == label and gpfx.startswith(gen_pfx[:7]):
            return row
    # Fallback: any row matching country label
    for (clabel, _), row in stats.items():
        if clabel == label:
            return row
    raise KeyError(f"No stats row for {country} / {generation}")

# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------
INCOME_FACTOR = {
    "bottom_50":  10,
    "top_25":     25,
    "top_10":     80,
    "top_1":     200,
}

FIELDNAMES = [
    "id", "first_name", "last_name", "gender",
    "email", "address", "country", "nationality", "generation",
    "date_of_birth",
    "wealth_tier", "net_worth_usd", "monthly_income_usd",
    "internet_frequency",
    "monthly_internet_spend_usd",
    "food_living_pct", "tech_pct", "lifestyle_pct", "travel_pct", "investment_pct",
    "food_living_usd", "tech_usd", "lifestyle_usd", "travel_usd", "investment_usd",
]


def generate():
    stats_data    = load_stats()
    behavior_data = load_behavior()
    expenses_data = load_expenses()
    gender_data   = load_gender()

    personas = []

    for i in range(1, N_PERSONAS + 1):
        country    = weighted_choice(COUNTRY_WEIGHTS)
        tier       = weighted_choice(TIER_WEIGHTS)
        generation = weighted_choice(GENERATION_WEIGHTS)

        # Gender
        male_pct, female_pct = gender_data.get(generation, (50.0, 50.0))
        gender = random.choices(["male", "female"], weights=[male_pct, female_pct], k=1)[0]

        # Name
        pool      = NAMES[country]
        first     = random.choice(pool[gender])
        last      = random.choice(pool["last"])

        # Nationality (ISO alpha-2)
        nationality = COUNTRY_TO_NATIONALITY[country]

        # Date of birth (from generation range)
        dob_lo, dob_hi = GENERATION_DOB_RANGE[generation]
        dob_year  = random.randint(dob_lo, dob_hi)
        dob_month = random.randint(1, 12)
        dob_day   = random.randint(1, 28)   # safe range for all months
        date_of_birth = f"{dob_year:04d}-{dob_month:02d}-{dob_day:02d}"

        # Net worth
        stats_row  = get_stats_row(country, generation, stats_data)
        net_worth  = sample_net_worth(tier, stats_row)
        monthly_income = round(net_worth / INCOME_FACTOR[tier], 2)

        # Internet behavior
        bkey = (country, tier, generation)
        brow = behavior_data.get(bkey, behavior_data.get((country, tier, "millennial")))
        frequency       = sample_frequency(brow)
        internet_spend  = sample_internet_spend(brow)

        # Expense allocation
        ekey = (country, tier, generation)
        erow = expenses_data.get(ekey, expenses_data.get((country, tier, "millennial")))
        pcts = sample_expense_pcts(erow)
        cats = ["food_living", "tech", "lifestyle", "travel", "investment"]
        usd  = {c: round(monthly_income * pcts[c] / 100.0, 2) for c in cats}

        personas.append({
            "id":                       i,
            "first_name":               first,
            "last_name":                last,
            "gender":                   gender,
            "email":                    make_email(first, last, country),
            "address":                  make_address(country),
            "country":                  country,
            "nationality":              nationality,
            "generation":               generation,
            "date_of_birth":            date_of_birth,
            "wealth_tier":              tier,
            "net_worth_usd":            net_worth,
            "monthly_income_usd":       monthly_income,
            "internet_frequency":       frequency,
            "monthly_internet_spend_usd": internet_spend,
            "food_living_pct":          pcts["food_living"],
            "tech_pct":                 pcts["tech"],
            "lifestyle_pct":            pcts["lifestyle"],
            "travel_pct":               pcts["travel"],
            "investment_pct":           pcts["investment"],
            "food_living_usd":          usd["food_living"],
            "tech_usd":                 usd["tech"],
            "lifestyle_usd":            usd["lifestyle"],
            "travel_usd":               usd["travel"],
            "investment_usd":           usd["investment"],
        })

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(personas)

    # Summary
    print(f"Generated {len(personas)} personas → {OUTPUT_CSV}")
    # Also write users.csv as an alias for downstream consumers
    import shutil
    users_csv = os.path.join(DIR, "users.csv")
    shutil.copy2(OUTPUT_CSV, users_csv)
    print(f"Copied → {users_csv}")
    print()
    from collections import Counter
    countries   = Counter(p["country"]    for p in personas)
    tiers       = Counter(p["wealth_tier"] for p in personas)
    generations = Counter(p["generation"] for p in personas)
    freqs       = Counter(p["internet_frequency"] for p in personas)
    print("Country distribution:")
    for k, v in sorted(countries.items()):
        print(f"  {k:8s}: {v:4d}  ({100*v/N_PERSONAS:.1f}%)")
    print("Wealth tier distribution:")
    for k, v in sorted(tiers.items()):
        print(f"  {k:12s}: {v:4d}  ({100*v/N_PERSONAS:.1f}%)")
    print("Generation distribution:")
    for k, v in sorted(generations.items()):
        print(f"  {k:12s}: {v:4d}  ({100*v/N_PERSONAS:.1f}%)")
    print("Internet frequency distribution:")
    for k, v in sorted(freqs.items()):
        print(f"  {k:10s}: {v:4d}  ({100*v/N_PERSONAS:.1f}%)")


if __name__ == "__main__":
    generate()
