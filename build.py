"""Aamukatsaus
Hakee uudet sanktiomerkinnät (OpenSanctions) ja CISA:n KEV-lisäykset
ja tekee niistä yhden nettisivun kansioon site/.
"""

import csv
import io
import json
import urllib.request
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

# ---------- ASETUKSET: muokkaa näitä ----------
PAIVIA = 14               # kuinka monta päivää taaksepäin katsotaan
KEV_AVAINSANAT = []       # esim. ["Fortinet", "Microsoft"]. Tyhjä = kaikki
SANKTIO_MAAT = []         # maakoodit pienellä, esim. ["ru", "by", "ir"]. Tyhjä = kaikki
SANKTIO_AVAINSANAT = []   # sanoja nimestä tai ohjelmasta. Tyhjä = kaikki
MAX_SANKTIOT = 200        # ettei sivusta tule liian pitkä
# ----------------------------------------------

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
SANKTIO_URL = (
    "https://data.opensanctions.org/datasets/latest/sanctions/targets.simple.csv"
)

TYYPIT = {
    "Person": "Henkilö",
    "Company": "Yritys",
    "Organization": "Organisaatio",
    "LegalEntity": "Oikeushenkilö",
    "Vessel": "Alus",
    "Airplane": "Ilma-alus",
}


def lataa(url):
    """Lataa tiedoston netistä ja palauttaa sen sisällön."""
    pyynto = urllib.request.Request(
        url, headers={"User-Agent": "aamukatsaus-harrasteprojekti"}
    )
    with urllib.request.urlopen(pyynto, timeout=180) as vastaus:
        return vastaus.read()


def osuu(teksti, avainsanat):
    """Tosi, jos avainsanalista on tyhjä tai jokin sana löytyy tekstistä."""
    if not avainsanat:
        return True
    teksti = teksti.lower()
    return any(sana.lower() in teksti for sana in avainsanat)


def hae_kev(raja):
    data = json.loads(lataa(KEV_URL))
    tulokset = []
    for v in data["vulnerabilities"]:
        if v.get("dateAdded", "") < raja:
            continue
        haettava = " ".join(
            [
                v.get("vendorProject", ""),
                v.get("product", ""),
                v.get("vulnerabilityName", ""),
                v.get("shortDescription", ""),
            ]
        )
        if osuu(haettava, KEV_AVAINSANAT):
            tulokset.append(v)
    tulokset.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return tulokset


def hae_sanktiot(raja):
    teksti = lataa(SANKTIO_URL).decode("utf-8")
    halutut_maat = {m.lower() for m in SANKTIO_MAAT}
    tulokset = []
    for rivi in csv.DictReader(io.StringIO(teksti)):
        if rivi.get("first_seen", "")[:10] < raja:
            continue
        maat = {m.strip().lower() for m in rivi.get("countries", "").split(";")}
        if halutut_maat and not (maat & halutut_maat):
            continue
        haettava = " ".join(
            [rivi.get("name", ""), rivi.get("aliases", ""), rivi.get("program_ids", "")]
        )
        if osuu(haettava, SANKTIO_AVAINSANAT):
            tulokset.append(rivi)
    tulokset.sort(key=lambda r: r.get("first_seen", ""), reverse=True)
    return tulokset


def kev_html(rivit):
    if not rivit:
        return "<p>Ei uusia merkintöjä valitulla aikavälillä.</p>"
    osat = [
        "<div class='vieritys'><table>",
        "<tr><th>Lisätty</th><th>CVE</th><th>Tuote</th><th>Kuvaus</th>"
        "<th>CISA:n määräaika</th><th>Kiristyshaittaohjelma</th></tr>",
    ]
    for v in rivit:
        cve = escape(v.get("cveID", ""))
        if v.get("knownRansomwareCampaignUse") == "Known":
            kiristys = "<span class='kiristys'>Kyllä</span>"
        else:
            kiristys = "Ei tiedossa"
        osat.append(
            "<tr>"
            f"<td>{escape(v.get('dateAdded', ''))}</td>"
            f"<td><a href='https://nvd.nist.gov/vuln/detail/{cve}'>{cve}</a></td>"
            f"<td>{escape(v.get('vendorProject', ''))} {escape(v.get('product', ''))}</td>"
            f"<td>{escape(v.get('shortDescription', ''))}</td>"
            f"<td>{escape(v.get('dueDate', ''))}</td>"
            f"<td>{kiristys}</td>"
            "</tr>"
        )
    osat.append("</table></div>")
    return "".join(osat)


def sanktio_html(rivit):
    if not rivit:
        return "<p>Ei uusia merkintöjä valitulla aikavälillä.</p>"
    osat = [
        "<div class='vieritys'><table>",
        "<tr><th>Nähty ensi kerran</th><th>Nimi</th><th>Tyyppi</th>"
        "<th>Maat</th><th>Ohjelmat</th><th>Listat</th></tr>",
    ]
    for r in rivit[:MAX_SANKTIOT]:
        tunnus = escape(r.get("id", ""))
        nimi = escape(r.get("name", ""))
        tyyppi = TYYPIT.get(r.get("schema", ""), r.get("schema", ""))
        osat.append(
            "<tr>"
            f"<td>{escape(r.get('first_seen', '')[:10])}</td>"
            f"<td><a href='https://www.opensanctions.org/entities/{tunnus}/'>{nimi}</a></td>"
            f"<td>{escape(tyyppi)}</td>"
            f"<td>{escape(r.get('countries', '').upper())}</td>"
            f"<td>{escape(r.get('program_ids', ''))}</td>"
            f"<td>{escape(r.get('dataset', ''))}</td>"
            "</tr>"
        )
    osat.append("</table></div>")
    if len(rivit) > MAX_SANKTIOT:
        osat.append(f"<p>Näytetään {MAX_SANKTIOT} uusinta, yhteensä {len(rivit)} osumaa.</p>")
    return "".join(osat)


SIVUPOHJA = """<!doctype html>
<html lang="fi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aamukatsaus</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1000px; margin: 0 auto;
         padding: 1rem; line-height: 1.5; color: #1a1a1a; background: #fafafa; }
  h1 { margin-bottom: 0; }
  .paivitetty { color: #666; margin-top: 0.25rem; }
  .vieritys { overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0 2rem;
          font-size: 0.9rem; background: #fff; }
  th, td { text-align: left; padding: 0.5rem; border-bottom: 1px solid #ddd;
           vertical-align: top; }
  th { background: #eee; }
  .kiristys { color: #b00020; font-weight: 600; }
  footer { color: #666; font-size: 0.85rem; margin: 2rem 0; }
</style>
</head>
<body>
<h1>Aamukatsaus</h1>
<p class="paivitetty">Päivitetty __PAIVITETTY__. Katsotaan __PAIVIA__ päivää taaksepäin.</p>

<h2>Uudet sanktiomerkinnät (__SANKTIOT_MAARA__)</h2>
__SANKTIOT__

<h2>Uudet CISA KEV -haavoittuvuudet (__KEV_MAARA__)</h2>
__KEV__

<footer>
Lähteet: OpenSanctions (opensanctions.org, ei-kaupallinen käyttö) ja
CISA Known Exploited Vulnerabilities -katalogi. Harrasteprojekti, ei
virallinen seulontatyökalu.
</footer>
</body>
</html>
"""


def main():
    nyt = datetime.now(timezone.utc)
    raja = (nyt - timedelta(days=PAIVIA)).strftime("%Y-%m-%d")

    kev = hae_kev(raja)
    sanktiot = hae_sanktiot(raja)
    print(f"KEV: {len(kev)} uutta, sanktiot: {len(sanktiot)} uutta")

    sivu = (
        SIVUPOHJA.replace("__PAIVITETTY__", nyt.strftime("%d.%m.%Y klo %H:%M UTC"))
        .replace("__PAIVIA__", str(PAIVIA))
        .replace("__SANKTIOT_MAARA__", str(len(sanktiot)))
        .replace("__SANKTIOT__", sanktio_html(sanktiot))
        .replace("__KEV_MAARA__", str(len(kev)))
        .replace("__KEV__", kev_html(kev))
    )

    Path("site").mkdir(exist_ok=True)
    Path("site/index.html").write_text(sivu, encoding="utf-8")
    Path("yhteenveto.txt").write_text(
        f"Sanktiot: {len(sanktiot)} uutta. KEV: {len(kev)} uutta.", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
