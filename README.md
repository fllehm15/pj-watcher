# PJ Portal Watcher – GitHub Actions

Diese Version ist für einen öffentlichen GitHub-Repository gedacht und läuft
mit GitHub Actions ohne eigenen PC.

## Sicherheit

Im Repository stehen keine Zugangsdaten und kein Zielkrankenhaus.
Die sensiblen Werte werden ausschließlich als GitHub Actions Secrets hinterlegt.

Benötigte Secrets:

- `PJ_EMAIL`
- `PJ_PASSWORD`
- `TARGET_HOSPITAL_TERMS`
- `TARGET_SUBJECT_TERMS`
- `SMTP_USER`
- `SMTP_APP_PASSWORD`
- `EMAIL_TO`

Für Halle BG / Innere Medizin:

`TARGET_HOSPITAL_TERMS`
```
Halle BG|BG Halle|BG Klinikum Halle|Bergmannstrost
```

`TARGET_SUBJECT_TERMS`
```
Innere Medizin
```

Der manuelle GitHub-Actions-Start (`Run workflow`) ist ein Testmodus:
Er prüft Login, Merkliste, Ziel und Verfügbarkeit und sendet anschließend
immer eine E-Mail mit dem Betreff `PJ-Watcher TEST: läuft`.

Geplante Läufe finden ungefähr alle 5 Minuten statt. GitHub garantiert keine
sekundengenaue Ausführung; geplante Läufe können verzögert werden.

Der Watcher bucht NICHT.

Enddatum:
24.11.2026 23:59 Uhr (Europe/Berlin). Danach greift er nicht mehr auf das
PJ-Portal zu und versucht, den eigenen Workflow automatisch zu deaktivieren.
