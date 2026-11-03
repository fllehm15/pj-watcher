#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PJ-Portal Watcher for GitHub Actions (READ ONLY)

- Logs into the PJ portal.
- Opens the "Merkliste".
- Reads only the configured hospital/subject and the 3rd tertial.
- Sends email if a free place is detected.
- Never books, reserves, removes, or changes anything.

Sensitive configuration is provided via GitHub Actions secrets.
"""

from __future__ import annotations

import json
import os
import re
import smtplib
import ssl
import sys
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from zoneinfo import ZoneInfo

from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

STATE_FILE = Path("state.json")
EXPIRED_FILE = Path(".watcher_expired")

PORTAL_URL = os.environ.get("PJ_PORTAL_URL", "https://www2.pj-portal.de/index_lei.php").strip()
PJ_EMAIL = os.environ.get("PJ_EMAIL", "").strip()
PJ_PASSWORD = os.environ.get("PJ_PASSWORD", "")

TARGET_HOSPITAL_TERMS = [
    x.strip().lower()
    for x in os.environ.get("TARGET_HOSPITAL_TERMS", "").split("|")
    if x.strip()
]
TARGET_SUBJECT_TERMS = [
    x.strip().lower()
    for x in os.environ.get("TARGET_SUBJECT_TERMS", "").split("|")
    if x.strip()
]

SMTP_USER = os.environ.get("SMTP_USER", "").strip()
SMTP_APP_PASSWORD = os.environ.get("SMTP_APP_PASSWORD", "")
EMAIL_TO = os.environ.get("EMAIL_TO", "").strip()

TEST_MODE = os.environ.get("TEST_MODE", "false").lower() in {"1", "true", "yes"}
END_AT = os.environ.get("END_AT", "2026-11-24T23:59:00+01:00").strip()

PAGE_TIMEOUT_MS = 60_000


def log(msg: str) -> None:
    """Keep public Actions logs generic: don't print target/user/page contents."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"[{stamp}] {msg}", flush=True)


def require_config() -> None:
    required = {
        "PJ_EMAIL": PJ_EMAIL,
        "PJ_PASSWORD": PJ_PASSWORD,
        "TARGET_HOSPITAL_TERMS": "|".join(TARGET_HOSPITAL_TERMS),
        "TARGET_SUBJECT_TERMS": "|".join(TARGET_SUBJECT_TERMS),
        "SMTP_USER": SMTP_USER,
        "SMTP_APP_PASSWORD": SMTP_APP_PASSWORD,
        "EMAIL_TO": EMAIL_TO,
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        raise RuntimeError("Missing required configuration: " + ", ".join(missing))


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"last_status": None, "expired_notified": False}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def parse_end_at() -> datetime:
    dt = datetime.fromisoformat(END_AT)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=ZoneInfo("Europe/Berlin"))
    return dt


def is_expired() -> bool:
    return datetime.now(timezone.utc) >= parse_end_at().astimezone(timezone.utc)


def send_email(subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_USER
    msg["To"] = EMAIL_TO
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=30) as smtp:
        smtp.login(SMTP_USER, SMTP_APP_PASSWORD)
        smtp.send_message(msg)

    log("Email sent successfully.")


def page_has_security_challenge(page) -> bool:
    try:
        text = (page.locator("body").inner_text(timeout=5000) or "").lower()
    except Exception:
        return False

    phrases = (
        "captcha",
        "ich bin kein roboter",
        "i am not a robot",
        "access denied",
        "zugriff verweigert",
        "too many requests",
        "zu viele anfragen",
        "sicherheitsabfrage",
    )
    return any(p in text for p in phrases)


def first_visible(locator):
    try:
        for i in range(locator.count()):
            item = locator.nth(i)
            if item.is_visible():
                return item
    except Exception:
        pass
    return None


def has_visible_password(page) -> bool:
    return first_visible(page.locator('input[type="password"]')) is not None


def login(page) -> None:
    page.goto(PORTAL_URL, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)

    if page_has_security_challenge(page):
        raise RuntimeError("Security challenge detected; watcher stopped without bypassing it.")

    if not has_visible_password(page):
        # Could already be authenticated, but GitHub runs are normally fresh.
        log("Login form not visible; continuing with current session.")
        return

    password = first_visible(page.locator('input[type="password"]'))

    username = first_visible(page.locator('input[type="email"]'))
    if username is None:
        username = first_visible(page.locator('input[name*="mail" i]'))
    if username is None:
        username = first_visible(page.locator('input[name*="login" i]'))
    if username is None:
        # Safe fallback on the login page: first visible text input.
        username = first_visible(page.locator('input[type="text"]'))

    if username is None or password is None:
        raise RuntimeError("Login fields could not be located.")

    username.fill(PJ_EMAIL)
    password.fill(PJ_PASSWORD)

    submit = first_visible(page.get_by_role("button", name=re.compile(r"anmelden|login", re.I)))
    if submit is None:
        submit = first_visible(page.locator('input[type="submit"]'))

    if submit is None:
        raise RuntimeError("Login button could not be located.")

    submit.click()

    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        page.wait_for_timeout(2500)

    if page_has_security_challenge(page):
        raise RuntimeError("Security challenge appeared after login; no bypass attempted.")

    if has_visible_password(page):
        raise RuntimeError("Login was not accepted. Check PJ credentials.")

    log("PJ portal login successful.")


def open_merkliste(page) -> None:
    # Prefer an actual link.
    item = first_visible(page.get_by_role("link", name=re.compile(r"merkliste", re.I)))
    if item is None:
        item = first_visible(page.get_by_role("button", name=re.compile(r"merkliste", re.I)))
    if item is None:
        item = first_visible(page.get_by_text(re.compile(r"^\s*merkliste\s*$", re.I)))

    if item is None:
        raise RuntimeError("Merkliste navigation could not be located.")

    item.click()

    try:
        page.wait_for_load_state("networkidle", timeout=15_000)
    except Exception:
        page.wait_for_timeout(2500)

    if page_has_security_challenge(page):
        raise RuntimeError("Security challenge appeared on Merkliste; no bypass attempted.")

    log("Merkliste opened.")


def extract_target_third_tertial(page) -> dict:
    """
    Find the target hospital inside the target subject section and extract the
    cell under '3. Tertial'. No click or other mutation is performed.
    """
    result = page.evaluate(
        """({hospitalTerms, subjectTerms}) => {
            const norm = s => (s || "").replace(/\\s+/g, " ").trim();
            const low = s => norm(s).toLowerCase();
            const visible = el => {
                const st = window.getComputedStyle(el);
                const r = el.getBoundingClientRect();
                return st.display !== "none" &&
                       st.visibility !== "hidden" &&
                       r.width > 0 && r.height > 0;
            };

            const tables = Array.from(document.querySelectorAll("table")).filter(visible);

            for (const table of tables) {
                const rows = Array.from(table.querySelectorAll("tr")).filter(visible);
                if (!rows.length) continue;

                const tableText = low(table.innerText || table.textContent || "");
                if (!hospitalTerms.some(x => tableText.includes(x))) continue;
                if (!subjectTerms.some(x => tableText.includes(x))) continue;

                let thirdIndex = -1;

                // Header index: blank/name column + 1st/2nd/3rd tertial columns.
                for (const tr of rows.slice(0, 8)) {
                    const cells = Array.from(tr.querySelectorAll(":scope > th, :scope > td"));
                    for (let i = 0; i < cells.length; i++) {
                        if (low(cells[i].innerText || cells[i].textContent || "").includes("3. tertial")) {
                            thirdIndex = i;
                            break;
                        }
                    }
                    if (thirdIndex >= 0) break;
                }

                let inTargetSubject = false;

                for (const tr of rows) {
                    const cells = Array.from(tr.querySelectorAll(":scope > th, :scope > td"));
                    if (!cells.length) continue;

                    const cellTexts = cells.map(td => norm(td.innerText || td.textContent || ""));
                    const rowText = low(cellTexts.join(" | "));
                    const firstCell = low(cellTexts[0] || "");

                    // A subject heading row usually consists mostly of its subject name.
                    const subjectHit = subjectTerms.some(x => firstCell.includes(x) || rowText === x);
                    if (subjectHit) {
                        inTargetSubject = true;
                        continue;
                    }

                    // If another apparent section heading begins, leave target section.
                    if (inTargetSubject && cells.length <= 2 && firstCell && !hospitalTerms.some(x => firstCell.includes(x))) {
                        const looksLikeHeading =
                            firstCell.includes("medizin") ||
                            firstCell.includes("chirurgie") ||
                            firstCell.includes("heilkunde") ||
                            firstCell.includes("psychiatr") ||
                            firstCell.includes("pädiatr") ||
                            firstCell.includes("paediatr");
                        if (looksLikeHeading && !subjectTerms.some(x => firstCell.includes(x))) {
                            inTargetSubject = false;
                        }
                    }

                    if (!inTargetSubject) continue;
                    if (!hospitalTerms.some(x => rowText.includes(x))) continue;

                    let idx = thirdIndex;
                    // Normal Merkliste hospital rows have name + 3 tertial cells.
                    if (idx < 0 && cells.length >= 4) idx = 3;

                    if (idx < 0 || idx >= cellTexts.length) {
                        return {found: true, error: "Third tertial column could not be mapped."};
                    }

                    return {
                        found: true,
                        cell: cellTexts[idx],
                    };
                }
            }

            return {found: false};
        }""",
        {
            "hospitalTerms": TARGET_HOSPITAL_TERMS,
            "subjectTerms": TARGET_SUBJECT_TERMS,
        },
    )

    if not result.get("found"):
        raise RuntimeError(
            "Target entry was not found in the Merkliste. "
            "Make sure the desired hospital/subject is already on your PJ-Portal Merkliste."
        )

    if result.get("error"):
        raise RuntimeError(result["error"])

    return result


def classify(cell: str) -> dict:
    text = re.sub(r"\s+", " ", cell or "").strip()

    # Official PJ-Portal Merkliste format: frei/Angebot, e.g. 0/3 or 1/3.
    m = re.search(r"(?<!\d)(\d+)\s*/\s*(\d+)(?!\d)", text)
    if m:
        free = int(m.group(1))
        offer = int(m.group(2))
        return {
            "status": "available" if free > 0 else "unavailable",
            "free": free,
            "offer": offer,
        }

    low = text.lower()
    m = re.search(r"(?<!\d)(\d+)\s+(?:freie|verfügbare|verfuegbare)\s+pl(?:ä|ae)tze?", low)
    if m:
        free = int(m.group(1))
        return {
            "status": "available" if free > 0 else "unavailable",
            "free": free,
            "offer": None,
        }

    if "kein angebot" in low or "keine verfügbaren" in low or "keine verfuegbaren" in low:
        return {"status": "unavailable", "free": 0, "offer": None}

    raise RuntimeError("Availability cell was found but could not be interpreted safely.")


def human_status(result: dict) -> str:
    if result["status"] == "available":
        if result.get("offer") is not None:
            return f"{result['free']}/{result['offer']} (frei/Angebot)"
        if result.get("free") is not None:
            return f"{result['free']} freie(r) Platz/Plätze"
        return "frei"
    if result.get("offer") is not None:
        return f"{result.get('free', 0)}/{result['offer']} (frei/Angebot)"
    return "aktuell kein freier Platz erkannt"


def handle_expiry(state: dict) -> int:
    EXPIRED_FILE.write_text("expired\n", encoding="utf-8")
    log("Configured end time reached. No PJ-Portal request will be made.")

    if not state.get("expired_notified"):
        send_email(
            "PJ-Watcher beendet",
            "Der vereinbarte Überwachungszeitraum ist abgelaufen.\n\n"
            "Der Watcher greift ab jetzt nicht mehr auf das PJ-Portal zu und "
            "deaktiviert anschließend seinen GitHub-Actions-Workflow automatisch.\n",
        )
        state["expired_notified"] = True
        save_state(state)

    return 0


def main() -> int:
    require_config()
    state = load_state()

    if is_expired():
        return handle_expiry(state)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage"],
            )
            page = browser.new_page(locale="de-DE")
            page.set_default_timeout(PAGE_TIMEOUT_MS)

            login(page)
            open_merkliste(page)
            info = extract_target_third_tertial(page)
            result = classify(info["cell"])
            browser.close()

        status = result["status"]
        log(f"CHECK_OK status={status}")

        if TEST_MODE:
            send_email(
                "PJ-Watcher TEST: läuft",
                "Der manuelle Testlauf war erfolgreich.\n\n"
                "✓ GitHub Actions läuft.\n"
                "✓ Login ins PJ-Portal war erfolgreich.\n"
                "✓ Merkliste wurde geöffnet.\n"
                "✓ Der gewünschte Eintrag wurde gefunden.\n"
                "✓ Die Verfügbarkeit des 3. Tertials konnte gelesen werden.\n"
                "✓ Der E-Mail-Versand funktioniert.\n\n"
                f"Aktueller Status: {human_status(result)}\n\n"
                "Dies war nur ein Test. Es wurde nichts gebucht oder verändert.\n",
            )
            return 0

        previous = state.get("last_status")

        if status == "available" and previous != "available":
            send_email(
                "PJ-PLATZ FREI – bitte sofort prüfen",
                "Der PJ-Watcher hat beim überwachten Platz im 3. Tertial "
                "mindestens einen freien Platz erkannt.\n\n"
                f"Erkannte Verfügbarkeit: {human_status(result)}\n\n"
                "Bitte jetzt selbst im PJ-Portal einloggen und buchen, wenn du den Platz möchtest.\n\n"
                "Der Watcher selbst bucht oder verändert nichts.\n",
            )

        # We deliberately store only the generic status; no target/user details.
        if previous != status:
            state["last_status"] = status
            state["last_change_utc"] = datetime.now(timezone.utc).isoformat()
            save_state(state)

        return 0

    except Exception as exc:
        # Keep public log generic. Full target/page contents are not printed.
        log(f"CHECK_FAILED type={type(exc).__name__}")

        try:
            send_email(
                "PJ-Watcher: Prüfung fehlgeschlagen",
                "Der Watcher konnte den PJ-Platz diesmal nicht zuverlässig prüfen.\n\n"
                f"Fehlerart: {type(exc).__name__}\n"
                f"Hinweis: {str(exc)}\n\n"
                "Es wurde nichts gebucht oder verändert. "
                "Bitte den GitHub-Actions-Lauf kontrollieren.\n",
            )
        except Exception:
            log("ERROR_EMAIL_FAILED")

        return 1


if __name__ == "__main__":
    sys.exit(main())
