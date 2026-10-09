---
title: "First-run study"
nav_order: 13
summary: "How the maintainer runs the five first-run sessions required before 1.0, records consent, and generates the published measure"
status: stable
---

# First-run study

The [F2 release criterion](../product-status.md#before-the-first-stable-release) asks whether a new user can get a failing result, fix it, keep the evidence and edit one check, offline, within ten minutes. Only people new to Guardana can answer that question. This page explains how the maintainer runs those sessions. The published answer is [generated from the sheet](../generated/first-run.md) and says "not measured" until five consented sessions are recorded.

## One session

- Use one participant who has not used Guardana. They work on their own machine, in a clean virtual environment, using the published release and the README only.
- The maintainer watches and does not help. Record a hint or taking over as such.
- Start the clock at the first command. Stop it when `rule test` passes on the edited check, or at 30 minutes. A participant finished within ten minutes when that happened within 600 seconds; `finished_in_10_min` must agree with `edited_check_seconds`, and the sheet is refused when it does not.
- Record the seconds from the start when each step was reached: install, first failure, fix, saved run, edited check. Leave a step empty if it was not reached.

## Consent

Ask for consent before the session, in the participant's language. The text must say what is recorded (the timings, whether they finished, where they got stuck), what is not (no screen recording unless they ask for one, no files from their machine, no telemetry; the starter runs offline, while probes and configured integrations make network requests), where the notes are kept and for how long, that only counts and times are published and never names, and that they can withdraw before publication. Fill in the storage place and the retention period before using it.

### English

We record when each step was reached, whether you finished, and where you got stuck. We record your own words only if you agree separately.

There is no screen recording unless you ask for one. We record no files from your machine. Your starter session runs offline and has no telemetry; probes and configured integrations make network requests.

Notes are kept in [STORAGE] for [RETENTION]. Only counts and times are published, under an identifier such as P1, never your name. You can withdraw at any time before publication; your row will then be deleted.

Do you agree to take part? Yes/No. Do you agree to publication of your anonymised row? Yes/No.

### Polski

Zapisujemy czas dotarcia do każdego kroku, informację o tym, czy udało Ci się ukończyć zadanie, oraz miejsce, w którym pojawiła się trudność. Twoje własne słowa zapiszemy tylko za osobną zgodą.

Nie nagrywamy ekranu, chyba że o to poprosisz. Nie zapisujemy plików z Twojego komputera. Twoja sesja ze starterem działa offline i nie wysyła telemetrii; `guardana probe` i skonfigurowane integracje wysyłają żądania sieciowe.

Notatki przechowujemy w [STORAGE] przez [RETENTION]. Publikujemy tylko liczby i czasy pod identyfikatorem takim jak P1, nigdy Twoje imię ani nazwisko. Możesz wycofać się w dowolnym momencie przed publikacją; Twój wiersz zostanie wtedy usunięty.

Czy zgadzasz się na udział? Tak/Nie. Czy zgadzasz się na opublikowanie Twojego zanonimizowanego wiersza? Tak/Nie.

## The sheet

Keep notes outside the repository until consent is confirmed. Then add one row per participant to [`first-run-study.csv`](first-run-study.csv), using these columns and nothing else:

| column | values |
|---|---|
| `participant` | `P1`, `P2`, … — never a name |
| `date` | `YYYY-MM-DD` |
| `os`, `python` | as the participant reports them |
| `install_seconds`, `first_failure_seconds`, `fixed_seconds`, `saved_run_seconds`, `edited_check_seconds` | seconds from the start, empty when not reached |
| `finished_in_10_min` | `yes` or `no` |
| `maintainer_help` | `none`, `hint` or `took over` |
| `stuck_at` | the step, or empty |
| `consent_to_publish` | `yes` — a row without it is never committed |

`uv run python scripts/first_run_measure.py` validates the sheet and prints the measure. `uv run python scripts/generate_docs.py` writes it to the generated page. Neither accepts a row without consent, a participant written as a name, or a finish the timings contradict.
