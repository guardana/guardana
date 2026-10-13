---
title: "Adopter study"
nav_order: 16
summary: "How the maintainer records two independent teams' consented runs and generates adoption measures, separate from stable 1.0 release criteria"
status: stable
---

# Adopter study

The [F6 adoption measure](../product-status.md#adoption-measures) covers two independent teams running locked checks on their own application. It is not a stable 1.0 release criterion. This page explains how the maintainer records their runs and consent. The published application measures are [generated from the sheet](../generated/application-measures.md) and read "not measured": 0 of 2 teams have recorded runs. Pilot invitations remain open; the maintainer-run retrieval proof uses the reference application in `examples/retrieval_pilot/`, while the adoption pilot uses a team's own target.

## One run

- The team runs its own application through a recipe whose `kind` is `application`,
  with a lock: `guardana recipe lock`, then `guardana recipe run`. A model harness, a plain
  `probe` or a `scan` does not count, and `scripts/adopter_measure.py` refuses it.
- The run must finish: a run stopped by its budget, an interrupt or the target is refused,
  because the rules it never started are not recorded.
- The run must record no error that names no rule, such as a source file it could not read or a
  target that misstated what it offers: such an error lowers no rule's count, so the rules it
  touched would read as decided.
- The team keeps the saved run. The maintainer never needs its content: `row` reads only counts.

```bash
uv run python scripts/adopter_measure.py row run.json --team T1 --consent yes
```

The team runs that command on its own machine and sends the printed line. Nothing else leaves
the team.

## Consent

Ask for consent before the first run is recorded, in the team's language. The text must say what
is recorded (the counts in the row, the Guardana version, the run's schema version and its random
identifier), what is not (no prompt, reply, finding, rule id, target address or file from the
team), where the line is kept and for how long, that only the counts are published under an identifier such as T1 and never
the team's or company's name, and that the team can withdraw before publication. Fill in the
storage place and the retention period before using it.

### English

We record one line of counts per run: how many checks were selected, how many did not apply to
your application, how many ran, and how many reached a verdict, with the Guardana version, the
run's schema version and the run's random identifier. We record nothing from your application: no
prompt, reply, finding, rule name or address.

Lines are kept in [STORAGE] for [RETENTION]. Only the counts are published, under an identifier
such as T1, never your team's or your company's name. You can withdraw at any time before
publication; your lines will then be deleted.

Do you agree to publication of these counts? Yes/No.

### Polski

Z każdego przebiegu zapisujemy jeden wiersz liczb: ile kontroli wybrano, ile nie dotyczyło Waszej
aplikacji, ile się wykonało i ile doszło do werdyktu, oraz wersję Guardany, wersję schematu
przebiegu i jego losowy identyfikator. Nie zapisujemy niczego z Waszej aplikacji: żadnego promptu,
odpowiedzi, wyniku, nazwy reguły ani adresu.

Wiersze przechowujemy w [STORAGE] przez [RETENTION]. Publikujemy tylko liczby pod identyfikatorem
takim jak T1, nigdy nazwę zespołu ani firmy. Możecie wycofać zgodę w dowolnym momencie przed
publikacją; Wasze wiersze zostaną wtedy usunięte.

Czy zgadzacie się na opublikowanie tych liczb? Tak/Nie.

## The sheet

Add each consented line to [`adopter-runs.csv`](adopter-runs.csv):

| column | values |
|---|---|
| `team` | `T1`, `T2`, … — never a name |
| `run_id` | the run's own identifier, from the saved run; a run is recorded once |
| `guardana` | the version that wrote the run |
| `schema_version` | the run's schema, 14 or later |
| `rules_selected`, `rules_not_applicable`, `rules_attempted`, `rules_decided` | counts from the run |
| `consent_to_publish` | `yes` — a line without it is never committed |

`uv run python scripts/adopter_measure.py` validates the sheet and prints the measures.
`uv run python scripts/generate_docs.py` writes them to the generated page. Neither accepts a line
without consent, a team written as a name, a run recorded twice, or counts that contradict each
other.
