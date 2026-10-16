"""Maintainer proofs run against the published packages, never against this checkout.

Run from `scripts/` with the base interpreter, not the one the proof installs into:
`python -m proofs <command> --help`. `.github/workflows/proofs.yml` runs them on clean
runners; each command writes a JSON record of every step it took.
"""
