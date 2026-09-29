# Vuln Scout

Система мониторинга открытых источников для обнаружения новых,
критических и потенциально 0-day уязвимостей.

## Status

🚧 v0.1 — MVP development

## Architecture

Source
→ Collector
→ Pre-filter
→ AI Analyzer
→ Validator
→ Normalizer
→ Correlator
→ Zero-day Scoring
→ PostgreSQL
→ Telegram

## Stack

- Python
- PostgreSQL
- Docker / Docker Compose
- LLM API
- Telegram Bot

## Branches

- `main` — стабильные версии
- `develop` — текущая разработка
- `feature/*` — новая функциональность
- `fix/*` — исправления