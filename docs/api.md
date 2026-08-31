# API Reference

> Populated in MILESTONE 2+ as endpoints are implemented. This file documents the FastAPI contract.

## Base URL

`http://localhost:8000/api/v1`

## Health

### `GET /health`
Returns app + database health.

## System

### `GET /system/status`
Returns tool availability (Python, TShark, Zeek, Docker, Npcap).

_(Added in M2)_
