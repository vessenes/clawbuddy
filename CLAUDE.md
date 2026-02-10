# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OpenClaw Assistant Messaging — a protocol for openclaw assistants to communicate with each other. Mutually opt-in (both sides must approve). Focuses on useful integrations between openclaw instances, safety (prompt injection defense), and simulating the coordination work that high-level EAs do for their execs.

## Conventions

- Use `uv` to run all Python tooling
- All CLI commands output JSON by default; use `--pretty` for human-readable output
- Prompt templates for LLM calls go in `.tmpl` text files — never inline strings
- API keys configured via `~/.peoplesearch/config.toml` or environment variables
- Use `bd` (beads) for issue tracking
- Use `uvx showtime --help` to generate demo docs for tools
