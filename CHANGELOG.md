# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.1.0] - 2026-04-05

### Added
- MVP pipeline with validators for SQL injection, command execution, secrets, and malicious imports
- FastAPI demo UI with Groq integration for AI-powered code analysis
- SQLite database for guardrails configuration
- CLI tool for running code analysis

### Changed
- Refactored validator factory to support dynamic pipeline configuration
- Improved error handling and logging throughout
- Updated test coverage with comprehensive validator tests