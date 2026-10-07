# Zaalima IAM Server

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen)]()
[![Tests](https://img.shields.io/badge/Tests-215%20Passing-success)]()
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.16-blue)]()
[![Java](https://img.shields.io/badge/Java-21-orange)]()

An enterprise-grade, high-performance Identity and Access Management (IAM) Server built with Spring Boot 3, Spring Authorization Server, PostgreSQL, and Redis.

## Features
- OAuth2 PKCE Authorization Code Grant (RFC 7636)
- Client Credentials M2M Grant (RFC 6749 §4.4)
- Token Revocation (RFC 7009) & Introspection (RFC 7662)
- Refresh Token Rotation & Replay Detection
- Multi-Stage Dockerfile (Alpine JRE 21) & Docker Compose (Postgres 16 + Redis 7)
- 215/215 Automated Tests Passing
