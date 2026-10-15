# Zaalima Identity and Access Management (IAM) Server

[![Java](https://img.shields.io/badge/Java-17-orange)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.16-brightgreen)](https://spring.io/projects/spring-boot)
[![PostgreSQL](https://img.shields.io/badge/Database-PostgreSQL-blue)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Cache-Redis-red)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Containerized-Docker-2496ED)](https://www.docker.com/)

A Java-based Identity and Access Management server built with Spring Boot, Spring Security, Spring Authorization Server, PostgreSQL, Redis, and TOTP-based multi-factor authentication.

The project includes user management, authentication-related security controls, OAuth2 authorization-server integration, MFA workflows, role and authority management, token revocation, and audit-log functionality.

> **Status:** The dashboard frontend has been pushed to the `main` branch. The latest recorded automated test run completed with 220 tests, zero failures, zero errors, and zero skipped tests. Re-run tests before releases and verify individual security flows before production use.

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Problem Statement and Objectives](#2-problem-statement-and-objectives)
3. [Features](#3-features)
4. [Technology Stack](#4-technology-stack)
5. [Architecture](#5-architecture)
6. [Project Structure](#6-project-structure)
7. [Prerequisites](#7-prerequisites)
8. [Clone the Repository](#8-clone-the-repository)
9. [Environment Configuration](#9-environment-configuration)
10. [Run Locally](#10-run-locally)
11. [Run with Docker Compose](#11-run-with-docker-compose)
12. [Application URLs](#12-application-urls)
13. [API Reference](#13-api-reference)
14. [Authentication and MFA](#14-authentication-and-mfa)
15. [Database and Redis](#15-database-and-redis)
16. [Frontend Dashboard](#16-frontend-dashboard)
17. [Build and Testing](#17-build-and-testing)
18. [Security Considerations](#18-security-considerations)
19. [Troubleshooting](#19-troubleshooting)
20. [Current Limitations](#20-current-limitations)
21. [Future Roadmap](#21-future-roadmap)
22. [Contribution Guidelines](#22-contribution-guidelines)
23. [Development Workflow](#23-development-workflow)
24. [License](#24-license)

## 1. Project Overview

Identity and Access Management (IAM) involves managing digital identities, verifying users, and controlling access to applications and resources.

Zaalima IAM Server provides a centralized foundation for identity-related operations, including user registration, profile management, authentication-related security controls, MFA, role and authority assignments, OAuth2 integration, token revocation, and audit-log access.

## 2. Problem Statement and Objectives

Applications that implement identity management independently may duplicate authentication logic, user records, access-control rules, and security workflows.

Project objectives:

- Centralize identity-related operations.
- Provide user registration and profile endpoints.
- Integrate Spring Security.
- Integrate Spring Authorization Server.
- Provide TOTP-based MFA-related workflows.
- Persist identity data using PostgreSQL.
- Integrate Redis for supporting operations.
- Provide role and authority assignment endpoints.
- Provide token revocation and audit-log endpoints.
- Supply a browser-based dashboard for supported operations.

## 3. Features

### User management

- User registration.
- Authenticated-user profile retrieval and update.
- User lookup endpoints.
- User enable/disable operations.
- Role assignment and removal.
- Password-reset-related endpoints.

### Authentication and authorization

- Spring Security integration.
- OAuth2 authorization-server integration.
- Authorization consent page.
- MFA authentication controller and page.
- Token revocation endpoint.
- CSRF-token endpoint.

The exact OAuth2 grants, endpoint permissions, and token lifecycle behavior must be confirmed against the current security configuration.

### Multi-factor authentication

- MFA setup endpoint.
- MFA code verification endpoint.
- MFA enable and disable endpoints.
- TOTP library integration.
- MFA-related authentication workflow.

The dashboard currently supports manual setup using the secret returned by the backend. QR-code enrollment and a verified MFA status badge are not provided by the current dashboard/API contract.

### Administration and auditing

- Audit-log retrieval endpoint.
- Role-authority assignment and removal.
- User administration endpoints.

### Infrastructure

- PostgreSQL integration.
- Redis integration.
- Docker Compose configuration.
- Maven build and automated testing.

## 4. Technology Stack

| Technology | Purpose |
|---|---|
| Java 17 | Application language and runtime |
| Spring Boot 3.5.16 | Application framework |
| Spring Security | Application security |
| Spring Authorization Server | OAuth2 authorization-server integration |
| Spring Web | HTTP endpoints |
| Spring Data JPA | Persistence abstraction |
| PostgreSQL | Relational database |
| Spring Data Redis | Redis integration |
| Redis 7 | Supporting in-memory data operations |
| TOTP library 1.7.1 | Time-based one-time-password functionality |
| Spring Validation | Request validation |
| Thymeleaf | Server-rendered pages |
| HTML, CSS, JavaScript | Dashboard frontend |
| Bootstrap 5.3.3 | Frontend styling |
| Maven | Build and dependency management |
| Spring Boot Test | Automated testing |
| Spring Security Test | Security-focused tests |
| H2 | Test database support |
| Docker Compose | Containerized execution |

Dependencies are declared in `pom.xml`.

## 5. Architecture

```text
                 Browser / API Client
                         |
                         v
               Spring Security Layer
                         |
                         v
                Controllers / Routes
                         |
                         v
                    Services
                         |
               +---------+---------+
               |                   |
               v                   v
        Spring Data JPA       Redis Integration
               |
               v
           PostgreSQL

Supporting components:
- OAuth2 authorization-server configuration
- TOTP/MFA services
- CSRF handling
- Audit logging
- Thymeleaf pages
- Static dashboard
```

### Layer responsibilities

- **Controllers:** expose HTTP endpoints for user management, MFA, consent, token revocation, roles, and audit logs.
- **Services:** implement application-level identity, MFA, rate-limiting, token-revocation, and audit operations.
- **Repositories:** provide database access through Spring Data interfaces.
- **Entities:** represent users, roles, authorities, MFA credentials, password-reset records, and audit logs.
- **Security configuration:** defines authentication and authorization behavior.
- **Infrastructure:** PostgreSQL stores relational data; Redis supports application operations.

The exact responsibility of each component should be confirmed from its implementation when extending the project.

## 6. Project Structure

```text
zaalima-project-3-iam-server/
├── pom.xml
├── Dockerfile
├── docker-compose.yml
├── README.md
└── src/
    ├── main/
    │   ├── java/com/zaalima/iam/
    │   │   ├── IamServerApplication.java
    │   │   ├── config/
    │   │   ├── controller/
    │   │   ├── dto/
    │   │   ├── entity/
    │   │   ├── exception/
    │   │   ├── initializer/
    │   │   ├── repository/
    │   │   ├── security/
    │   │   └── service/
    │   └── resources/
    │       ├── application.yml
    │       ├── application-prod.yml
    │       ├── static/
    │       │   ├── index.html
    │       │   ├── css/app.css
    │       │   └── js/app.js
    │       └── templates/
    │           ├── consent.html
    │           └── mfa.html
    └── test/
```

### Package overview

- `config/` — security, authorization-server, and TOTP configuration.
- `controller/` — HTTP endpoint definitions.
- `dto/` — request and response objects.
- `entity/` — persistence entities.
- `exception/` — exception handling.
- `initializer/` — initialization components.
- `repository/` — database access interfaces.
- `security/` — security support components.
- `service/` — application services.
- `resources/static/` — frontend assets.
- `resources/templates/` — server-rendered pages.

## 7. Prerequisites

For local development:

- JDK 17.
- Maven, or the Maven Wrapper if present.
- PostgreSQL.
- Redis.
- Git.

For containerized execution, install Docker Desktop with Docker Compose support.

Check installed tools:

```powershell
java -version
mvn -version
git --version
docker --version
docker compose version
```

## 8. Clone the Repository

```powershell
git clone https://github.com/sudharshan-163/zaalima-project-3-iam-server.git
cd zaalima-project-3-iam-server
```

## 9. Environment Configuration

The application reads configuration from YAML files and environment variables.

### Common variables

| Variable | Purpose | Default/example |
|---|---|---|
| `SPRING_DATASOURCE_URL` | PostgreSQL JDBC URL | `jdbc:postgresql://127.0.0.1:5432/zaalima_iam` |
| `SPRING_DATASOURCE_USERNAME` | Database username | `postgres` in default configuration |
| `SPRING_DATASOURCE_PASSWORD` | Database password | Set privately in the environment |
| `SPRING_DATA_REDIS_HOST` | Redis hostname | `127.0.0.1` |
| `SPRING_DATA_REDIS_PORT` | Redis port | `6379` |
| `SERVER_PORT` | Application port | `8085` |
| `DB_PASSWORD` | Docker Compose database password | Set before starting containers |

### Local PowerShell example

Replace the placeholders with your local database configuration:

```powershell
$env:SPRING_DATASOURCE_URL = "jdbc:postgresql://127.0.0.1:5432/zaalima_iam"
$env:SPRING_DATASOURCE_USERNAME = "postgres"
$env:SPRING_DATASOURCE_PASSWORD = "<YOUR_LOCAL_DATABASE_PASSWORD>"
$env:SPRING_DATA_REDIS_HOST = "127.0.0.1"
$env:SPRING_DATA_REDIS_PORT = "6379"
$env:SERVER_PORT = "8085"
```

Do not commit real passwords, MFA secrets, private keys, tokens, or production credentials.

## 10. Run Locally

### Step 1: Start PostgreSQL and Redis

Make sure both services are running and accessible with the configured connection details.

### Step 2: Configure environment variables

Follow [Environment Configuration](#9-environment-configuration).

### Step 3: Build the application

```powershell
mvn clean package -DskipTests
```

### Step 4: Start the application

```powershell
mvn spring-boot:run
```

Alternatively, run the generated JAR:

```powershell
java -jar target/iam-server-0.0.1-SNAPSHOT.jar
```

### Step 5: Open the application

```text
http://localhost:8085/
http://localhost:8085/login
```

Access depends on the current authentication state and security configuration.

## 11. Run with Docker Compose

Docker Compose defines the IAM application, PostgreSQL 16, and Redis 7 services.

### Step 1: Set the database password

```powershell
$env:DB_PASSWORD = "<YOUR_STRONG_LOCAL_DATABASE_PASSWORD>"
```

### Step 2: Start the services

```powershell
docker compose up -d --build
```

### Step 3: Check status

```powershell
docker compose ps
```

### Step 4: View application logs

```powershell
docker compose logs -f zaalima-iam-server
```

PostgreSQL logs:

```powershell
docker compose logs -f zaalima-postgres
```

Redis logs:

```powershell
docker compose logs -f zaalima-redis
```

### Step 5: Stop the services

```powershell
docker compose down
```

Named database volumes are retained unless explicitly removed. `docker compose down -v` can delete local database data; use it only when data loss is acceptable.

## 12. Application URLs

| Resource | URL |
|---|---|
| Dashboard | `http://localhost:8085/` |
| Login | `http://localhost:8085/login` |
| OAuth2 consent | `http://localhost:8085/oauth2/consent` |
| MFA authentication | `http://localhost:8085/mfa` |
| CSRF endpoint | `http://localhost:8085/api/csrf` |

Some pages and endpoints require authentication or an active session.

## 13. API Reference

The following paths are controller mappings identified in the source. This inventory does not imply that every endpoint is publicly accessible.

### User management

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/users/register` | Register a user |
| GET | `/api/users/me` | Retrieve the authenticated user's profile |
| PUT | `/api/users/me` | Update the authenticated user's profile |
| GET | `/api/users/{id}` | Retrieve a user by ID |
| PUT | `/api/users/{id}` | Update a user by ID |
| GET | `/api/users/by-username/{username}` | Look up a user by username |
| GET | `/api/users/by-email/{email}` | Look up a user by email |
| PATCH | `/api/users/{id}/enable` | Enable a user |
| PATCH | `/api/users/{id}/disable` | Disable a user |
| POST | `/api/users/{userId}/roles/{roleId}` | Assign a role |
| DELETE | `/api/users/{userId}/roles/{roleId}` | Remove a role |
| POST | `/api/users/password/forgot` | Start password recovery |
| POST | `/api/users/password/reset` | Submit a password-reset request |

### MFA

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/mfa/setup` | Set up MFA |
| POST | `/api/mfa/verify` | Verify an MFA code |
| POST | `/api/mfa/enable` | Enable MFA |
| POST | `/api/mfa/disable` | Disable MFA |

### Roles and authorities

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/roles/{roleId}/authorities/{authorityId}` | Assign an authority |
| DELETE | `/api/roles/{roleId}/authorities/{authorityId}` | Remove an authority |

### Token revocation and audit

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/tokens/revoke` | Submit a token-revocation request |
| GET | `/api/admin/audit-logs` | Retrieve audit-log information |

### Other routes

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/csrf` | Retrieve CSRF information |
| GET | `/oauth2/consent` | Render OAuth2 consent page |
| GET | `/mfa` | Render MFA authentication page |
| POST | `/mfa` | Handle MFA authentication submission |

OAuth2 protocol endpoints may also be provided by Spring Authorization Server configuration. Verify exact URLs, grant types, client requirements, request parameters, and response schemas against the current implementation.

### API usage notes

- Inspect request DTOs for required fields and validation rules.
- Inspect the security configuration for authentication and role requirements.
- State-changing browser requests may require a CSRF token.
- A controller mapping does not mean the route is public.
- Do not share real tokens, passwords, or MFA codes in logs or screenshots.

## 14. Authentication and MFA

### Authentication

The application integrates Spring Security and includes authentication-related components. The exact login sequence and OAuth2 grant behavior depend on the current security and authorization-server configuration.

### MFA workflow

1. Sign in through the supported authentication flow.
2. Open Security / MFA in the dashboard.
3. Request MFA setup.
4. Use the returned secret with a compatible authenticator application where applicable.
5. Enter the current six-digit TOTP code.
6. Verify the code or enable MFA using the relevant endpoint.
7. Disable MFA through the provided operation when appropriate.

Treat an MFA secret as a credential. Never publish it or a live OTP.

The dashboard does not currently provide a verified QR-code enrollment flow or MFA status badge.

## 15. Database and Redis

### PostgreSQL

The application uses Spring Data JPA and the PostgreSQL JDBC driver. Identity-related entities include users, roles, authorities, MFA credentials, password-reset information, and audit logs.

The current configuration includes:

```yaml
spring:
  jpa:
    hibernate:
      ddl-auto: update
```

For production, consider a controlled database migration strategy instead of relying on automatic schema updates.

### Redis

The project includes Spring Data Redis and a Redis service in Docker Compose. Review the relevant services and configuration to confirm exact key structures, expiration rules, and operational behavior.

### Persistence recommendations

- Back up database data.
- Use separate development and production credentials.
- Restrict external access to PostgreSQL and Redis.
- Define retention and cleanup policies for audit and security records.

## 16. Frontend Dashboard

Frontend files:

```text
src/main/resources/static/
├── index.html
├── css/
│   └── app.css
└── js/
    └── app.js
```

Dashboard sections:

- **Overview:** Summary of supported functionality.
- **Profile:** Retrieve and update the authenticated user's profile.
- **Registration:** Submit a user-registration request.
- **Security / MFA:** Request setup, verify a code, enable MFA, or disable MFA.

The frontend uses existing backend endpoints and session-based requests. Backend authorization remains the actual security boundary.

## 17. Build and Testing

### Build without running tests

```powershell
mvn -DskipTests package
```

### Run automated tests

```powershell
mvn test
```

### Run complete verification

```powershell
mvn clean verify
```

The latest recorded test run completed with **220 tests, zero failures, zero errors, and zero skipped tests**. Re-run the tests before a release because results may change as the code changes.

Recommended additional validation:

- Valid and invalid registration input.
- Profile retrieval and update persistence.
- Authorization for administrative endpoints.
- MFA setup, verification, enablement, disablement, and login challenges.
- OAuth2 flows using correctly registered clients.
- Token revocation behavior.
- CSRF protection for state-changing requests.
- Password recovery and reset.
- Container health and persistence after restart.
- Sensitive-value exposure in logs and API responses.

## 18. Security Considerations

Before production use:

- Keep passwords, signing keys, client secrets, and MFA secrets out of source control.
- Use environment variables or a secrets manager.
- Enforce HTTPS.
- Review authorization for every sensitive endpoint.
- Protect administrative user, role, authority, audit, and token operations.
- Verify password hashing and password-reset controls.
- Apply rate limits to authentication and recovery endpoints.
- Review session expiration, cookie flags, CSRF handling, and logout behavior.
- Protect MFA enrollment secrets and challenge state.
- Define audit-log access and retention.
- Review database migrations and backups.
- Keep dependencies patched.
- Avoid exposing authentication secrets in the dashboard.

The presence of a security library or endpoint does not by itself prove that the application is secure. Conduct a dedicated security review before production deployment.

## 19. Troubleshooting

### PostgreSQL connection failure

- Confirm PostgreSQL is running.
- Verify JDBC URL, username, and password.
- Confirm the database exists.
- Check port connectivity.
- From the application container, use the Compose service name rather than `localhost`.

### Redis connection failure

- Confirm Redis is running.
- Verify host and port.
- Check container health and application logs.

### Port 8085 is already in use

Stop the conflicting process or select another application port and update the corresponding container port mapping.

### Browser redirects to login

Some resources require authentication. Inspect browser network requests and the security configuration before treating a redirect as an application failure.

### CSRF errors

Retrieve CSRF information from the supported endpoint and send the expected header. Confirm the token and session belong to the same browser session.

### Maven test failures

Run the failing test individually, inspect the complete exception, and verify test-profile/database configuration before changing application code.

## 20. Current Limitations

Items requiring further verification or implementation:

- QR-code MFA enrollment and a dashboard MFA status indicator are not currently provided by the described frontend/API contract.
- OAuth2 grant support and protocol behavior should be checked against authorization-server configuration.
- Endpoint authorization requirements should be documented from the security configuration.
- Password recovery, profile persistence, token revocation, and OAuth2 consent should be verified end to end.
- Production database migration strategy requires review.
- HTTPS, secrets management, monitoring, backup, and recovery require environment-specific setup.

## 21. Future Roadmap

These are proposed enhancements, not claims of completed functionality.

### Phase 1 — Documentation and API quality

- Document request and response schemas.
- Document authentication and authorization requirements.
- Add examples for supported API requests.
- Document error responses.
- Introduce API documentation tooling where appropriate.

### Phase 2 — Authentication experience

- Add QR-code MFA enrollment.
- Add a clear MFA status view.
- Improve account-recovery flows.
- Validate session expiration and logout.
- Improve user-facing authentication errors.

### Phase 3 — Security hardening

- Review all endpoint permissions.
- Add authorization tests.
- Review rate limiting and account lockout.
- Verify token revocation and refresh-token lifecycle.
- Establish secret rotation procedures.
- Review dependencies and security configuration.

### Phase 4 — Database and operations

- Introduce versioned database migrations.
- Document backup and restore.
- Define audit-log retention.
- Add monitoring and alerting.
- Improve readiness and liveness checks.
- Establish deployment and rollback procedures.

### Phase 5 — Developer experience

- Add an OpenAPI specification.
- Improve development environment documentation.
- Add integration-test examples.
- Document client registration and OAuth2 setup.
- Establish a contribution and release process.

## 22. Contribution Guidelines

1. Create a feature branch.
2. Keep changes focused.
3. Never commit secrets or local environment files.
4. Add tests for behavior changes.
5. Run the relevant test suite.
6. Review the final diff.
7. Open a pull request with a clear summary and validation results.

Security-sensitive changes require additional review.

## 23. Development Workflow

Example branch workflow:

```powershell
git checkout main
git pull origin main
git checkout -b docs/update-iam-readme
```

Review changes:

```powershell
git diff --check
git diff -- README.md
git status --short
```

Stage only the intended README file:

```powershell
git add README.md
git diff --cached --check
git diff --cached
```

After reviewing and approving the staged diff:

```powershell
git commit -m "docs: improve IAM server README"
git push origin docs/update-iam-readme
```

Follow the project's agreed process for merging documentation into `main`.

## 24. License

A license has not yet been specified in this README. Add the appropriate license file and update this section before distributing the project under an explicit open-source license.

---

**Repository:** [zaalima-project-3-iam-server](https://github.com/sudharshan-163/zaalima-project-3-iam-server)
**Default branch:** `main`
**Maintainer:** Project team
