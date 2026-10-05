# Multi-stage build for Zaalima IAM Server
FROM eclipse-temurin:17-jdk-jammy AS builder
WORKDIR /app
COPY pom.xml .
COPY .mvn .mvn
COPY mvnw mvnw
COPY mvnw.cmd mvnw.cmd
COPY src src

RUN chmod +x ./mvnw && ./mvnw clean package -DskipTests

FROM eclipse-temurin:17-jre-jammy
WORKDIR /app

# Non-root user for security hardening
RUN groupadd -r iamgroup && useradd -r -g iamgroup iamuser

COPY --from=builder /app/target/*.jar app.jar
RUN chown -R iamuser:iamgroup /app

USER iamuser

EXPOSE 8085

ENTRYPOINT ["java", "-jar", "app.jar"]
