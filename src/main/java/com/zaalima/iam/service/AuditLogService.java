package com.zaalima.iam.service;

import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuditLogService {

    private final AuditLogRepository auditLogRepository;

    public AuditLog logEvent(
            String username,
            String eventType,
            String description,
            boolean success,
            String ipAddress) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(truncate(username, 255));
        auditLog.setEventType(truncate(eventType, 100));
        auditLog.setDescription(truncate(description, 255));
        auditLog.setTimestamp(Instant.now());
        auditLog.setSuccess(success);
        auditLog.setIpAddress(truncate(ipAddress, 45));

        return auditLogRepository.save(auditLog);
    }

    public AuditLog logSuccess(
            String username,
            String eventType,
            String description) {

        return logEvent(username, eventType, description, true, null);
    }

    public AuditLog logFailure(
            String username,
            String eventType,
            String description) {

        return logEvent(username, eventType, description, false, null);
    }

    public Page<AuditLog> getAuditLogs(
            String username,
            String eventType,
            Pageable pageable) {

        return auditLogRepository.findFiltered(
                normalizeFilter(username),
                normalizeFilter(eventType),
                pageable);
    }

    private String normalizeFilter(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String truncate(String value, int maxLength) {
        if (value == null) {
            return null;
        }
        return value.length() > maxLength ? value.substring(0, maxLength) : value;
    }
}
