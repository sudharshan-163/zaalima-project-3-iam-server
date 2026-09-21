package com.zaalima.iam.service;

import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.repository.AuditLogRepository;
import lombok.RequiredArgsConstructor;
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
        auditLog.setUsername(username);
        auditLog.setEventType(eventType);
        auditLog.setDescription(description);
        auditLog.setTimestamp(Instant.now());
        auditLog.setSuccess(success);
        auditLog.setIpAddress(ipAddress);

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
}
