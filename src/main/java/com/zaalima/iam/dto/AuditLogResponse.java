package com.zaalima.iam.dto;

import com.zaalima.iam.entity.AuditLog;

import java.time.Instant;

public record AuditLogResponse(
        Long id,
        String username,
        String eventType,
        String description,
        Instant timestamp,
        boolean success,
        String ipAddress
) {
    public static AuditLogResponse from(AuditLog auditLog) {
        return new AuditLogResponse(
                auditLog.getId(),
                auditLog.getUsername(),
                auditLog.getEventType(),
                auditLog.getDescription(),
                auditLog.getTimestamp(),
                auditLog.isSuccess(),
                auditLog.getIpAddress()
        );
    }
}
