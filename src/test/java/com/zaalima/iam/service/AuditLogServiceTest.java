package com.zaalima.iam.service;

import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.repository.AuditLogRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuditLogServiceTest {

    @Mock
    private AuditLogRepository auditLogRepository;

    @InjectMocks
    private AuditLogService auditLogService;

    @Test
    void logSuccess_shouldPersistSuccessfulAuditEvent() {

        auditLogService.logSuccess(
            "testuser",
            "USER_REGISTERED",
            "User registration completed successfully"
        );

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog auditLog = captor.getValue();

        assertEquals("testuser", auditLog.getUsername());
        assertEquals("USER_REGISTERED", auditLog.getEventType());
        assertEquals("User registration completed successfully", auditLog.getDescription());
        assertTrue(auditLog.isSuccess());
        assertNotNull(auditLog.getTimestamp());
        assertNull(auditLog.getIpAddress());
    }

    @Test
    void logFailure_shouldPersistFailedAuditEvent() {

        auditLogService.logFailure(
            "testuser",
            "REGISTRATION_FAILED_DUPLICATE_USERNAME",
            "User registration failed because the username already exists"
        );

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog auditLog = captor.getValue();

        assertEquals("testuser", auditLog.getUsername());
        assertEquals("REGISTRATION_FAILED_DUPLICATE_USERNAME", auditLog.getEventType());
        assertFalse(auditLog.isSuccess());
        assertNotNull(auditLog.getTimestamp());
    }

    @Test
    void logEvent_shouldNotStoreSensitiveValues() {

        String description = "Password reset failed because the token is invalid";

        auditLogService.logFailure(
            null,
            "PASSWORD_RESET_INVALID_TOKEN",
            description
        );

        ArgumentCaptor<AuditLog> captor = ArgumentCaptor.forClass(AuditLog.class);
        verify(auditLogRepository).save(captor.capture());

        AuditLog auditLog = captor.getValue();

        assertNull(auditLog.getUsername());
        assertEquals("PASSWORD_RESET_INVALID_TOKEN", auditLog.getEventType());
        assertEquals(description, auditLog.getDescription());

        assertFalse(auditLog.getDescription().contains("secret-token"));
        assertFalse(auditLog.getDescription().contains("Password123"));
        assertFalse(auditLog.getDescription().contains("$2a$"));
    }
}
