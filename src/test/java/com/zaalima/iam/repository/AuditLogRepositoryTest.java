package com.zaalima.iam.repository;

import com.zaalima.iam.entity.AuditLog;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class AuditLogRepositoryTest {

    @Autowired
    private AuditLogRepository auditLogRepository;

    @Test
    void shouldSaveAndRetrieveAuditLogsByUsername() {
        auditLogRepository.save(createLog(
            "vinay",
            "USER_REGISTERED",
            true,
            Instant.parse("2026-01-01T10:00:00Z")
        ));
        auditLogRepository.save(createLog(
            "vinay",
            "PASSWORD_RESET_SUCCESS",
            true,
            Instant.parse("2026-01-01T11:00:00Z")
        ));

        List<AuditLog> logs =
            auditLogRepository.findByUsernameOrderByTimestampDesc("vinay");

        assertThat(logs).hasSize(2);
        assertThat(logs.get(0).getEventType())
            .isEqualTo("PASSWORD_RESET_SUCCESS");
        assertThat(logs.get(1).getEventType())
            .isEqualTo("USER_REGISTERED");
    }

    @Test
    void shouldRetrieveAuditLogsByEventType() {
        auditLogRepository.save(createLog(
            "vinay",
            "USER_REGISTERED",
            true,
            Instant.parse("2026-01-01T10:00:00Z")
        ));
        auditLogRepository.save(createLog(
            "other-user",
            "USER_REGISTERED",
            true,
            Instant.parse("2026-01-01T11:00:00Z")
        ));

        List<AuditLog> logs =
            auditLogRepository.findByEventTypeOrderByTimestampDesc(
                "USER_REGISTERED"
            );

        assertThat(logs).hasSize(2);
        assertThat(logs.get(0).getUsername()).isEqualTo("other-user");
        assertThat(logs.get(1).getUsername()).isEqualTo("vinay");
    }

    @Test
    void shouldRetrieveAllAuditLogsInDescendingTimestampOrder() {
        auditLogRepository.save(createLog(
            "vinay",
            "USER_REGISTERED",
            true,
            Instant.parse("2026-01-01T10:00:00Z")
        ));
        auditLogRepository.save(createLog(
            "vinay",
            "PASSWORD_RESET_INVALID_TOKEN",
            false,
            Instant.parse("2026-01-01T12:00:00Z")
        ));

        List<AuditLog> logs =
            auditLogRepository.findAllByOrderByTimestampDesc();

        assertThat(logs).hasSize(2);
        assertThat(logs.get(0).isSuccess()).isFalse();
        assertThat(logs.get(1).isSuccess()).isTrue();
    }

    private AuditLog createLog(
            String username,
            String eventType,
            boolean success,
            Instant timestamp) {

        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(username);
        auditLog.setEventType(eventType);
        auditLog.setDescription("Test audit event");
        auditLog.setTimestamp(timestamp);
        auditLog.setSuccess(success);
        auditLog.setIpAddress(null);

        return auditLog;
    }
}
