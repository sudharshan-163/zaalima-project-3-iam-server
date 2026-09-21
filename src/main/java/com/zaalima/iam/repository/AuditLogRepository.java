package com.zaalima.iam.repository;

import com.zaalima.iam.entity.AuditLog;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByUsernameOrderByTimestampDesc(String username);

    List<AuditLog> findByEventTypeOrderByTimestampDesc(String eventType);

    List<AuditLog> findAllByOrderByTimestampDesc();
}
