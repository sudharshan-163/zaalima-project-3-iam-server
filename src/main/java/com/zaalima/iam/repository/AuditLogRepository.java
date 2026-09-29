package com.zaalima.iam.repository;

import com.zaalima.iam.entity.AuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    List<AuditLog> findByUsernameOrderByTimestampDesc(String username);

    List<AuditLog> findByEventTypeOrderByTimestampDesc(String eventType);

    List<AuditLog> findAllByOrderByTimestampDesc();

    @Query("""
            SELECT a
            FROM AuditLog a
            WHERE (:username IS NULL OR a.username = :username)
              AND (:eventType IS NULL OR a.eventType = :eventType)
            """)
    Page<AuditLog> findFiltered(
            @Param("username") String username,
            @Param("eventType") String eventType,
            Pageable pageable);
}
