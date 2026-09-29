package com.zaalima.iam.controller;

import com.zaalima.iam.dto.AuditLogPageResponse;
import com.zaalima.iam.dto.AuditLogResponse;
import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.service.AuditLogService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@RestController
@RequestMapping("/api/admin/audit-logs")
@RequiredArgsConstructor
public class AuditLogController {

    private static final int DEFAULT_PAGE = 0;
    private static final int DEFAULT_SIZE = 20;
    private static final int MAX_SIZE = 100;

    private final AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<AuditLogPageResponse> getAuditLogs(
            @RequestParam(required = false) String username,
            @RequestParam(required = false) String eventType,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        if (page < 0) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "page must be zero or greater");
        }

        if (size < 1 || size > MAX_SIZE) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "size must be between 1 and 100");
        }

        Pageable pageable = PageRequest.of(
                page,
                size,
                Sort.by(
                        Sort.Order.desc("timestamp"),
                        Sort.Order.desc("id")
                )
        );

        Page<AuditLog> auditLogPage =
                auditLogService.getAuditLogs(username, eventType, pageable);

        List<AuditLogResponse> content = auditLogPage.getContent()
                .stream()
                .map(AuditLogResponse::from)
                .toList();

        AuditLogPageResponse response = new AuditLogPageResponse(
                content,
                auditLogPage.getNumber(),
                auditLogPage.getSize(),
                auditLogPage.getTotalElements(),
                auditLogPage.getTotalPages(),
                auditLogPage.isFirst(),
                auditLogPage.isLast()
        );

        return ResponseEntity.ok(response);
    }
}
