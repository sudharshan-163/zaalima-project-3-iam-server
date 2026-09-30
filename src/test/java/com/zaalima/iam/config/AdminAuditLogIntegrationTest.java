package com.zaalima.iam.config;

import com.zaalima.iam.entity.AuditLog;
import com.zaalima.iam.repository.AuditLogRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.*;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class AdminAuditLogIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AuditLogRepository auditLogRepository;

    @BeforeEach
    void setUp() {
        auditLogRepository.deleteAll();
    }

    private AuditLog createAuditLog(
            String username,
            String eventType,
            String description,
            boolean success,
            String ipAddress,
            Instant timestamp) {
        AuditLog auditLog = new AuditLog();
        auditLog.setUsername(username);
        auditLog.setEventType(eventType);
        auditLog.setDescription(description);
        auditLog.setSuccess(success);
        auditLog.setIpAddress(ipAddress);
        auditLog.setTimestamp(timestamp);
        return auditLogRepository.save(auditLog);
    }

    @Test
    @DisplayName("Unauthenticated request should be rejected")
    void getAuditLogs_unauthenticated_shouldBeRejected() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser(username = "regular_user", authorities = {"ROLE_USER"})
    @DisplayName("Authenticated non-admin request should be forbidden")
    void getAuditLogs_nonAdminUser_shouldReturnForbidden() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Admin request should return 200 OK")
    void getAuditLogs_adminUser_shouldReturnOk() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Exact username filter should match only exact username")
    void getAuditLogs_usernameFilter_shouldReturnExactMatchOnly() throws Exception {
        createAuditLog("alice", "LOGIN", "Login event", true, "127.0.0.1", Instant.parse("2026-09-01T10:00:00Z"));
        createAuditLog("alice_extra", "LOGIN", "Other user", true, "127.0.0.1", Instant.parse("2026-09-01T11:00:00Z"));
        createAuditLog("bob", "LOGIN", "Bob login", true, "127.0.0.1", Instant.parse("2026-09-01T12:00:00Z"));

        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("username", "alice"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].username").value("alice"));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Exact eventType filter should match only exact eventType")
    void getAuditLogs_eventTypeFilter_shouldReturnExactMatchOnly() throws Exception {
        createAuditLog("user1", "USER_REGISTERED", "Register event", true, "127.0.0.1", Instant.parse("2026-09-01T10:00:00Z"));
        createAuditLog("user2", "USER_REGISTERED_MFA", "Other type", true, "127.0.0.1", Instant.parse("2026-09-01T11:00:00Z"));
        createAuditLog("user3", "LOGIN_SUCCESS", "Login event", true, "127.0.0.1", Instant.parse("2026-09-01T12:00:00Z"));

        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("eventType", "USER_REGISTERED"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].eventType").value("USER_REGISTERED"))
                .andExpect(jsonPath("$.content[0].username").value("user1"));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Combined username and eventType filters should filter conjunctively")
    void getAuditLogs_combinedFilters_shouldReturnConjunctiveMatch() throws Exception {
        createAuditLog("alice", "LOGIN_SUCCESS", "Alice login", true, "127.0.0.1", Instant.parse("2026-09-01T10:00:00Z"));
        createAuditLog("alice", "LOGOUT", "Alice logout", true, "127.0.0.1", Instant.parse("2026-09-01T11:00:00Z"));
        createAuditLog("bob", "LOGIN_SUCCESS", "Bob login", true, "127.0.0.1", Instant.parse("2026-09-01T12:00:00Z"));

        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("username", "alice")
                        .param("eventType", "LOGIN_SUCCESS"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content", hasSize(1)))
                .andExpect(jsonPath("$.content[0].username").value("alice"))
                .andExpect(jsonPath("$.content[0].eventType").value("LOGIN_SUCCESS"));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Results are sorted by timestamp DESC and id DESC tie-breaker")
    void getAuditLogs_sorting_shouldSortByTimestampDescThenIdDesc() throws Exception {
        Instant t1 = Instant.parse("2026-09-01T10:00:00Z");
        Instant t2 = Instant.parse("2026-09-01T12:00:00Z");
        Instant t3 = Instant.parse("2026-09-01T14:00:00Z");

        AuditLog logOldest = createAuditLog("u1", "EV1", "oldest", true, "127.0.0.1", t1);
        AuditLog logMidTie1 = createAuditLog("u2", "EV2", "mid-tie-1", true, "127.0.0.1", t2);
        AuditLog logMidTie2 = createAuditLog("u3", "EV3", "mid-tie-2", true, "127.0.0.1", t2);
        AuditLog logNewest = createAuditLog("u4", "EV4", "newest", true, "127.0.0.1", t3);

        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(4)))
                .andExpect(jsonPath("$.content[0].id").value(logNewest.getId()))
                .andExpect(jsonPath("$.content[1].id").value(logMidTie2.getId()))
                .andExpect(jsonPath("$.content[2].id").value(logMidTie1.getId()))
                .andExpect(jsonPath("$.content[3].id").value(logOldest.getId()));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Default pagination should be page 0 and size 20")
    void getAuditLogs_defaultPagination_shouldDefaultToPageZeroAndSizeTwenty() throws Exception {
        for (int i = 1; i <= 25; i++) {
            createAuditLog("user" + i, "EVENT", "desc", true, "127.0.0.1", Instant.parse("2026-09-01T10:00:00Z").plusSeconds(i));
        }

        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.totalElements").value(25))
                .andExpect(jsonPath("$.totalPages").value(2))
                .andExpect(jsonPath("$.first").value(true))
                .andExpect(jsonPath("$.last").value(false))
                .andExpect(jsonPath("$.content", hasSize(20)));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Explicit page and size parameters should work correctly")
    void getAuditLogs_explicitPagination_shouldReturnRequestedSlice() throws Exception {
        for (int i = 1; i <= 15; i++) {
            createAuditLog("user" + i, "EVENT", "desc", true, "127.0.0.1", Instant.parse("2026-09-01T10:00:00Z").plusSeconds(i));
        }

        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("page", "1")
                        .param("size", "5"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(1))
                .andExpect(jsonPath("$.size").value(5))
                .andExpect(jsonPath("$.totalElements").value(15))
                .andExpect(jsonPath("$.totalPages").value(3))
                .andExpect(jsonPath("$.first").value(false))
                .andExpect(jsonPath("$.last").value(false))
                .andExpect(jsonPath("$.content", hasSize(5)));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Negative page parameter should return 400 Bad Request")
    void getAuditLogs_negativePage_shouldReturnBadRequest() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("page", "-1"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Size less than 1 should return 400 Bad Request")
    void getAuditLogs_sizeBelowOne_shouldReturnBadRequest() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("size", "0"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Size greater than 100 should return 400 Bad Request")
    void getAuditLogs_sizeAboveMax_shouldReturnBadRequest() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs")
                        .param("size", "101"))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Empty repository returns valid empty page response structure")
    void getAuditLogs_emptyResults_shouldReturnValidEmptyPageResponse() throws Exception {
        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(0)))
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(20))
                .andExpect(jsonPath("$.totalElements").value(0))
                .andExpect(jsonPath("$.totalPages").value(0))
                .andExpect(jsonPath("$.first").value(true))
                .andExpect(jsonPath("$.last").value(true));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Response and item fields strictly match agreed contract schema")
    void getAuditLogs_contractFields_shouldMatchExactSpecification() throws Exception {
        AuditLog saved = createAuditLog(
                "contract_user",
                "PASSWORD_CHANGE",
                "Password changed successfully",
                true,
                "192.168.1.1",
                Instant.parse("2026-09-01T12:30:00Z")
        );

        mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray())
                .andExpect(jsonPath("$.page").isNumber())
                .andExpect(jsonPath("$.size").isNumber())
                .andExpect(jsonPath("$.totalElements").isNumber())
                .andExpect(jsonPath("$.totalPages").isNumber())
                .andExpect(jsonPath("$.first").isBoolean())
                .andExpect(jsonPath("$.last").isBoolean())
                .andExpect(jsonPath("$.content[0].id").value(saved.getId()))
                .andExpect(jsonPath("$.content[0].username").value("contract_user"))
                .andExpect(jsonPath("$.content[0].eventType").value("PASSWORD_CHANGE"))
                .andExpect(jsonPath("$.content[0].description").value("Password changed successfully"))
                .andExpect(jsonPath("$.content[0].timestamp").value("2026-09-01T12:30:00Z"))
                .andExpect(jsonPath("$.content[0].success").value(true))
                .andExpect(jsonPath("$.content[0].ipAddress").value("192.168.1.1"));
    }

    @Test
    @WithMockUser(username = "admin_user", authorities = {"ROLE_ADMIN"})
    @DisplayName("Response must not expose passwords, tokens, OTPs, or secrets")
    void getAuditLogs_sensitiveData_shouldNeverBeExposed() throws Exception {
        createAuditLog(
                "secret_user",
                "LOGIN_SUCCESS",
                "User logged in",
                true,
                "10.0.0.1",
                Instant.parse("2026-09-01T12:00:00Z")
        );

        String responseBody = mockMvc.perform(get("/api/admin/audit-logs"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        Pattern sensitivePattern = Pattern.compile(
                "(?i)\"(password|passwordHash|hash|secret|token|accessToken|refreshToken|otp|bearer)\"\\s*:"
        );
        assertFalse(
                sensitivePattern.matcher(responseBody).find(),
                "Response JSON exposes sensitive field names: " + responseBody
        );
    }
}