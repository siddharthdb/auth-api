// src/main/java/com/enterprise/authapi/controller/SecurityAuditController.java
package com.enterprise.authapi.controller;

import com.enterprise.authapi.exception.ResourceNotFoundException;
import com.enterprise.authapi.model.RefreshToken;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.payload.ApiResponse;
import com.enterprise.authapi.repository.RefreshTokenRepository;
import com.enterprise.authapi.security.CookieUtils;
import com.enterprise.authapi.security.CurrentUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for security audit functions
 */
@Slf4j
@RestController
@RequestMapping("/api/security")
@RequiredArgsConstructor
public class SecurityAuditController {

    private final RefreshTokenRepository refreshTokenRepository;
    private final CookieUtils cookieUtils;

    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenDuration;

    /**
     * Get active sessions for current user
     *
     * @param user the authenticated user
     * @return list of active sessions
     */
    @GetMapping("/sessions")
    public ResponseEntity<List<Map<String, Object>>> getUserSessions(
            @CurrentUser User user,
            HttpServletRequest request) {
        log.debug("Fetching active sessions for user: {}", user.getUsername());

        List<RefreshToken> activeSessions = refreshTokenRepository.findByUser(user).stream()
                .filter(token -> !token.isRevoked() && token.getExpiryDate().isAfter(Instant.now()))
                .collect(Collectors.toList());

        String currentRefreshToken = null;
        Cookie refreshTokenCookie = cookieUtils.getCookieFromRequest(request, "refreshToken");
        if (refreshTokenCookie != null) {
            currentRefreshToken = refreshTokenCookie.getValue();
        }

        final String finalCurrentRefreshToken = currentRefreshToken;

        List<Map<String, Object>> sessionDtos = activeSessions.stream().map(token -> {
            Map<String, Object> sessionInfo = new HashMap<>();
            sessionInfo.put("id", token.getId());
            sessionInfo.put("ipAddress", token.getIpAddress());
            sessionInfo.put("userAgent", token.getUserAgent());
            // Calculate creation time by subtracting refresh token duration from expiry date
            Instant creationTime = token.getExpiryDate().minus(refreshTokenDuration, ChronoUnit.MILLIS);
            sessionInfo.put("createdAt", LocalDateTime.ofInstant(creationTime, ZoneId.systemDefault()).toString());
            sessionInfo.put("expiresAt", LocalDateTime.ofInstant(token.getExpiryDate(), ZoneId.systemDefault()).toString());
            sessionInfo.put("isCurrentSession", token.getToken().equals(finalCurrentRefreshToken));
            return sessionInfo;
        }).collect(Collectors.toList());

        return ResponseEntity.ok(sessionDtos);
    }

    /**
     * Revoke a specific session
     *
     * @param user the authenticated user
     * @param tokenId the ID of the session to revoke
     * @return operation result
     */
    @PostMapping("/sessions/{tokenId}/revoke")
    public ResponseEntity<ApiResponse> revokeSession(
            @CurrentUser User user,
            @PathVariable Long tokenId) {

        log.debug("Revoking session with ID {} for user: {}", tokenId, user.getUsername());

        RefreshToken token = refreshTokenRepository.findById(tokenId)
                .orElseThrow(() -> new ResourceNotFoundException("Session", "id", tokenId));

        // Security check - only allow users to revoke their own sessions
        if (!token.getUser().getId().equals(user.getId()) &&
                !hasAdminAuthority(SecurityContextHolder.getContext().getAuthentication())) {
            throw new AccessDeniedException("You can only revoke your own sessions");
        }

        token.setRevoked(true);
        refreshTokenRepository.save(token);

        log.info("Session revoked successfully: ID {}", tokenId);

        return ResponseEntity.ok(new ApiResponse(true, "Session revoked successfully"));
    }

    /**
     * Revoke all sessions for the current user except the current one
     *
     * @param user the authenticated user
     * @param request the HTTP request
     * @return operation result
     */
    @PostMapping("/sessions/revoke-all")
    public ResponseEntity<ApiResponse> revokeAllSessions(
            @CurrentUser User user,
            HttpServletRequest request) {

        log.debug("Revoking all sessions for user: {}", user.getUsername());

        String currentRefreshToken = null;
        Cookie refreshTokenCookie = cookieUtils.getCookieFromRequest(request, "refreshToken");
        if (refreshTokenCookie != null) {
            currentRefreshToken = refreshTokenCookie.getValue();
        }

        int revokedCount = 0;
        List<RefreshToken> userTokens = refreshTokenRepository.findByUser(user);
        for (RefreshToken token : userTokens) {
            // Skip the current session if requested
            if (currentRefreshToken == null || !token.getToken().equals(currentRefreshToken)) {
                token.setRevoked(true);
                refreshTokenRepository.save(token);
                revokedCount++;
            }
        }

        log.info("{} sessions revoked for user: {}", revokedCount, user.getUsername());

        return ResponseEntity.ok(new ApiResponse(true, revokedCount + " sessions revoked successfully"));
    }

    /**
     * Get security events for admin monitoring
     *
     * @param startDate optional start date for filtering
     * @param endDate optional end date for filtering
     * @return list of security events
     */
    @GetMapping("/events")
    @PreAuthorize("hasAuthority('ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> getSecurityEvents(
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

        log.debug("Fetching security events");

        // This would typically be implemented with a SecurityEvent entity and repository
        // For demonstration, we'll just return a mock response
        List<Map<String, Object>> events = List.of(
                createEvent(1L, "LOGIN_SUCCESS", "john.doe", "192.168.1.1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", LocalDateTime.now().minusDays(1)),
                createEvent(2L, "LOGIN_FAILURE", "unknown", "203.0.113.1", "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36", LocalDateTime.now().minusHours(2)),
                createEvent(3L, "PASSWORD_CHANGE", "jane.smith", "198.51.100.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", LocalDateTime.now().minusMinutes(30))
        );

        // Apply date filtering if provided
        List<Map<String, Object>> filteredEvents = events;
        if (startDate != null) {
            filteredEvents = filteredEvents.stream()
                    .filter(event -> {
                        LocalDateTime timestamp = (LocalDateTime) event.get("timestamp");
                        return timestamp.isAfter(startDate);
                    })
                    .collect(Collectors.toList());
        }
        if (endDate != null) {
            filteredEvents = filteredEvents.stream()
                    .filter(event -> {
                        LocalDateTime timestamp = (LocalDateTime) event.get("timestamp");
                        return timestamp.isBefore(endDate);
                    })
                    .collect(Collectors.toList());
        }

        return ResponseEntity.ok(filteredEvents);
    }

    // Helper methods

    private Map<String, Object> createEvent(Long id, String eventType, String username, String ipAddress, String userAgent, LocalDateTime timestamp) {
        Map<String, Object> event = new HashMap<>();
        event.put("id", id);
        event.put("eventType", eventType);
        event.put("username", username);
        event.put("ipAddress", ipAddress);
        event.put("userAgent", userAgent);
        event.put("timestamp", timestamp);
        return event;
    }

    private boolean hasAdminAuthority(Authentication authentication) {
        return authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ADMIN"));
    }
}