// src/main/java/com/enterprise/authapi/service/RefreshTokenService.java
package com.enterprise.authapi.service;

import com.enterprise.authapi.exception.TokenRefreshException;
import com.enterprise.authapi.model.RefreshToken;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.repository.RefreshTokenRepository;
import com.enterprise.authapi.repository.UserRepository;
import com.enterprise.authapi.security.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Service for managing refresh tokens
 */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    @Value("${app.jwt.refresh-token-expiration}")
    private Long refreshTokenDuration;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtTokenProvider tokenProvider;

    /**
     * Create a new refresh token for a user
     *
     * @param user the user for whom to create a refresh token
     * @return the created refresh token
     */
    @Transactional
    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDuration))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Create a new refresh token for a user with device information
     *
     * @param user the user for whom to create a refresh token
     * @param request the HTTP request containing device information
     * @return the created refresh token
     */
    @Transactional
    public RefreshToken createRefreshToken(User user, HttpServletRequest request) {
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now().plusMillis(refreshTokenDuration))
                .ipAddress(getClientIp(request))
                .userAgent(request.getHeader("User-Agent"))
                .revoked(false)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Find a refresh token by its token value
     *
     * @param token the token value to search for
     * @return an Optional containing the refresh token if found
     */
    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    /**
     * Get all refresh tokens for a user
     *
     * @param user the user whose tokens to retrieve
     * @return a list of refresh tokens
     */
    public List<RefreshToken> findByUser(User user) {
        return refreshTokenRepository.findByUser(user);
    }

    /**
     * Verify that a refresh token is valid and not expired
     *
     * @param token the token to verify
     * @return the verified token
     * @throws TokenRefreshException if the token is invalid or expired
     */
    @Transactional
    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.isRevoked()) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was revoked. Please make a new signin request");
        }

        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException(token.getToken(), "Refresh token was expired. Please make a new signin request");
        }

        return token;
    }

    /**
     * Delete all refresh tokens for a user
     *
     * @param userId the ID of the user whose tokens to delete
     * @return the number of tokens deleted
     */
    @Transactional
    public int deleteByUserId(Long userId) {
        User user = userRepository.findById(userId).orElseThrow(
                () -> new RuntimeException("User not found with id: " + userId));
        return refreshTokenRepository.deleteByUser(user);
    }

    /**
     * Revoke all refresh tokens for a user
     *
     * @param user the user whose tokens to revoke
     */
    @Transactional
    public void revokeAllUserTokens(User user) {
        refreshTokenRepository.revokeAllUserTokens(user);
    }

    /**
     * Delete expired tokens from the database
     * Runs daily at midnight
     */
    @Scheduled(cron = "0 0 0 * * ?")
    @Transactional
    public void deleteExpiredTokens() {
        refreshTokenRepository.deleteAllExpiredTokens(Instant.now());
    }

    /**
     * Save a refresh token
     *
     * @param refreshToken the token to save
     * @return the saved token
     */
    @Transactional
    public RefreshToken save(RefreshToken refreshToken) {
        return refreshTokenRepository.save(refreshToken);
    }

    /**
     * Extract the client IP address from the request
     *
     * @param request the HTTP request
     * @return the client IP address
     */
    public String getClientIp(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        // In case of multiple proxies, first IP is the client IP
        if (ipAddress != null && ipAddress.contains(",")) {
            ipAddress = ipAddress.split(",")[0].trim();
        }
        return ipAddress;
    }
}