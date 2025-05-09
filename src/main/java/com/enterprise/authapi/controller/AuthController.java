// src/main/java/com/enterprise/authapi/controller/AuthController.java
package com.enterprise.authapi.controller;

import com.enterprise.authapi.exception.TokenRefreshException;
import com.enterprise.authapi.model.AuthProvider;
import com.enterprise.authapi.model.RefreshToken;
import com.enterprise.authapi.model.Role;
import com.enterprise.authapi.model.User;
import com.enterprise.authapi.payload.ApiResponse;
import com.enterprise.authapi.payload.AuthResponse;
import com.enterprise.authapi.payload.LoginRequest;
import com.enterprise.authapi.payload.SignUpRequest;
import com.enterprise.authapi.repository.RoleRepository;
import com.enterprise.authapi.repository.UserRepository;
import com.enterprise.authapi.security.CookieUtils;
import com.enterprise.authapi.security.JwtTokenProvider;
import com.enterprise.authapi.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Controller for handling authentication operations
 */
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider tokenProvider;
    private final RefreshTokenService refreshTokenService;
    private final CookieUtils cookieUtils;

    /**
     * Authenticate user and generate access and refresh tokens
     *
     * @param loginRequest login credentials
     * @param response HTTP response to add cookies
     * @return response with authentication status
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                              HttpServletRequest request,
                                              HttpServletResponse response) {
        log.info("Authentication attempt for user: {}", loginRequest.getUsername());

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = (User) authentication.getPrincipal();

        // Create tokens
        String accessToken = tokenProvider.generateAccessToken(authentication);
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, request);

        // Add cookies
        cookieUtils.addAccessTokenCookie(response, accessToken);
        cookieUtils.addRefreshTokenCookie(response, refreshToken.getToken());

        // Log the successful login
        log.info("User {} successfully authenticated", user.getUsername());

        Map<String, Object> responseData = new HashMap<>();
        responseData.put("userId", user.getId());
        responseData.put("username", user.getUsername());
        responseData.put("email", user.getEmail());
        responseData.put("roles", user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet()));

        return ResponseEntity.ok(new AuthResponse(true, "Login successful", responseData));
    }

    /**
     * Refresh the access token using a refresh token
     *
     * @param request HTTP request containing the refresh token cookie
     * @param response HTTP response to update cookies
     * @return response with new access token
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        log.debug("Token refresh request received");

        Cookie refreshTokenCookie = cookieUtils.getCookieFromRequest(request, "refreshToken");

        if (refreshTokenCookie == null) {
            log.warn("Refresh token not found in request");
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, "Refresh token not found"));
        }

        String requestRefreshToken = refreshTokenCookie.getValue();

        try {
            return refreshTokenService.findByToken(requestRefreshToken)
                    .map(refreshTokenService::verifyExpiration)
                    .map(RefreshToken::getUser)
                    .map(user -> {
                        String accessToken = tokenProvider.generateAccessToken(user);
                        cookieUtils.addAccessTokenCookie(response, accessToken);

                        log.debug("Access token refreshed for user: {}", user.getUsername());

                        return ResponseEntity.ok(new AuthResponse(true, "Token refreshed successfully"));
                    })
                    .orElseThrow(() -> new TokenRefreshException(requestRefreshToken, "Refresh token not found"));
        } catch (TokenRefreshException ex) {
            log.warn("Token refresh failed: {}", ex.getMessage());
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, ex.getMessage()));
        }
    }

    /**
     * Register a new user
     *
     * @param signUpRequest user registration data
     * @return response with registration status
     */
    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        log.info("New user registration attempt: {}", signUpRequest.getUsername());

        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            log.warn("Username {} is already taken", signUpRequest.getUsername());
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Username is already taken"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            log.warn("Email {} is already in use", signUpRequest.getEmail());
            return ResponseEntity
                    .badRequest()
                    .body(new ApiResponse(false, "Email is already in use"));
        }

        // Create user
        User user = new User();
        user.setUsername(signUpRequest.getUsername());
        user.setEmail(signUpRequest.getEmail());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setFirstName(signUpRequest.getFirstName());
        user.setLastName(signUpRequest.getLastName());
        user.setPhoneNumber(signUpRequest.getPhoneNumber());
        user.setProvider(AuthProvider.LOCAL);

        // Assign default role
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("Default role not found"));
        user.setRoles(Collections.singleton(userRole));

        userRepository.save(user);

        log.info("User registered successfully: {}", user.getUsername());

        return ResponseEntity.ok(new ApiResponse(true, "User registered successfully"));
    }

    /**
     * Logout a user by invalidating tokens
     *
     * @param request HTTP request containing the refresh token cookie
     * @param response HTTP response to delete cookies
     * @return response with logout status
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        String username = auth != null && auth.isAuthenticated() ? auth.getName() : "unknown";
        log.info("Logout request for user: {}", username);

        Cookie refreshTokenCookie = cookieUtils.getCookieFromRequest(request, "refreshToken");

        if (refreshTokenCookie != null) {
            String refreshToken = refreshTokenCookie.getValue();
            refreshTokenService.findByToken(refreshToken)
                    .ifPresent(token -> {
                        // Revoke refresh token
                        token.setRevoked(true);
                        refreshTokenService.save(token);
                        log.debug("Refresh token revoked for user: {}", token.getUser().getUsername());
                    });
        }

        // Delete cookies
        cookieUtils.deleteCookie(request, response, "accessToken");
        cookieUtils.deleteCookie(request, response, "refreshToken");

        SecurityContextHolder.clearContext();

        log.info("User logged out successfully");

        return ResponseEntity.ok(new ApiResponse(true, "Logged out successfully"));
    }

    /**
     * Get current user information
     *
     * @param request HTTP request
     * @return response with user details
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated() ||
                authentication.getPrincipal().equals("anonymousUser")) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body(new ApiResponse(false, "User not authenticated"));
        }

        User user = (User) authentication.getPrincipal();

        Map<String, Object> userData = new HashMap<>();
        userData.put("id", user.getId());
        userData.put("username", user.getUsername());
        userData.put("email", user.getEmail());
        userData.put("firstName", user.getFirstName());
        userData.put("lastName", user.getLastName());
        userData.put("phoneNumber", user.getPhoneNumber());
        userData.put("roles", user.getRoles().stream()
                .map(Role::getName)
                .collect(Collectors.toSet()));

        return ResponseEntity.ok(userData);
    }
}