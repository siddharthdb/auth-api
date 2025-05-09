package com.enterprise.authapi.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * Response object for authentication operations
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private boolean success;
    private String message;
    private Map<String, Object> data;

    public AuthResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
}