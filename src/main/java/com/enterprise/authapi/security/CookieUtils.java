// src/main/java/com/enterprise/authapi/security/CookieUtils.java
package com.enterprise.authapi.security;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.SerializationUtils;

import java.util.Base64;
import java.util.Optional;

@Component
public class CookieUtils {

    @Value("${app.cookie.secure}")
    private boolean secure;

    @Value("${app.cookie.http-only}")
    private boolean httpOnly;

    @Value("${app.cookie.same-site}")
    private String sameSite;

    @Value("${app.cookie.max-age-access}")
    private int maxAgeAccess;

    @Value("${app.cookie.max-age-refresh}")
    private int maxAgeRefresh;

    public void addAccessTokenCookie(HttpServletResponse response, String token) {
        createCookie(response, "accessToken", token, maxAgeAccess);
    }

    public void addRefreshTokenCookie(HttpServletResponse response, String token) {
        createCookie(response, "refreshToken", token, maxAgeRefresh);
    }

    public void createCookie(HttpServletResponse response, String name, String value, int maxAge) {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(secure);
        cookie.setMaxAge(maxAge);

        response.addHeader("Set-Cookie", String.format("%s=%s; Max-Age=%d; Path=/; %sHttpOnly; SameSite=%s",
                name,
                value,
                maxAge,
                secure ? "Secure; " : "",
                sameSite));
    }

    public void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    cookie.setValue("");
                    cookie.setPath("/");
                    cookie.setMaxAge(0);
                    response.addCookie(cookie);
                    break;
                }
            }
        }
    }

    // Renamed method to avoid ambiguity
    public Cookie getCookieFromRequest(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return cookie;
                }
            }
        }
        return null;
    }

    // Renamed method to avoid ambiguity
    public Optional<Cookie> getOptionalCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie);
                }
            }
        }
        return Optional.empty();
    }

    public String serialize(Object object) {
        return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(object));
    }

    public <T> T deserialize(Cookie cookie, Class<T> cls) {
        return cls.cast(SerializationUtils.deserialize(
                Base64.getUrlDecoder().decode(cookie.getValue())));
    }
}