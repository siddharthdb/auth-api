package com.enterprise.authapi.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Optional;

/**
 * Handler for OAuth2 authentication failure
 * Extends SimpleUrlAuthenticationFailureHandler to customize the redirect after authentication failure
 */
@Component
@RequiredArgsConstructor
public class OAuth2AuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final CookieUtils cookieUtils;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        // Use the renamed method
        Cookie redirectUriCookie = cookieUtils.getCookieFromRequest(request, "redirect_uri");

        // Extract value safely
        String targetUrl = redirectUriCookie != null ? redirectUriCookie.getValue() : "/";

        targetUrl = UriComponentsBuilder.fromUriString(targetUrl)
                .queryParam("error", exception.getLocalizedMessage())
                .build().toUriString();

        cookieUtils.deleteCookie(request, response, "redirect_uri");
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}