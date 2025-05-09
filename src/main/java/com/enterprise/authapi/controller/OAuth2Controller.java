package com.enterprise.authapi.controller;

import com.enterprise.authapi.security.CookieUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Controller to handle OAuth2 related endpoints
 */
@RestController
@RequestMapping("/api/auth/oauth2")
@RequiredArgsConstructor
public class OAuth2Controller {

    private final CookieUtils cookieUtils;

    /**
     * Endpoint to store the redirect URI in a cookie before starting the OAuth2 authorization flow
     */
    @GetMapping("/authorize")
    public void authorizeOAuth2(@RequestParam("redirect_uri") String redirectUri,
                                @RequestParam("provider") String provider,
                                HttpServletRequest request,
                                HttpServletResponse response) throws Exception {

        // Store the redirect_uri in a cookie for the OAuth2 success/failure handlers
        cookieUtils.createCookie(response, "redirect_uri", redirectUri, 180);

        // Redirect to the OAuth2 authorization endpoint
        String authorizationUri = UriComponentsBuilder.fromPath("/oauth2/authorization/{provider}")
                .buildAndExpand(provider)
                .toUriString();

        response.sendRedirect(authorizationUri);
    }
}