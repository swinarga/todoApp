// https://github.com/EmbarkXOfficial/Spring-Security-Course/blob/main/src/main/java/com/example/securitydemo/jwt/AuthTokenFilter.java
package com.satyatmawinarga.todoApp.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

/**
 * AuthTokenFilter
 * Filters incoming requests to check for a valid JWT in the header
 * and sets the authentication context if the token is valid.
 * Extracts JWT from request header, validates it, and configures the Spring
 * Security context with user details if the token is valid.
 */
@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private RefreshTokenService refreshTokenService;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());

        if (request.getRequestURI().equals("/api/users/register")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = parseJwt(request);
        // if null either the token is not present or expired
        if (jwt == null) {
            logger.debug("JWT is null");
            // if expired, check if refresh token is present and valid
            Cookie refreshTokenCookie = WebUtils.getCookie(request, "refreshToken");
            String refreshToken = refreshTokenCookie != null ?
                    refreshTokenCookie.getValue() : null;

            // refresh token is not present, continue to the next filter
            if (refreshToken == null) {
                logger.debug("Refresh token is null");
                filterChain.doFilter(request, response);
                return;
            }
            // handle expired access token
            handleExpiredJwt(request, response, refreshToken);
        } else {
            try {
                if (jwtUtils.validateJwtToken(jwt)) {
                    String username = jwtUtils.getUserNameFromJwtToken(jwt);
                    setAuthentication(username, request);
                }
            } catch (Exception e) {
                logger.error("Cannot set user authentication: {}", e);
            }
        }

        filterChain.doFilter(request, response); // continue to the next filter
    }

    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromCookie(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }

    private void setAuthentication(String username, HttpServletRequest request) {
        try {
            // set user authentication
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userDetails,
                            null,
                            userDetails.getAuthorities());
            logger.debug("Roles from JWT: {}", userDetails.getAuthorities());

            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
    }

    private void handleExpiredJwt(HttpServletRequest request,
                                  HttpServletResponse response, String refreshToken) {
        try {
            logger.debug("validating refresh token");
            RefreshToken validRefreshToken =
                    refreshTokenService.validateRefreshToken(refreshToken);
            // generate new access token
            String username = validRefreshToken.getUsername();
            String accessToken = jwtUtils.generateTokenFromUsername(username);

            // store access token in cookie
            ResponseCookie cookie = ResponseCookie.from("accessToken",
                            accessToken)
                    .httpOnly(true)
                    .secure(true)
                    .path("/")
                    .maxAge(jwtUtils.getJwtExpirationMs() / 1000)
                    .build();

            response.addHeader("Set-Cookie", cookie.toString());

            // set user authentication
            setAuthentication(username, request);
        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }
    }
}
