package com.satyatmawinarga.todoApp.user;

import com.satyatmawinarga.todoApp.jwt.*;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private static final Logger log = LoggerFactory.getLogger(UserController.class);
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("")
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/register")
    public ResponseEntity<?> create(@Valid @RequestBody CreateUser user) {
        log.info("Creating user: {}", user.username());
        try {
            if (userRepository.findByUsername(user.username()).isPresent()) {
                return ResponseEntity.status(HttpStatus.CONFLICT)
                        .body("Username already exists");
            }
            userRepository.save(User.builder()
                    .username(user.username())
                    .password(passwordEncoder.encode(user.password()))
                    .roles(List.of("USER"))
                    .build());
            return ResponseEntity.ok(HttpStatus.CREATED);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails.getUsername());

        // generate and store refresh token in db
        RefreshToken refreshToken = RefreshToken.builder()
                .username(userDetails.getUsername())
                .token(UUID.randomUUID().toString())
                .expiryDate(Instant.now()
                        .plusMillis(jwtUtils.getRefreshJwtExpirationMs()))
                .build();
        refreshTokenRepository.save(refreshToken);

        // store access token in cookie
        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", jwtToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(jwtUtils.getJwtExpirationMs() / 1000)
                .build();

        // store refresh token in cookie
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken",
                        refreshToken.getToken())
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(jwtUtils.getRefreshJwtExpirationMs() / 1000)
                .build();

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse responseBody = new LoginResponse(userDetails.getUsername(), roles,
                jwtToken, refreshToken.getToken());

        return new ResponseEntity<LoginResponse>(responseBody, responseHeaders,
                HttpStatus.OK);
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@CookieValue("refreshToken") String refreshToken) {
        log.debug("Logging out user with refresh token: {}", refreshToken);
        List<RefreshToken> refreshTokens =
                refreshTokenRepository.deleteByToken(refreshToken);
        log.debug("Deleted refresh tokens: {}", refreshTokens);

        if (refreshTokens.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid refresh token");
        }

        // clear cookies
        ResponseCookie accessTokenCookie = ResponseCookie.from("accessToken", "deleted")
                .path("/")
                .maxAge(0)
                .build();
        ResponseCookie refreshTokenCookie = ResponseCookie.from("refreshToken", "deleted")
                .path("/")
                .maxAge(0)
                .build();

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.add(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        responseHeaders.add(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return new ResponseEntity<>("Logout successful", responseHeaders, HttpStatus.OK);
    }
}
