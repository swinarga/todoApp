package com.satyatmawinarga.todoApp.jwt;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

@RestController
@RequestMapping("/api/refreshToken")
public class RefreshTokenController {
    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    JwtUtils jwtUtils;

    /**
     * Generate new access token given a valid refresh token
     *
     * @param refreshTokenRequest
     * @return
     */
    @PostMapping("")
    public ResponseEntity<?> refreshToken(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        RefreshToken validRefreshToken =
                validateRefreshToken(refreshTokenRequest.refreshToken());

        String username = validRefreshToken.getUsername();

        // generate new access token
        String accessToken = jwtUtils.generateTokenFromUsername(username);

        // store access token in cookie
        ResponseCookie cookie = ResponseCookie.from("accessToken",
                        accessToken)
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(jwtUtils.getJwtExpirationMs() / 1000)
                .build();

        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set(HttpHeaders.SET_COOKIE, cookie.toString());

        RefreshTokenResponse refreshTokenResponse = new RefreshTokenResponse(
                accessToken,
                refreshTokenRequest.refreshToken()
        );

        return new ResponseEntity<>(refreshTokenResponse, responseHeaders,
                HttpStatus.OK
        );
    }

    public RefreshToken validateRefreshToken(String refreshToken) throws RefreshTokenNotFoundException {
        return refreshTokenService.findByToken(refreshToken)
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(RefreshTokenNotFoundException::new);
    }

}
