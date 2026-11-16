package gr.hua.kantinakias.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;

@Component
public class JwtUtils {

    private final String jwtSecret;
    private final long jwtExpirationMs;

    public JwtUtils(
            @Value("${app.jwt.secret:}") String jwtSecret,
            @Value("${app.jwt.expiration-ms:86400000}") long jwtExpirationMs) {
        if (jwtExpirationMs <= 0) {
            throw new IllegalArgumentException("JWT expiration must be greater than zero.");
        }
        this.jwtSecret = jwtSecret;
        this.jwtExpirationMs = jwtExpirationMs;
    }

    public String generateJwtToken(Authentication authentication) {
        Objects.requireNonNull(authentication, "authentication must not be null");
        Instant issuedAt = Instant.now();

        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(issuedAt.plusMillis(jwtExpirationMs)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        if (authToken == null || authToken.isBlank()) {
            return false;
        }

        Key signingKey = getSigningKey();
        try {
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(authToken);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    private Key getSigningKey() {
        if (jwtSecret == null || jwtSecret.isBlank()) {
            throw new IllegalStateException(
                    "JWT secret is not configured. Set app.jwt.secret to a Base64-encoded key of at least 32 bytes.");
        }

        final byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(jwtSecret);
        } catch (DecodingException e) {
            throw new IllegalStateException("app.jwt.secret must be valid Base64.", e);
        }
        if (keyBytes.length < 32) {
            throw new IllegalStateException("app.jwt.secret must decode to at least 32 bytes for HS256.");
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
