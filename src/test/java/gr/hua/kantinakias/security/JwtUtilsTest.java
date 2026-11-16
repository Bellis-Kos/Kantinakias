package gr.hua.kantinakias.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtUtilsTest {

    private static final String TEST_SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private static final long TOKEN_LIFETIME_MS = 60_000;

    private final JwtUtils jwtUtils = new JwtUtils(TEST_SECRET, TOKEN_LIFETIME_MS);

    @Test
    void generatesAndReadsValidToken() {
        UserDetails user = User.withUsername("alice")
                .password("unused")
                .authorities("ROLE_USER")
                .build();
        var authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());

        String token = jwtUtils.generateJwtToken(authentication);

        assertTrue(jwtUtils.validateJwtToken(token));
        assertEquals("alice", jwtUtils.getUserNameFromJwtToken(token));
    }

    @Test
    void rejectsTamperedAndMalformedTokens() {
        UserDetails user = User.withUsername("alice")
                .password("unused")
                .authorities("ROLE_USER")
                .build();
        var authentication = new UsernamePasswordAuthenticationToken(
                user, null, user.getAuthorities());
        String token = jwtUtils.generateJwtToken(authentication);
        String[] parts = token.split("\\.");
        parts[2] = (parts[2].charAt(0) == 'a' ? "b" : "a") + parts[2].substring(1);

        assertFalse(jwtUtils.validateJwtToken(String.join(".", parts)));
        assertFalse(jwtUtils.validateJwtToken("not-a-jwt"));
        assertFalse(jwtUtils.validateJwtToken(" "));
    }

    @Test
    void rejectsExpiredTokens() {
        var signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(TEST_SECRET));
        String expiredToken = Jwts.builder()
                .setSubject("alice")
                .setExpiration(Date.from(Instant.now().minusSeconds(1)))
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();

        assertFalse(jwtUtils.validateJwtToken(expiredToken));
    }

    @Test
    void requiresConfiguredSecretOfAtLeast32BytesBeforeSigning() {
        JwtUtils unconfigured = new JwtUtils("", TOKEN_LIFETIME_MS);
        var authentication = new UsernamePasswordAuthenticationToken("alice", null);
        JwtUtils weakSecret = new JwtUtils("c2hvcnQ=", TOKEN_LIFETIME_MS);

        assertThrows(IllegalStateException.class, () -> unconfigured.generateJwtToken(authentication));
        assertThrows(IllegalStateException.class, () -> weakSecret.generateJwtToken(authentication));
    }
}
