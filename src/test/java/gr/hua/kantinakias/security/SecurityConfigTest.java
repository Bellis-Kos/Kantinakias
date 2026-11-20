package gr.hua.kantinakias.security;

import gr.hua.kantinakias.entity.Role;
import gr.hua.kantinakias.entity.User;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityConfigTest {

    @Test
    void authenticationManagerUsesBcryptAndLoadsUserAuthorities() {
        SecurityConfig config = new SecurityConfig();
        PasswordEncoder passwordEncoder = config.passwordEncoder();
        User user = new User(
                "owner@example.com",
                passwordEncoder.encode("correct-password"),
                Role.OWNER);
        UserDetailsService userDetailsService = email -> user;
        DaoAuthenticationProvider provider =
                config.authenticationProvider(userDetailsService, passwordEncoder);
        AuthenticationManager authenticationManager = config.authenticationManager(provider);

        var authentication = authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        "owner@example.com", "correct-password"));

        assertEquals("owner@example.com", authentication.getName());
        assertEquals("ROLE_OWNER", authentication.getAuthorities().iterator().next().getAuthority());
        assertThrows(
                BadCredentialsException.class,
                () -> authenticationManager.authenticate(
                        UsernamePasswordAuthenticationToken.unauthenticated(
                                "owner@example.com", "wrong-password")));
    }
}
