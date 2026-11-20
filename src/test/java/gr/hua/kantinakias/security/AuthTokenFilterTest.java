package gr.hua.kantinakias.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthTokenFilterTest {

    private static final String TEST_SECRET = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
    private final JwtUtils jwtUtils = new JwtUtils(TEST_SECRET, 60_000);
    private final UserDetailsService userDetailsService = username ->
            User.withUsername(username)
                    .password("unused")
                    .authorities("ROLE_CUSTOMER")
                    .build();
    private final AuthTokenFilter filter = new AuthTokenFilter(jwtUtils, userDetailsService);

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void authenticatesValidBearerToken() throws Exception {
        String token = jwtUtils.generateJwtToken(
                new UsernamePasswordAuthenticationToken("alice", null));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        var authentication = SecurityContextHolder.getContext().getAuthentication();
        assertTrue(authentication.isAuthenticated());
        assertEquals("alice", authentication.getName());
        assertEquals("ROLE_CUSTOMER", authentication.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    void leavesRequestUnauthenticatedForInvalidOrMissingBearerToken() throws Exception {
        MockHttpServletRequest invalidRequest = new MockHttpServletRequest();
        invalidRequest.addHeader(HttpHeaders.AUTHORIZATION, "Bearer invalid");

        filter.doFilter(invalidRequest, new MockHttpServletResponse(), new MockFilterChain());
        assertNull(SecurityContextHolder.getContext().getAuthentication());

        SecurityContextHolder.clearContext();
        filter.doFilter(
                new MockHttpServletRequest(),
                new MockHttpServletResponse(),
                new MockFilterChain());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void rejectsTokenWhenItsUserNoLongerExists() throws Exception {
        UserDetailsService missingUserService = username -> {
            throw new UsernameNotFoundException("User not found.");
        };
        AuthTokenFilter missingUserFilter = new AuthTokenFilter(jwtUtils, missingUserService);
        String token = jwtUtils.generateJwtToken(
                new UsernamePasswordAuthenticationToken("deleted@example.com", null));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
        MockHttpServletResponse response = new MockHttpServletResponse();

        missingUserFilter.doFilter(request, response, new MockFilterChain());

        assertEquals(401, response.getStatus());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }
}
