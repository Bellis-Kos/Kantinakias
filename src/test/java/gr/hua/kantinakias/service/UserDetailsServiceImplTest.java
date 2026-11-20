package gr.hua.kantinakias.service;

import gr.hua.kantinakias.entity.Role;
import gr.hua.kantinakias.entity.User;
import gr.hua.kantinakias.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UserDetailsServiceImplTest {

    @Test
    void loadsUserByEmailWithItsAuthorities() {
        UserRepository userRepository = mock(UserRepository.class);
        User user = new User("owner@example.com", "bcrypt-hash", Role.OWNER);
        when(userRepository.findByEmail("owner@example.com")).thenReturn(Optional.of(user));

        var userDetails = new UserDetailsServiceImpl(userRepository)
                .loadUserByUsername("owner@example.com");

        assertSame(user, userDetails);
        assertEquals("owner@example.com", userDetails.getUsername());
        assertEquals("ROLE_OWNER", userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    void throwsWhenEmailIsNotRegistered() {
        UserRepository userRepository = mock(UserRepository.class);
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        assertThrows(
                UsernameNotFoundException.class,
                () -> new UserDetailsServiceImpl(userRepository)
                        .loadUserByUsername("missing@example.com"));
    }
}
