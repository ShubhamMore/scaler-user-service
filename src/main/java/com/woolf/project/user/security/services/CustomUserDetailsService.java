package com.woolf.project.user.security.services;


import com.woolf.project.user.models.User;
import com.woolf.project.user.repositories.UserRepository;
import com.woolf.project.user.security.models.CustomUserDetails;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> userOptional = userRepository.findByEmail(username);
        if (userOptional.isEmpty()) {
            throw new UsernameNotFoundException("User by email: " + username + " doesn't exist.");
        }

        CustomUserDetails userDetails = new CustomUserDetails(userOptional.get());
        return userDetails;
    }
}
