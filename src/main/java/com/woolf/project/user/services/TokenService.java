package com.woolf.project.user.services;

import com.woolf.project.user.models.Token;
import com.woolf.project.user.models.User;
import com.woolf.project.user.repositories.TokenRepository;
import com.woolf.project.user.repositories.UserRepository;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.ZoneId;
import java.util.Date;
import java.util.Optional;

@Service
public class TokenService {

    private TokenRepository tokenRepository;
    private UserRepository userRepository;
    private PasswordEncoder bcryptPasswordEncoder;

    public TokenService(TokenRepository tokenRepository, UserRepository userRepository,
                        BCryptPasswordEncoder bcryptPasswordEncoder) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.bcryptPasswordEncoder = bcryptPasswordEncoder;
    }

    public Token login(String email, String password)
    {
        //1. Verify if the user exists
        Optional<User> user = userRepository.findByEmail(email);

        if(user.isEmpty()) {
            throw new UsernameNotFoundException("User not found for email: " + email);
        }

        //2. Verify the password
        if(!bcryptPasswordEncoder.matches(password, user.get().getHashedPassword()))
        {
            throw new BadCredentialsException("Bad credentials");
        }

        //3. Generate token
        Token token = generateToken(user.get());
        return tokenRepository.save(token);
    }

    public User validateToken(String tokenValue)
    {
        Optional<Token> token = tokenRepository.findByTokenValueAndExpiryDateGreaterThan(tokenValue, new Date());
        if(token.isEmpty())
        {
            throw new BadCredentialsException("Invalid token");
        }
        return token.get().getUser();
    }
    private Token generateToken(User user) {
        Token token = new Token();
        token.setUser(user);
        token.setTokenValue(RandomStringUtils.randomAlphanumeric(15));
        LocalDate currentDate = LocalDate.now();
        LocalDate thirtyDaysLater = currentDate.plusDays(30);
        Date expiryDate = Date.from(thirtyDaysLater.atStartOfDay(ZoneId.systemDefault()).toInstant());
        token.setExpiryDate(expiryDate);
        return token;
    }
}
