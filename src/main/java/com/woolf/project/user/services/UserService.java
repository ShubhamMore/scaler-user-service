package com.woolf.project.user.services;

import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.models.Address;
import com.woolf.project.user.models.User;
import com.woolf.project.user.repositories.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private BCryptPasswordEncoder bcryptpasswordencoder;
    private UserRepository userRepository;
    public UserService(UserRepository userRepository, BCryptPasswordEncoder bcryptpasswordencoder) {
        this.userRepository = userRepository;
        this.bcryptpasswordencoder = bcryptpasswordencoder;
    }

    public User createUser(String email, String password, String name, String street,
                           String city, String state, String zip, String country) throws UserAlreadyExistException {

        //1. Verify if the user exists
        Optional<User> user = userRepository.findByEmail(email);
        if(!user.isEmpty()) {
            throw new UserAlreadyExistException("User already present: " + email);
        }

        Address address = new Address();
        address.setStreet(street);
        address.setCity(city);
        address.setState(state);
        address.setZipcode(zip);
        address.setCountry(country);

        User newUser = new User();
        newUser.setUsername(name);
        newUser.setEmail(email);
        newUser.setUsername(name);
        newUser.setHashedPassword(bcryptpasswordencoder.encode(password));
        newUser.setAddress(address);
        return userRepository.save(newUser);
    }

}
