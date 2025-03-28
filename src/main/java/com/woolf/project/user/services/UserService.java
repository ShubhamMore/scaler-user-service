package com.woolf.project.user.services;

import com.woolf.project.user.dtos.ResetPasswordDTO;
import com.woolf.project.user.dtos.SignUpRequestDTO;
import com.woolf.project.user.exception.InvalidDataException;
import com.woolf.project.user.exception.PasswordInvalidException;
import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.models.Address;
import com.woolf.project.user.models.Role;
import com.woolf.project.user.models.User;
import com.woolf.project.user.repositories.RoleRepository;
import com.woolf.project.user.repositories.UserRepository;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UserService {

    private final String PASSWORD_REGEX =
            "^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$";

    private final Pattern pattern = Pattern.compile(PASSWORD_REGEX);

    private BCryptPasswordEncoder bcryptpasswordencoder;
    private UserRepository userRepository;
    private RoleRepository roleRepository;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bcryptpasswordencoder,RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.bcryptpasswordencoder = bcryptpasswordencoder;
        this.roleRepository = roleRepository;
    }

    public User createUser(SignUpRequestDTO signUpRequestDTO) throws UserAlreadyExistException, PasswordInvalidException, InvalidDataException {

        String email = signUpRequestDTO.getEmail();

        String password = signUpRequestDTO.getPassword();
        String name = signUpRequestDTO.getName();
        String street = signUpRequestDTO.getStreet();
        String city = signUpRequestDTO.getCity();
        String state = signUpRequestDTO.getState();
        String zip = signUpRequestDTO.getZipcode();
        String country = signUpRequestDTO.getCountry();
        List<String> roles = signUpRequestDTO.getRoles();
        String resetPasswordQuestion = signUpRequestDTO.getResetPasswordQuestion();
        String resetPasswordAnswer = signUpRequestDTO.getResetPasswordAnswer();

        if(email == null || password == null || name == null || street == null || city == null || state == null
                || zip == null || country == null || roles == null || resetPasswordQuestion == null
                || resetPasswordAnswer == null) {
            throw new InvalidDataException("Invalid data");
        }

        if(!isValidPassword(password)) {
            throw new PasswordInvalidException("Invalid Password. Password should be at least 8 characters long " +
                    "and should have at least one digit, one uppercase letter, " +
                    "one lowercase letter and one special character");
        }

        List<Role> roleList = new ArrayList<>();
        if(!roles.isEmpty()) {
            for(String role : roles) {
                Optional<Role> roleOptional = roleRepository.findByName(role);
                if(roleOptional.isPresent()) {
                    roleList.add(roleOptional.get());
                } else {
                    Role newRole = new Role();
                    newRole.setName(role);
                    roleList.add(roleRepository.save(newRole));
                }
            }
        } else {
            throw new InvalidDataException("Roles is mandatory while creating user");
        }

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
        newUser.setName(name);
        newUser.setEmail(email);
        newUser.setHashedPassword(bcryptpasswordencoder.encode(password));
        newUser.setAddress(address);
        newUser.setRoles(roleList);
        return userRepository.save(newUser);
    }


    public User getUserByEmail(String email) {
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isEmpty()) {
            throw new UsernameNotFoundException("User by email: " + email + " doesn't exist.");
        }
        return user.get();
    }

    public User getUserById(Long id) {
        Optional<User> user = userRepository.findById(id);
        if(user.isEmpty()) {
            throw new UsernameNotFoundException("User by Id: " + id + " doesn't exist.");
        }
        return user.get();
    }

    public List<User> getAllUser() {
        return userRepository.findAll();
    }

    private boolean isValidPassword(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }

        Matcher matcher = pattern.matcher(password);
        return matcher.matches();
    }

    public User resetPassword(ResetPasswordDTO resetPasswordDTO) throws InvalidDataException {
        Optional<User> optionalUser = userRepository.findByEmail(resetPasswordDTO.getEmail());
        if(optionalUser.isEmpty()) {
            throw new UsernameNotFoundException(resetPasswordDTO.getEmail() + " user doesn't exist.");
        }
        User user = optionalUser.get();
        String actualResetPasswordQuestion = user.getResetPasswordQuestion();
        String actualResetPasswordAnswer = user.getResetPasswordAnswer();

        if(!resetPasswordDTO.getResetPasswordQuestion().equalsIgnoreCase(actualResetPasswordQuestion)) {
            throw new InvalidDataException("Question for Reset Password does not match.");
        }

        if(!resetPasswordDTO.getResetPasswordAnswer().equalsIgnoreCase(actualResetPasswordAnswer)) {
            throw new InvalidDataException("Answer for Reset Password does not match.");
        }

        String newEncodedPassword = bcryptpasswordencoder.encode(resetPasswordDTO.getNewPassword());
        user.setHashedPassword(newEncodedPassword);
        return userRepository.save(user);
    }

    public String getResetPasswordQuestion(String email) throws InvalidDataException {
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isEmpty()) {
            throw new UsernameNotFoundException( email + " user doesn't exist.");
        }
        return user.get().getResetPasswordQuestion();
    }

    public User addRole(Long id, String roleName)
    {
        Optional<User> optionalUser = userRepository.findById(id);
        if(optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User by id: " + id + " doesn't exist.");
        }
        User user = optionalUser.get();

        Role addRole;
        if(roleRepository.findByName(roleName).isPresent()) {
            addRole = roleRepository.findByName(roleName).get();
        } else {
            addRole = new Role();
            addRole.setName(roleName);
            roleRepository.save(addRole);
        }
        user.getRoles().add(addRole);
        return userRepository.save(user);
    }

    public User removeRole(Long id, String roleName) throws InvalidDataException {
        Optional<User> optionalUser = userRepository.findById(id);
        if(optionalUser.isEmpty()) {
            throw new UsernameNotFoundException("User doesn't exist.");
        }
        User user = optionalUser.get();

        Optional<Role> optionalRole = roleRepository.findByName(roleName);
        if(optionalRole.isEmpty()) {
            throw new InvalidDataException(roleName + " Role does not exist" );
        }
        user.getRoles().remove(optionalRole.get());
        return userRepository.save(user);
    }


    public User updateUser(Long id, Map<String, Object> updates)
    {
        Optional<User> optionalUser = userRepository.findById(id);
        if(optionalUser.isEmpty())
        {
            throw new UsernameNotFoundException(id + " doesn't exist.");
        }

        User user = optionalUser.get();
        updates.forEach((key, value) -> {
            switch (key) {
                case "name":
                    user.setName((String) value);
                    break;
                case "email":
                    user.setEmail((String) value);
                    break;
                case "hashedPassword":
                    user.setHashedPassword(bcryptpasswordencoder.encode((String) value));
                    break;
                case "resetPasswordQuestion":
                    user.setResetPasswordQuestion((String) value);
                    break;
                case "resetPasswordAnswer":
                    user.setResetPasswordAnswer((String) value);
                    break;
                case "street":
                    user.getAddress().setStreet((String) value);
                    break;
                case "city":
                    user.getAddress().setCity((String) value);
                    break;
                case "state":
                    user.getAddress().setState((String) value);
                    break;
                case "zipcode":
                    user.getAddress().setZipcode((String) value);
                    break;
                case "country":
                    user.getAddress().setCountry((String) value);
                    break;
            }
        });
        return userRepository.save(user);
    }

    public void deleteUser(String email){
        Optional<User> optionalUser = userRepository.findByEmail(email);
        if(optionalUser.isEmpty()){
            throw new UsernameNotFoundException(email + " user doesn't exist.");
        }
        User user = optionalUser.get();
        user.getRoles().removeAll(user.getRoles());
        userRepository.delete(user);
    }
}