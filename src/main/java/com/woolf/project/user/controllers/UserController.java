package com.woolf.project.user.controllers;

import com.woolf.project.user.dtos.LoginRequestDTO;
import com.woolf.project.user.dtos.LoginResponseDTO;
import com.woolf.project.user.dtos.SignUpRequestDTO;
import com.woolf.project.user.dtos.UserDTO;
import com.woolf.project.user.exception.PasswordInvalidException;
import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.exception.InvalidDataException;
import com.woolf.project.user.models.Token;
import com.woolf.project.user.models.User;
import com.woolf.project.user.services.TokenService;
import com.woolf.project.user.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;
    private TokenService tokenService;

    public UserController(UserService userService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/signup")
    public ResponseEntity<UserDTO> signup(@RequestBody SignUpRequestDTO requestDTO) throws UserAlreadyExistException,PasswordInvalidException, InvalidDataException {
        User user = userService.createUser(requestDTO.getEmail(),
                requestDTO.getPassword(), requestDTO.getName(), requestDTO.getStreet(), requestDTO.getCity(),
                requestDTO.getState(), requestDTO.getZipcode(), requestDTO.getCountry(), requestDTO.getRoles());

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.CREATED);
    }

    @GetMapping("/getAllUsers")
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')") //This will enable role based access
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<User> userList = userService.getAllUser();
        List<UserDTO> userDtoList = new ArrayList<>();
        for (User user : userList) {
            userDtoList.add(UserDTO.fromUser(user));
        }
        return new ResponseEntity<>(userDtoList, HttpStatus.OK);
    }

    @GetMapping("/getUser/{email}")
    public ResponseEntity<UserDTO> getUsersByEmail(@PathVariable String email) {
        User user = userService.getUserByEmail(email);
        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }

    @GetMapping("/getUser/{id}")
    public ResponseEntity<UserDTO> getAllUsers(@PathVariable Long id) {
        User user = userService.getUserById(id);
        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(@RequestBody LoginRequestDTO requestDTO) {
        Token token = tokenService.login(requestDTO.getEmail(), requestDTO.getPassword());
        return new ResponseEntity<>(LoginResponseDTO.fromToken(token), HttpStatus.OK);
    }

    @PostMapping("/validate/{token}")
    public ResponseEntity<UserDTO> validateUser(@PathVariable String token) {
        User user = tokenService.validateToken(token);
        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }
}
