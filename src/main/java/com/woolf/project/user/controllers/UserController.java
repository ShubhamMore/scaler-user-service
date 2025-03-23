package com.woolf.project.user.controllers;

import com.woolf.project.user.dtos.LoginRequestDTO;
import com.woolf.project.user.dtos.LoginResponseDTO;
import com.woolf.project.user.dtos.SignUpRequestDTO;
import com.woolf.project.user.dtos.UserDTO;
import com.woolf.project.user.exception.PasswordInvalidException;
import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.models.Token;
import com.woolf.project.user.models.User;
import com.woolf.project.user.services.TokenService;
import com.woolf.project.user.services.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
    public ResponseEntity<UserDTO> signup(@RequestBody SignUpRequestDTO requestDTO) throws UserAlreadyExistException,PasswordInvalidException {
        User user = userService.createUser(requestDTO.getEmail(),
                requestDTO.getPassword(), requestDTO.getName(), requestDTO.getStreet(), requestDTO.getCity(),
                requestDTO.getState(), requestDTO.getZipcode(), requestDTO.getCountry());

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.CREATED);
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
