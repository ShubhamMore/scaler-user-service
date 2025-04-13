package com.woolf.project.user.controllers;

import com.woolf.project.user.enums.Roles;
import com.woolf.project.user.dtos.LoginRequestDTO;
import com.woolf.project.user.dtos.LoginResponseDTO;
import com.woolf.project.user.dtos.SignUpRequestDTO;
import com.woolf.project.user.dtos.UserDTO;
import com.woolf.project.user.dtos.ResetPasswordDTO;
import com.woolf.project.user.exception.PasswordInvalidException;
import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.exception.InvalidDataException;
import com.woolf.project.user.models.Token;
import com.woolf.project.user.models.User;
import com.woolf.project.user.services.TokenService;
import com.woolf.project.user.services.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;
    private TokenService tokenService;

    public UserController(UserService userService) {
        this.userService = userService;
        this.tokenService = tokenService;
    }

    @PostMapping("/signUp")
    public ResponseEntity<UserDTO> signup(@Valid @RequestBody SignUpRequestDTO requestDTO) throws UserAlreadyExistException, PasswordInvalidException, InvalidDataException {
        User user = userService.createUser(requestDTO);

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.CREATED);
    }


    @GetMapping("/getAllUsers")
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')")
    public ResponseEntity<List<UserDTO>> getAllUsers() {
        List<User> userList = userService.getAllUser();
        List<UserDTO> userDTOList = new ArrayList<>();
        for (User user : userList) {
            userDTOList.add(UserDTO.fromUser(user));
        }
        return new ResponseEntity<>(userDTOList, HttpStatus.OK);
    }

    @GetMapping("/getUser/{email}")
    public ResponseEntity<UserDTO> getUsersByEmail(@PathVariable String email) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            // Extract the JWT token
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String username = jwt.getClaim("sub");  // username is email
            if (!email.equalsIgnoreCase(username)) { // Case-insensitive check
                throw new AccessDeniedException("You cannot access another user's data.");
            }
        } else {
            throw new BadCredentialsException("Authentication Failed.");
        }

        User user = userService.getUserByEmail(email);

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }

    @GetMapping("/getResetPasswordQuestion/{email}")
    public ResponseEntity<Map> getResetPasswordQuestion(@PathVariable String email) throws InvalidDataException {
        String question = userService.getResetPasswordQuestion(email);
        Map<String,String> response = new HashMap<>();
        response.put("resetPasswordQuestion",question);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/resetPassword")
        public ResponseEntity<UserDTO> resetPassword(@RequestBody @Valid ResetPasswordDTO resetPasswordDTO) throws InvalidDataException {

        User user = userService.resetPassword(resetPasswordDTO);
        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
    }

//    @GetMapping("/getUser/{id}")
//    public ResponseEntity<UserDTO> getAllUsers(@PathVariable Long id) {
//        User user = userService.getUserById (id);
//        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.OK);
//    }

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


    @PatchMapping("/addRole/{id}")
    public ResponseEntity<UserDTO> addRole(@PathVariable Long id, @RequestParam Roles roleName) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            // Extract the JWT token
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  // username is email
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { // Case-insensitive check
                throw new AccessDeniedException(" You don't have access to perform this action.");
            }
        }
        else {
            throw new BadCredentialsException("Authentication Failed.");
        }

        User updatedUser = userService.addRole(id,roleName);
        return new ResponseEntity<>(UserDTO.fromUser(updatedUser), HttpStatus.OK);
    }

    @PatchMapping("/removeRole/{id}")
    public ResponseEntity<UserDTO> removeRole(@PathVariable Long id, @RequestParam Roles roleName) throws InvalidDataException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            // Extract the JWT token
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  // username is email
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { // Case-insensitive check
                throw new AccessDeniedException("You don't have access to perform this action.");
            }
        }
        else {
            throw new BadCredentialsException("Authentication Failed");
        }

        User updatedUser = userService.removeRole(id,roleName);
        return new ResponseEntity<>(UserDTO.fromUser(updatedUser), HttpStatus.OK);
    }


    @PatchMapping("/updateUser/{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable Long id, @RequestBody Map<String, Object> updates) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            // Extract the JWT token
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  // username is email
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { // Case-insensitive check
                throw new AccessDeniedException("You don't have access to perform this action.");
            }
        }
        else {
            throw new BadCredentialsException("Authentication Failed.");
        }

        User updatedUser = userService.updateUser(id,updates);
        return new ResponseEntity<>(UserDTO.fromUser(updatedUser), HttpStatus.OK);
    }

    @DeleteMapping("/deleteUser/{email}")
    public ResponseEntity<Void> deleteUser(@PathVariable String email ) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            // Extract the JWT token
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String username = jwt.getClaim("sub");  // username is email
            if (!email.equalsIgnoreCase(username)) { // Case-insensitive check
                throw new AccessDeniedException("You cannot delete another user.");
            }
        }
        else {
            throw new BadCredentialsException("Authentication Failed.");
        }

        userService.deleteUser(email);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
