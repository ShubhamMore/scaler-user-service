package com.woolf.project.user.controllers;

import com.woolf.project.user.enums.Roles;
import com.woolf.project.user.dtos.ResetPasswordDTO;
import com.woolf.project.user.dtos.SignUpRequestDTO;
import com.woolf.project.user.dtos.UserDTO;
import com.woolf.project.user.exception.InvalidDataException;
import com.woolf.project.user.exception.PasswordInvalidException;
import com.woolf.project.user.exception.UserAlreadyExistException;
import com.woolf.project.user.models.User;
import com.woolf.project.user.services.UserService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    private UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("/signUp")
    public ResponseEntity<UserDTO> signup(@Valid @RequestBody  SignUpRequestDTO requestDTO) throws UserAlreadyExistException, PasswordInvalidException, InvalidDataException {
        User user = userService.createUser(requestDTO);

        return new ResponseEntity<>(UserDTO.fromUser(user), HttpStatus.CREATED);
    }


    @GetMapping("/getUser/{email}")
    public ResponseEntity<UserDTO> getUsersByEmail(@PathVariable String email) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String username = jwt.getClaim("sub");
            if (!email.equalsIgnoreCase(username)) {
                throw new AccessDeniedException("You don't have permission to perform this action.");
            }
        } else {
            throw new BadCredentialsException("Authentication Failed");
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

    @PatchMapping("/addRole/{id}")
    public ResponseEntity<UserDTO> addRole(@PathVariable Long id, @RequestParam Roles roleName)
    {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { 
                throw new AccessDeniedException("You don't have permission to perform this action.");
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
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { 
                throw new AccessDeniedException("You don't have permission to perform this action.");
            }
        }
        else {throw new BadCredentialsException("Authentication Failed.");
        }

        User updatedUser = userService.removeRole(id,roleName);
        return new ResponseEntity<>(UserDTO.fromUser(updatedUser), HttpStatus.OK);
    }

    @PatchMapping("/updateUser/{id}")
    public ResponseEntity<UserDTO> updateUser(@PathVariable Long id, @RequestBody Map<String, Object> updates) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String userId = jwt.getClaim("userId");  
            if (!userId.equalsIgnoreCase(String.valueOf(id))) { 
                throw new AccessDeniedException("You don't have permission to perform this action");
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
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String username = jwt.getClaim("sub");
            if (!email.equalsIgnoreCase(username)) {
                throw new AccessDeniedException("You don't have permission to perform this action.");
            }
        } else {
            throw new BadCredentialsException("Authentication Failed.");
        }
        userService.deleteUser(email);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}