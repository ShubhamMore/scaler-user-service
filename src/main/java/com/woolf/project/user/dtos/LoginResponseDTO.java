package com.woolf.project.user.dtos;

import com.woolf.project.user.models.Token;
import lombok.Getter;
import lombok.Setter;


@Getter
@Setter
public class LoginResponseDTO {
    private String token;

    public static LoginResponseDTO fromToken(Token token) {
        LoginResponseDTO ldto = new LoginResponseDTO();
        ldto.setToken(token.getTokenValue());
        return ldto;
    }
}
