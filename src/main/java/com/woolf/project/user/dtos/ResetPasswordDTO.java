package com.woolf.project.user.dtos;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordDTO {
    private String email;
    private String resetPasswordQuestion;
    private String resetPasswordAnswer;
    private String newPassword;
}
