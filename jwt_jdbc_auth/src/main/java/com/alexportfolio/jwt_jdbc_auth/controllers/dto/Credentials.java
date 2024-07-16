package com.alexportfolio.jwt_jdbc_auth.controllers.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class Credentials {
    private String username;
    private String password;
    private String oldPassword;
    private String[] authorities;
}
