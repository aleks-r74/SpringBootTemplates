package com.alexportfolio.jwt_jdbc_auth.controllers;

import com.alexportfolio.jwt_jdbc_auth.controllers.dto.Credentials;
import com.alexportfolio.jwt_jdbc_auth.controllers.dto.TokenDto;
import com.alexportfolio.jwt_jdbc_auth.security.AuthenticationObj;
import com.alexportfolio.jwt_jdbc_auth.security.MutableUser;
import com.alexportfolio.jwt_jdbc_auth.security.TokenProcessor;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.web.bind.annotation.*;
import com.alexportfolio.jwt_jdbc_auth.utils.Protector;
import java.security.Principal;


@RestController
@AllArgsConstructor
public class JWTAuthController {
    UserDetailsManager userDetailsManager;
    TokenProcessor tokenProcessor;
    PasswordEncoder passwordEncoder;

    @GetMapping("test")
    String root(Principal user){
        return "Hi " + user.getName();
    }

    // accepts credentials, returns token
    @PostMapping(path="auth", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<TokenDto> login(@RequestBody Credentials credentials){
        String reqUsername   = credentials.getUsername();
        String reqPass       = credentials.getPassword();
        UserDetails dbUser;
        if(!Protector.isAllowed(reqUsername))
            return new ResponseEntity<TokenDto>(new TokenDto(), HttpStatus.LOCKED);

        try{ // load user by user name
                dbUser = userDetailsManager.loadUserByUsername(reqUsername);
                // checkin user's password
                if(!passwordEncoder.matches(reqPass, dbUser.getPassword())) {
                    Protector.complain(reqUsername);
                    throw new UsernameNotFoundException("");
                }
            } catch(UsernameNotFoundException e){
            return new ResponseEntity<TokenDto>(new TokenDto(), HttpStatus.NOT_FOUND);
        }
        var authObj = new AuthenticationObj(dbUser.getUsername(), true, dbUser.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authObj);
        var tokenDto = tokenProcessor.generateToken(authObj);

       return new ResponseEntity<TokenDto>(tokenDto, HttpStatus.OK);
    }


    // creates new user
    @PostMapping(path="reg", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<TokenDto> createNewUser(@RequestBody Credentials credentials){
        String reqUsername  = credentials.getUsername();
        String reqPass      = credentials.getPassword();
        String[] reqAuth    = credentials.getAuthorities() == null ? new String[]{"ROLE_USER"} : credentials.getAuthorities();
        // validate credentials

        // check that credentials do not exist
        try{
            if(userDetailsManager.loadUserByUsername(reqUsername).getUsername().equals(reqUsername)){
                return new ResponseEntity<TokenDto>(new TokenDto(), HttpStatus.NOT_ACCEPTABLE);
            };
        }catch(UsernameNotFoundException e){
            // if user wasn't found, we can proceed
        }

        // create new user
        UserDetails newUser = User
                .withUsername(reqUsername)
                .password(passwordEncoder.encode(reqPass))
                .authorities(reqAuth)
                .build();

        // writing the newUser to the DB
        userDetailsManager.createUser(newUser);

        // create new token
        var authObject = new AuthenticationObj(reqUsername,true,tokenProcessor.strArrToAuthCollection(reqAuth));
        var tokenDto = tokenProcessor.generateToken(authObject);

        // return result
        return new ResponseEntity<TokenDto>(tokenDto, HttpStatus.OK);
    }

    @DeleteMapping(path="reg", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Void> deleteUser(@RequestBody Credentials credentials){
        if(credentials.getUsername().equals("admin")){
            return new ResponseEntity<Void>(HttpStatus.NOT_ACCEPTABLE);
        }
        userDetailsManager.deleteUser(credentials.getUsername());
        return new ResponseEntity<Void>(HttpStatus.OK);
    }

    @PatchMapping(path="reg", consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<Void> updateUserPassword(@RequestBody Credentials credentials){
        if(credentials.getPassword().strip().length()<6)
            return new ResponseEntity<Void>(HttpStatus.NOT_ACCEPTABLE);
        try {
            UserDetails dbUser = userDetailsManager.loadUserByUsername(credentials.getUsername());
            MutableUser updUser = new MutableUser(dbUser);
            updUser.setPassword(passwordEncoder.encode(credentials.getPassword()));
            userDetailsManager.updateUser(updUser);

        }catch(AuthenticationException e){
            return new ResponseEntity<Void>(HttpStatus.NOT_FOUND);
        }

        return new ResponseEntity<Void>(HttpStatus.OK);
    }
}
