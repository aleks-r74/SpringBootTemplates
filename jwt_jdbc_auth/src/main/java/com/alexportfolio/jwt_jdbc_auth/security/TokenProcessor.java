package com.alexportfolio.jwt_jdbc_auth.security;

import com.alexportfolio.jwt_jdbc_auth.controllers.dto.TokenDto;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
public class TokenProcessor {
    private static SecretKey privateKey = Jwts.SIG.HS256.key().build();
    private final int TOKEN_EXP_SEC = 86400;

    public TokenDto generateToken(Authentication authObj) {
        Date currentDate = new Date();
        Date expirationDate = new Date(currentDate.toInstant().plusSeconds(TOKEN_EXP_SEC).toEpochMilli());
        String authorities = authObj.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.joining(","));
        String token =  Jwts.builder()
                        .subject(authObj.getName())
                        .claim("authorities",authorities)
                        .signWith(privateKey)
                        .issuedAt(currentDate)
                        .expiration(expirationDate)
                        .compact();
        return new TokenDto(token);
    }

    public Authentication getAuthObjFromToken(String token)   {
        try {
            // extracting payload from the token
             var payload = Jwts.parser()
                                .verifyWith(privateKey)
                                .build()
                                .parseSignedClaims(token)
                                .getPayload();
             // converting payload to map
            Map<String, String> map = payload.entrySet()
                    .stream()
                    .filter(e->(e.getValue() instanceof String))
                    .collect(
                            Collectors.toMap(e->(String)e.getKey(), e->(String)e.getValue())
                    );
            // constructing Authentication object
            String[] tokenAuthorities = map.get("authorities").split(",");
            var authorities = strArrToAuthCollection(tokenAuthorities);

            return new AuthenticationObj(map.get("sub"),true, authorities);
        } catch (JwtException e){
            return null;
        }
    }

    public List<? extends GrantedAuthority> strArrToAuthCollection(String[] authoritiesArr){
        Function<String,GrantedAuthority> strToAuthority = str-> ()-> str;
        return Arrays.stream(authoritiesArr)
                    .map(strToAuthority)
                    .collect(Collectors.toList());
    }

}
