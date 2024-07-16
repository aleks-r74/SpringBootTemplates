package com.alexportfolio.jwt_jdbc_auth.security;

import lombok.NoArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;

@NoArgsConstructor
public class AuthenticationObj implements Authentication {
    private String principal;
    private boolean authenticated = false;
    Collection<? extends GrantedAuthority> authorities = null;

    public AuthenticationObj(String principal, boolean isAuthenticated, Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        this.principal = principal;
        this.authenticated = isAuthenticated;
    }

    public <T extends Collection<GrantedAuthority>> void setAuthorities(T authorities) {
         this.authorities = authorities;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public String getPrincipal() {
        return this.principal;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }

    @Override
    public boolean equals(Object another) {
        if(!(another instanceof String)) return false;
        return principal.equals((String)another);
    }

    @Override
    public String toString() {
        return principal;
    }

    @Override
    public int hashCode() {
        return principal.hashCode();
    }

    @Override
    public String getName() {
        return principal;
    }
}
