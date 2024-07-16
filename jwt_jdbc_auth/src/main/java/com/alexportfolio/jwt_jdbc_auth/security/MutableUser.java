package com.alexportfolio.jwt_jdbc_auth.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


import java.util.Collection;

public class MutableUser implements UserDetails {

    private String password;
    private final UserDetails delegate;

    public MutableUser(UserDetails user) {
        this.delegate = user;
        this.password = user.getPassword();
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.delegate.getAuthorities();
    }

    public String getUsername() {
        return this.delegate.getUsername();
    }

    public boolean isAccountNonExpired() {
        return this.delegate.isAccountNonExpired();
    }

    public boolean isAccountNonLocked() {
        return this.delegate.isAccountNonLocked();
    }

    public boolean isCredentialsNonExpired() {
        return this.delegate.isCredentialsNonExpired();
    }

    public boolean isEnabled() {
        return this.delegate.isEnabled();
    }
}