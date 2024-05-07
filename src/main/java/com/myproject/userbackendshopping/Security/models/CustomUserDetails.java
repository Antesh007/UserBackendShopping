package com.myproject.userbackendshopping.Security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.myproject.userbackendshopping.models.Roles;
import com.myproject.userbackendshopping.models.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@JsonDeserialize
public class CustomUserDetails implements UserDetails {
    public CustomUserDetails(){}
//    private User user;
    private List<CustomGrantedAuthority>authorities;
    private String password;
    private String username;
    private boolean accountNonExpired;
    private boolean accountNonLocked;
    private boolean credentialsNonExpired;
    private boolean enabled;

    private Long userId;

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }
    public CustomUserDetails(User user){
        this.accountNonLocked = true;
        this.accountNonExpired = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
        this.password = user.getHashedPassword();
        this.username = user.getEmail();
        List<CustomGrantedAuthority>grantedAuthorities= new ArrayList<>();
        for (Roles role: user.getRoles()){
            grantedAuthorities.add(new CustomGrantedAuthority(role));
        }
        this.authorities = grantedAuthorities;
        this.userId = user.getId();
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
//        List<CustomGrantedAuthority>grantedAuthorities= new ArrayList<>();
//        for (Roles role: user.getRoles()){
//            grantedAuthorities.add(new CustomGrantedAuthority(role));
//        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}
