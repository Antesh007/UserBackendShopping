package com.myproject.userbackendshopping.Security.models;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.myproject.userbackendshopping.models.Roles;
import org.springframework.security.core.GrantedAuthority;

@JsonDeserialize
public class CustomGrantedAuthority implements GrantedAuthority {
//    private Roles roles;
    private String authority;
    public CustomGrantedAuthority(){}
    public CustomGrantedAuthority(Roles roles){
        this.authority = roles.getName();
    }
    @Override
    public String getAuthority() {
        return authority;
    }
}
