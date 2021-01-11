package com.hwj.spring_security_demo.entity;

import org.springframework.security.core.GrantedAuthority;

/**
 * @program: spring_security_demo
 * @description: 权限类
 * @author: HeWJ
 * @create: 2021-01-04 11:50
 **/

/**
 * GrantedAuthority接口是spring security提供用于获取权限信息的接口
 */
public class Auth implements GrantedAuthority {
    private String authName;

    public Auth(String authName) {
        this.authName = authName;
    }

    @Override
    public String getAuthority() {
        return authName;
    }

    public String getAuthName() {
        return authName;
    }

    public void setAuthName(String authName) {
        this.authName = authName;
    }
}
