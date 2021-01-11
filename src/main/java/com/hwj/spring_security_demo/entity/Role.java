package com.hwj.spring_security_demo.entity;

import org.springframework.security.core.GrantedAuthority;

import java.util.List;


/**
 * @program: spring_security_demo
 * @description: 角色类
 * @author: HeWJ
 * @create: 2021-01-04 11:50
 **/
public class Role {
    private String roleName;

    /*一个角色包含多个权限*/
    List<Auth> authList;

    public Role(String roleName, List<Auth> authList) {
        this.roleName = roleName;
        this.authList = authList;
    }

    public String getRoleName() {
        return roleName;
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }

    public List<Auth> getAuthList() {
        return authList;
    }

    public void setAuthList(List<Auth> authList) {
        this.authList = authList;
    }
}
