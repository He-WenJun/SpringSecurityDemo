package com.hwj.spring_security_demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @program: spring_security_demo
 * @description:
 * @author: HeWJ
 * @create: 2021-01-08 17:13
 **/
@RestController
public class TestController {
    //hasRole()，指当前登录的账号必须包含所指的的权限
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/adminMapper")
    public String adminMapper(){
        return "当前账号拥有ADMIN权限";
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping("/userMapper")
    public String userMapper(){
        return "当前账号拥有USER权限";
    }

    //and 是并且的关系，指包含这两个权限
    @PreAuthorize("hasRole('ADMIN') and hasRole('USER')")
    @GetMapping("/adminAndUserMapper")
    public String adminAndUserMapper(){
        return "当前账号拥有ADMIN和USER权限";
    }
}
