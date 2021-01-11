package com.hwj.spring_security_demo.entity;

import java.util.List;

/**
 * @program: spring_security_demo
 * @description: 资源类
 * @author: HeWJ
 * @create: 2021-01-04 11:29
 **/
public class Menu {
    /*资源的url*/
    String url;
    /*本资源所需权限*/
    List<Auth> authList;

    public Menu(String url, List<Auth> authList) {
        this.url = url;
        this.authList = authList;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public List<Auth> getAuthList() {
        return authList;
    }

    public void setAuthList(List<Auth> authList) {
        this.authList = authList;
    }
}
