package com.hwj.spring_security_demo.config.security.filter;

import com.hwj.spring_security_demo.entity.Auth;
import com.hwj.spring_security_demo.entity.Menu;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.AntPathMatcher;

import javax.servlet.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/**
 * 权限校验过滤器，实现动态的权限验证，它的主要责任就是当访问一个url时，返回这个url所需要的访问权限。
 * FilterInvocationSecurityMetadataSource（权限资源过滤器接口）继承了 SecurityMetadataSource（权限资源接口），
 * Spring Security是通过SecurityMetadataSource来加载访问时所需要的具体权限
 */
@Slf4j
public class UrlAuthorityFilter implements FilterInvocationSecurityMetadataSource {

    /**
     * AntPathMatcher是Spring提供用来对资源路径或者url的字符串做匹配使用的。采用的是Ant风格的格式
     * Ant风格的资源地址支持3中匹配
     * ？：匹配文件名中的一个字符
     * *：匹配文件中的任意字符
     * **：匹配多层路径
     */
    private AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 本方法用于在收到请求时，根据请求的url返回此条url需要的访问权限，可以有多个
     * @param o
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        log.info("进入权限检验过滤器，调用getAttributes方法开始获取当前请求url的访问权限");
        //获取当前请求的请求url
        String requestUrl = ((FilterInvocation) o).getRequestUrl();

        /**
         * 关于角色与权限实现思路：
         * 在使用SpringSecurity的时候，获取用户和权限的部分是要自己完成的，为了把不同的权限赋予不同的角色，
         * 创建auth表保存权限，role表保存角色，中间应该还有个role-auth保存角色权限关系，SS可根据用户的角色，
         * 获取拥有的权限，即user通过role => role-auth => auth获取一份权限列表，这份权限列表中的权限ID必须是SS可以识别的，
         * 因此，auth表id前缀 = ROLE_（SpringSecurity在保存权限时，权限必须添加ROLE_前缀，不然会匹配不到权限）
         */

        //省略去查询资源操作
        List<Auth> adminAuth = new ArrayList<>();
        adminAuth.add(new Auth("ROLE_ADMIN"));

        List<Auth> userAuth = new ArrayList<>();
        userAuth.add(new Auth("ROLE_USER"));

        //hello.html 需要ROLE_ADMIN权限
        Menu hello = new Menu("/hello.html", adminAuth);
        //home.html 需要ROLE_USER权限
        Menu home = new Menu("/home.html", userAuth);

        List<Menu> menus = Arrays.asList(hello, home);

        //遍历找出请求url对应的资源url的权限列表，取出交给SpringSecurity
        for(Menu menu : menus){
            if(antPathMatcher.match(menu.getUrl(), requestUrl)){
                List<Auth> authList = menu.getAuthList();
                String[] authArr = new String[authList.size()];
                for(int i = 0; i < authList.size(); i++){
                    authArr[i] = authList.get(i).getAuthority();
                }
                log.info("当前请求的url是{}，本资源所需的访问权是{}", requestUrl, Arrays.toString(authArr));
                return SecurityConfig.createList(authArr);
            }
        }

        /**
         * 如果本方法返回null的话，意味着当前这个请求不需要任何角色就能访问
         * 此处做逻辑控制，如果没有匹配上的，返回一个默认具体权限，防止漏缺资源配置
         */
        log.info("当前请求的url是{}，url所需的访问权是{}", requestUrl, "ROLE_LOGIN");
        return SecurityConfig.createList("ROLE_LOGIN");
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        log.info("执行getAllConfigAttributes");
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        log.info("执行supports");
        return false;
    }
}
