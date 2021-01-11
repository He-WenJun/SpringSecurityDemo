package com.hwj.spring_security_demo.config.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Iterator;

/**
 * @program: spring_security_demo
 * @description: 权限决策管理器
 *  当执行完权限校验过滤器后，得到了url的具体访问权限，就会执行这里的权限决策管理器，来决定是否通过权限验证
 * @author: HeWJ
 * @create: 2021-01-04 15:03
 **/
@Slf4j
public class AuthorityManager implements AccessDecisionManager {

    /**
     *  取当前用户的权限与这次请求的这个url需要的权限作对比，决定是否放行
     * @param authentication 包含了当前的用户信息，包括拥有的权限,即之前UserDetailsService登录时候存储的用户对象
     * @param o 就是FilterInvocation对象，可以得到request等web资源
     * @param collection 是本次访问需要的权限。即上一步的 AuthorityFilter（权限校验过滤器） 中查询核对得到的权限列表
     * @throws AccessDeniedException
     * @throws InsufficientAuthenticationException
     */
    @Override
    public void decide(Authentication authentication, Object o, Collection<ConfigAttribute> collection) throws AccessDeniedException, InsufficientAuthenticationException {
        log.info("进入权限决策管理器，开始对本次请求的url访问权限鉴权");
        if(authentication == null)
            throw new AccessDeniedException("无认证信息");

        Iterator<ConfigAttribute> iterator = collection.iterator();

        while (iterator.hasNext()){
            //当前请求的url所需权限
            String auth = iterator.next().getAttribute();
            if ("ROLE_LOGIN".equals(auth)) {
                if (authentication instanceof AnonymousAuthenticationToken)
                    throw new BadCredentialsException("未登录");
                else
                    return;
            }
            //检查当前认证的账号是否具备访问此url的权限
            log.info("当前url所需权限：{}", auth);
            for(GrantedAuthority authority : authentication.getAuthorities()){
                if(auth.equals(authority.getAuthority())){
                    return;
                }
            }
        }

        throw new AccessDeniedException("权限不足!");
    }

    @Override
    public boolean supports(ConfigAttribute configAttribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return true;
    }
}
