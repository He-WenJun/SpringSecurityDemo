package com.hwj.spring_security_demo.service.impl;

import com.hwj.spring_security_demo.entity.Auth;
import com.hwj.spring_security_demo.entity.Role;
import com.hwj.spring_security_demo.entity.User;
import com.hwj.spring_security_demo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class UserServiceImpl implements UserService {


    /**
     * Spring Security通过UserDetailsService接口调用loadUserByUsername方法来根据用户名加载用户信息，
     * 执行登录,构建Authentication对象必须的信息,如果用户不存在，则抛出UsernameNotFoundException异常
     *
     * @param userName
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {

        /**
         * 省略去数据库查询用户名
         */

        log.info("当前执行的方法为loadUserByUsername，登录的用户名为：{}" ,userName);

        //下面模拟去数据库查询账号，用户的角色，权限操作
        List<Auth> adminAuth = new ArrayList<>();
        adminAuth.add(new Auth("ROLE_ADMIN"));

        List<Auth> userAuth = new ArrayList<>();
        userAuth.add(new Auth("ROLE_USER"));

        //一个账号可以拥有多个角色，一个角色包含多个权限
        List<Role> userRoles = new ArrayList<>();
        Role userRole = new Role("user", userAuth);
        userRoles.add(userRole);

        List<Role> adminRoles = new ArrayList<>();
        Role adminRole = new Role("admin", adminAuth);
        adminRoles.add(adminRole);
        adminRoles.add(userRole);

        User user = new User();
        //写死两个账号，密码都是123456
        if(userName.equals("admin")){
            user.setUsername(userName);
            user.setRoles(adminRoles);
            //MD5的123456密文
            user.setPassword("e10adc3949ba59abbe56e057f20f883e");
        }else if(userName.equals("user")){
            user.setUsername(userName);
            user.setRoles(userRoles);
            //MD5的123456密文
            user.setPassword("e10adc3949ba59abbe56e057f20f883e");
        }else{
            log.info("账号不存在");
            throw new UsernameNotFoundException("用户名不存在");
        }
        //这个User类实现了UserDetails接口，返回的user对象会被Spring Security构建成Authentication对象储存起来
        return user;
    }
}
