package com.hwj.spring_security_demo.config;

import com.hwj.spring_security_demo.config.security.AuthorityManager;
import com.hwj.spring_security_demo.config.security.filter.UrlAuthorityFilter;
import com.hwj.spring_security_demo.config.security.handler.AuthorityDeniedHandler;
import com.hwj.spring_security_demo.config.security.handler.LoginAuthenticationFailureHandler;
import com.hwj.spring_security_demo.config.security.handler.LoginAuthenticationSuccessHandler;
import com.hwj.spring_security_demo.config.security.handler.LogoutHandler;
import com.hwj.spring_security_demo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.util.DigestUtils;


/**
 * @Description: spring-security权限管理的核心配置
 */
@Configuration
@EnableWebSecurity
@Slf4j
/**
 * 当我们想要开启spring方法级安全时，
 * 只需要在任何 @Configuration实例上使用 @EnableGlobalMethodSecurity 注解就能达到此目的。
 * 同时这个注解为我们提供了prePostEnabled 、securedEnabled 和 jsr250Enabled 三种不同的机制来实现同一种功能
 * prePostEnabled ：prePostEnabled = true 会解锁 @PreAuthorize 和 @PostAuthorize
 *      @PreAuthorize 注解会在方法执行前进行验证
 *      @PostAuthorize 在方法调用完成后进行权限检查，它不能控制方法是否能被调用，
 *                     只能在方法调用完成后检查权限决定是否要抛出AccessDeniedException。
 * securedEnabled：securedEnabled = true 会解锁@Secured注解
 *      @Secured 缺点（限制）就是不支持Spring EL表达式，不够灵活。
 *               并且指定的角色必须以ROLE_开头，不可省略。该注解功能要简单的多，
 *              默认情况下只能基于角色（默认需要带前缀 ROLE_）集合来进行访问控制决策。
 *              该注解的机制是只要其声明的角色集合（value）中包含当前用户持有的任一角色就可以访问。
 *              也就是 用户的角色集合和 @Secured 注解的角色集合要存在非空的交集。 不支持使用 SpEL 表达式进行决策。
 * JSR-250：
 *      @DenyAll 拒绝所有访问
 *      @RolesAllowed({"USER", "ADMIN"})  该方法只要具有"USER", "ADMIN"任意一种权限就可以访问。
 *                                        这里可以省略前缀ROLE_，实际的权限可能是ROLE_ADMIN
 *      @PermitAll 允许所有访问
 */
@EnableGlobalMethodSecurity(jsr250Enabled = true, prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private UserService userService; //实现了UserDetailsService接口，spring security会根据此接口加载账号信息


    /**
     *   configure(HttpSecurity)方法定义了哪些URL路径应该被保护，哪些不应该。
     *   具体来说，“/”和“/ home”路径被配置为不需要任何身份验证。所有其他路径必须经过身份验证。
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .anyRequest().authenticated()//其他的路径都是登录后即可访问
                .withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
                    @Override
                    public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                        o.setSecurityMetadataSource(new UrlAuthorityFilter());
                        return o;
                    }
                })
                .accessDecisionManager(new AuthorityManager()) //自定义权限决策管理器
                .and()
                .formLogin()
                .loginPage("/login.html") //登录页面
                .loginProcessingUrl("/login") //登录的url
                .usernameParameter("username") //用户名参数名
                .passwordParameter("password") //密码参数名
                .defaultSuccessUrl("/home.html") //认证成功后默认跳转的地址
                .failureHandler(new LoginAuthenticationFailureHandler()) //认证失败处理器
                .successHandler(new LoginAuthenticationSuccessHandler()) //认证成功处理器
                .permitAll()
                .and()
                .logout()
                .logoutUrl("/logout") //登出url
                .logoutSuccessHandler(new LogoutHandler()) //登出成功处理器
                .permitAll()
                .and()
                .exceptionHandling().accessDeniedHandler(new AuthorityDeniedHandler()); //登录后访问接口权限不足时的处理器
    }

    @Override
    public void configure(WebSecurity web) {
        //完全不走spring security filter的路径，一般用于指定前端静态资源
        web.ignoring().antMatchers( "/js/**", "/login.html");
    }


    /**
     * @Description: 配置userDetails的数据源，密码加密格式
     * @return: void
     **/
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //指定加载账号信息的数据源
        auth.userDetailsService(userService)
                //密码的加密方式与比较逻辑
                .passwordEncoder(new PasswordEncoder() {
                    //加密方式
                    @Override
                    public String encode(CharSequence charSequence) {
                        log.info("执行了encode方法加密字符，明文：{}", charSequence);
                        log.info(DigestUtils.md5DigestAsHex(charSequence.toString().getBytes()));
                        return DigestUtils.md5DigestAsHex(charSequence.toString().getBytes());
                    }

                    /**
                     * 登录时的密码比较逻辑
                     * @param charSequence 明文（前台传递过来的密码）
                     * @param s 密文（数据库中储存的加密密码）
                     * @return
                     */
                    @Override
                    public boolean matches(CharSequence charSequence, String s) {
                        log.info("执行matches方法进行密码比较，数据库密文{}，前端传递的明文{}", s, charSequence);
                        log.info("matches方法密码比较结果{}",s.equals(DigestUtils.md5DigestAsHex(charSequence.toString().getBytes())));
                        return s.equals(DigestUtils.md5DigestAsHex(charSequence.toString().getBytes()));
                    }
                });
    }


    /**
     * 默认在内存中创建的用户
     * @param auth
     * @throws Exception
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("123").password("123").roles("USER");
    }
}
