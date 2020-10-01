package com.mzx.security_sql.config;


import com.mzx.security_sql.service.impl.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // DelegatingPasswordEncoder和NoOpPasswordEncoder都是PasswordEncoder接口的实现类,
    // 根据官方的定义,Spring Security的PasswordEncoder接口用于执行密码的单向转换，以便安全地存储密码。
    @Bean
    PasswordEncoder passwordEncoder(){
//        事实上,NoOpPasswordEncoder就是没有编码的编码器
//        return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder(10);
    }

    //基于内存认证
    /**
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("root").password("root").roles("ADMIN","USER")
                .and()
                .withUser("ma").password("ma").roles("USER")
                .and()
                .withUser("admin").password("$2a$10$5.9K8IANoyjK4jVJqPg8z.5BPdgvNMMmuwP3k4RqoWSh3912TRHUW").roles("ADMIN","USER")
                .and()
                .withUser("sang").password("$2a$10$/JDJbU/a5hMzXxeNR1CMpODCYtQQYQAshIJICQ2PeJy11qhzcpMiG").roles("USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/admin/**")
                .hasRole("ADMIN")
                .antMatchers("/user/**")
                .access("hasAnyRole('ADMIN','USER')")
                .antMatchers("/db/**")
                .access("hasRole('ADMIN') and hasRole('USER')")
                .anyRequest()
                .authenticated()
                .and()
                .formLogin()
                .loginProcessingUrl("/login")
                .permitAll()
                .loginPage("/login_page")
                .usernameParameter("username")
                .passwordParameter("password")
                //登陆成功设置
                .successHandler(new AuthenticationSuccessHandler(){
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        Object principal = authentication.getPrincipal();
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter out = httpServletResponse.getWriter();
                        httpServletResponse.setStatus(200);
                        Map<String,Object> map = new HashMap<>();
                        map.put("status",200);
                        map.put("msg",principal);
                        ObjectMapper objectMapper = new ObjectMapper();
                        out.write(objectMapper.writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //登陆失败设置
                .failureHandler(new AuthenticationFailureHandler(){
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
                        httpServletResponse.setContentType("application/json;charset=utf-8");
                        PrintWriter printWriter  = httpServletResponse.getWriter();
                        httpServletResponse.setStatus(401);
                        Map<String,Object> map = new HashMap<>();
                        map.put("status",401);
                        if (e instanceof LockedException){
                            map.put("msg","用户被锁定，登陆失败");
                        }else if (e instanceof BadCredentialsException){
                            map.put("msg","用户账号或密码输入错误，登陆失败");
                        }else if(e instanceof DisabledException){
                            map.put("msg","用户被禁用，登陆失败");
                        }else if(e instanceof AccountExpiredException){
                            map.put("msg","账号已过期，登陆失败");
                        }else if(e instanceof CredentialsExpiredException){
                            map.put("msg","密码已过期，登陆失败");
                        }else {
                            map.put("msg","登陆失败");
                        }
                        ObjectMapper objectMapper = new ObjectMapper();
                        printWriter.write(objectMapper.writeValueAsString(map));
                        printWriter.flush();
                        printWriter.close();
                    }
                })
                //注销登出设置
                .and()
                .logout()
                .logoutUrl("/logout")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) {

                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
                        httpServletResponse.sendRedirect("/login_page");
                    }
                })
                .and()
                .csrf()
                .disable()
                ;
    }
    */

    //基于数据库验证 用户账号 和 目录权限

    @Autowired
    UserServiceImpl userService;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .antMatchers("/admin/**").hasRole("admin")
//                .antMatchers("/dba/**").hasRole("dba")
//                .antMatchers("/user/**").hasRole("user")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
//                .loginProcessingUrl("/login").permitAll()
//                .and()
//                .csrf().disable();
        http.authorizeRequests().withObjectPostProcessor(new ObjectPostProcessor<FilterSecurityInterceptor>() {
            @Override
            public <O extends FilterSecurityInterceptor> O postProcess(O o) {
                o.setSecurityMetadataSource(cfisms());
                o.setAccessDecisionManager(cadm());
                return o;
            }
        })
                .and()
                .formLogin()
                .loginProcessingUrl("/login").permitAll()
                .and()
                .csrf().disable();
    }

    @Bean
    CustomFilterInvocationSecurityMetadataSoure cfisms(){
        return new CustomFilterInvocationSecurityMetadataSoure();
    }

    @Bean
    CustomAccessDecisionManager cadm(){
        return new CustomAccessDecisionManager();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService);
    }

    //角色继承
    @Bean
    RoleHierarchy roleHierarchy(){
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_dba > ROLE_admin  ROLE_admin > ROLE_user";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }
}
