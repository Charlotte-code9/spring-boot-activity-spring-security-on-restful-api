package com.springsecurityrestapi.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.SecurityFilterChain;
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true,proxyTargetClass=true)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}password").roles("USER")
                .and()
                .withUser("admin").password("{noop}password").roles("USER", "ADMIN");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                //HTTP Basic authentication
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/students/getAllStudent").hasRole("USER")
                .antMatchers(HttpMethod.GET, "/students/getStudentById").hasRole("USER")
                .antMatchers(HttpMethod.POST, "/students/addStudent").hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT, "/students/updateStudent").hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE, "/students/deleteStudent").hasRole("ADMIN")
                .and()
                .csrf().disable()
                .formLogin().disable();
    }

}
