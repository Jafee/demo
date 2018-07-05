package com.example.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {


        @Autowired
        FindByIndexNameSessionRepository<? extends Session> sessionRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .sessionManagement()
                .maximumSessions(1)
                .sessionRegistry(sessionRegistry());

        http
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/", "/login").permitAll()
                .anyRequest().authenticated()

                .and()
                    .formLogin()
                    .loginPage("/login")
                    .defaultSuccessUrl("/")

                .and()
                    .rememberMe()
                    .rememberMeParameter("remember-me")
                    .rememberMeCookieName("remember-me")
                    .rememberMeServices(rememberMeServices())

                .and()
                    .logout()
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/")

                .and()
                    .csrf()
                    .disable();
        }


        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication().withUser(User.withUsername("user")
                    .password("{noop}password").roles("USER").build());

        }

        @Bean
        RememberMeServices rememberMeServices() {
            SpringSessionRememberMeServices rememberMeServices = new SpringSessionRememberMeServices();
            rememberMeServices.setAlwaysRemember(true);
            return rememberMeServices;
        }

        @Bean
        SpringSessionBackedSessionRegistry sessionRegistry() {
            return new SpringSessionBackedSessionRegistry<>(this.sessionRepository);
        }
    }
