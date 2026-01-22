package com.example.SecurityApplication;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
//    @Autowired
//    DataSource dataSource;
    @Autowired
AuthTokenFilter authTokenFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http){
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(
                authorizeRequests-> authorizeRequests
                        .requestMatchers("/hello").permitAll()
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN","USER")
                        .requestMatchers("/user/**").hasRole("USER")
                        .requestMatchers("/login/**").permitAll()
                        .anyRequest()
                        .authenticated()) ;
        //disable basic authencitcation for jwt
        // http.httpBasic(Customizer.withDefaults());
        http.addFilterBefore(authTokenFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource){
        UserDetails user = User.withUsername("user1")
             //   .password("{noop}password")
            .password(passwordEncoder().encode("password"))
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder().encode("adminpassword"))
                .roles("ADMIN")
                .build();

       // return new InMemoryUserDetailsManager(user,admin);
       // UserDetailsManager

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager( dataSource);
        if(!userDetailsManager.userExists("user1")){
            userDetailsManager.createUser(user);
        }

        if(!userDetailsManager.userExists("admin")){
            userDetailsManager.createUser(admin);
        }
//        userDetailsManager.createUser(admin);
//        userDetailsManager.createUser(user);
        return userDetailsManager ;
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder){
        return builder.getAuthenticationManager() ;
    }
}
