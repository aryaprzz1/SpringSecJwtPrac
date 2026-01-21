package com.example.SecurityApplication;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class hello {

    @Autowired
    AuthenticationManager authenticationManager ;

    @Autowired
    JwtUtils jwtUtils ;

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/hello")
    public String sayHello(){
        return "hello";
    }

    @PreAuthorize("hasAnyRole('ADMIN','USER')")
    @GetMapping("/admin")
    public String sayAdmin(){
        return "hello";
    }

    @GetMapping("/user")
    public String sayUser(){
        return "hello";
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest loginRequest){
            Authentication authentication ;
            try{
                authentication = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(
                                loginRequest.getUsername() ,
                                loginRequest.getPassword()
                        )
                );
            }catch(AuthenticationException e){
                    e.printStackTrace();
                    return "error";
            }

            SecurityContextHolder.getContext().setAuthentication(authentication);
            UserDetails userDetails = (UserDetails) authentication.getPrincipal() ;

            String jwtToken = jwtUtils.generateToken(userDetails.getUsername());
            return jwtToken ;
    }
}
