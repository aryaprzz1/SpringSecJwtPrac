package com.example.SecurityApplication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class JwtUtils {
    private String jwtSecret = " ZHVtbXktc3ByaW5nLWp3dC1zZWNyZXQta2V5LTEyMy1zZWN1cmU=" ;
    private int jwtExpirationMs = 1728000;

    // Authorization Bearer<Token>

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken !=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return  null ;
    }

    public String generateToken(String userName) {
        return Jwts.builder()
                .setSubject(userName) //whom token refers too
                .setIssuedAt(new Date()) // experitaton
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

        public boolean validateToken(String jwtToken){
            try{
//                Jwts.parser().verifyWith(key()).build().parseSignedClaims(jwtToken);
                Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(jwtToken);
            }catch (Exception e){
            e.printStackTrace();
        }
        return true ;
    }

    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromToken(String jwt) {
        return Jwts.parserBuilder().setSigningKey(key()).build().parseClaimsJws(jwt).getBody().getSubject() ;
    }
}
