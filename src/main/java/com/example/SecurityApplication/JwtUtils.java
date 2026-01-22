package com.example.SecurityApplication;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Objects;

@Component
public class JwtUtils {
//    private final UserDetailsService userDetailsService;
    private String jwtSecret = " ZHVtbXktc3ByaW5nLWp3dC1zZWNyZXQta2V5LTEyMy1zZWN1cmU=" ;
    private int jwtExpirationMs = 172800000;

//    public JwtUtils(UserDetailsService userDetailsService) {
//        this.userDetailsService = userDetailsService;
//    }

    // Authorization Bearer<Token>

    public String getJwtFromHeader(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if(bearerToken !=null && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return  null ;
    }

    public String generateToken(UserDetails userDetails) {
          String userName = userDetails.getUsername() ;
        return Jwts.builder()
                .setSubject(userName) //whom token refers too
                .claim("roles",userDetails.getAuthorities()
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .toList())
                .setIssuedAt(new Date()) // experitaton
                .setExpiration(new Date(new Date().getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

        public boolean validateToken(String jwtToken){
            try{
//                Jwts.parser().verifyWith(key()).build().parseSignedClaims(jwtToken);
                Jwts.parserBuilder()
                        .setSigningKey(key())
                        .build()
                        .parseClaimsJws(jwtToken);
                return true;
            }catch (Exception e){
            e.printStackTrace();
        }
        return false;
    }
    public List<String> getRolesNameFromToken(String jwt) {
        List<?> roles = Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .get("roles", List.class)    ;

        return  roles.stream()
                .map(Objects::toString)
                .toList();
    }


    public String getUserNameFromToken(String jwt) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject() ;
    }
    public Key key(){
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
}
