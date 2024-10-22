package com.chahd.users.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Allow specific HTTP methods
        response.addHeader("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS, POST, PUT, DELETE");

        // Allow specific headers in the request
        response.addHeader("Access-Control-Allow-Headers", 
                "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers, Authorization");

        // Expose specific headers in the response
        response.addHeader("Access-Control-Expose-Headers", 
                "Authorization, Access-Control-Allow-Origin, Access-Control-Allow-Headers");

        // Respond to preflight requests
        if (request.getMethod().equals("OPTIONS")) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        String jwt = request.getHeader("Authorization");

        if (jwt == null || !jwt.startsWith(SecParams.PREFIX)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SecParams.SECRET)).build();
            // Remove the "Bearer " prefix from the JWT
            jwt = jwt.substring(SecParams.PREFIX.length()); // 7 characters in "Bearer "

            DecodedJWT decodedJWT = verifier.verify(jwt);
            String username = decodedJWT.getSubject();
            List<String> roles = decodedJWT.getClaims().get("roles").asList(String.class);

            Collection<GrantedAuthority> authorities = new ArrayList<>();
            for (String role : roles) {
                authorities.add(new SimpleGrantedAuthority(role));
            }

            UsernamePasswordAuthenticationToken user = 
                    new UsernamePasswordAuthenticationToken(username, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(user);
        } catch (Exception e) {
            // Handle the error as necessary (e.g., logging)
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // Unauthorized status code
            return; // Stop further processing if there's an issue with JWT
        }

        filterChain.doFilter(request, response);
    }
}
