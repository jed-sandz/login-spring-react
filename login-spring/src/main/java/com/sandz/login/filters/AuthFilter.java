package com.sandz.login.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class AuthFilter implements Filter {
    @Value("${jwt.secret}")
    private String secretKey;

    public void doFilter(
            ServletRequest request,
            ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        res.addHeader("Access-Control-Allow-Origin", "*");
        res.addHeader("Access-Control-Allow-Methods","GET, OPTIONS, HEAD, PUT, POST");
        res.addHeader("Access-Control-Allow-Headers","*");

        if (req.getMethod().equals("OPTIONS")) {
            res.setStatus(HttpServletResponse.SC_ACCEPTED);
            return;
        }
        System.out.println(req.getRequestURI());

        if(req.getRequestURI().startsWith("/accounts")) {

            String token = req.getHeader("x-auth-token");
            String username = null;
            try {
                Claims claims = Jwts.parser()
                        .setSigningKey(secretKey)
                        .parseClaimsJws(token).getBody();
                System.out.println(claims.getSubject());
                username = claims.getSubject();
            } catch (JwtException | ClassCastException | IllegalArgumentException e) {
                username = "error";
            }

            if(username == null || username.equals("error")){
                res.setStatus(400);
                response.getOutputStream().print("Token is invalid");
                return;
            }
        }
        chain.doFilter(request, response);
    }
}
