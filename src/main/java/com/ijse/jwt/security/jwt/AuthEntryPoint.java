package com.ijse.jwt.security.jwt;

import javax.naming.AuthenticationException;

import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.io.IOException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import  org.springframework.security.core.AuthenticationException;

@Component
public class AuthEntryPoint implements AuthenticationEntryPoint {


   

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
            org.springframework.security.core.AuthenticationException authException)
            throws java.io.IOException {
        // TODO Auto-generated method stub
       
         response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Error:Unauthorized");
    }
}
