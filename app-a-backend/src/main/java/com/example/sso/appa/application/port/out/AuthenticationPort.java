package com.example.sso.appa.application.port.out;

import com.example.sso.appa.domain.model.User;

public interface AuthenticationPort {
    User extractUserFromToken(String token);
    boolean validateToken(String token);
}
