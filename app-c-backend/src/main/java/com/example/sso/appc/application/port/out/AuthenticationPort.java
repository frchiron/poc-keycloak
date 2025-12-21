package com.example.sso.appc.application.port.out;

import com.example.sso.appc.domain.model.User;

public interface AuthenticationPort {
    User extractUserFromToken(String token);
    boolean validateToken(String token);
}
