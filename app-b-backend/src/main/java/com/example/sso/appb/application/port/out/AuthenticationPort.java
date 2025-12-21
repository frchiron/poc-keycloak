package com.example.sso.appb.application.port.out;

import com.example.sso.appb.domain.model.User;

public interface AuthenticationPort {
    User extractUserFromToken(String token);
    boolean validateToken(String token);
}
