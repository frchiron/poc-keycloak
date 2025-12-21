package com.example.sso.appb.application.service;

import com.example.sso.appb.application.port.in.GetUserInfoUseCase;
import com.example.sso.appb.application.port.out.AuthenticationPort;
import com.example.sso.appb.domain.model.User;
import org.springframework.stereotype.Service;

@Service
public class UserService implements GetUserInfoUseCase {

    private final AuthenticationPort authenticationPort;

    public UserService(AuthenticationPort authenticationPort) {
        this.authenticationPort = authenticationPort;
    }

    @Override
    public User getUserInfo(String token) {
        if (!authenticationPort.validateToken(token)) {
            throw new RuntimeException("Invalid token");
        }
        return authenticationPort.extractUserFromToken(token);
    }
}
