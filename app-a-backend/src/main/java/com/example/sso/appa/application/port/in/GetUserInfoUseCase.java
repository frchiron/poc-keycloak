package com.example.sso.appa.application.port.in;

import com.example.sso.appa.domain.model.User;

public interface GetUserInfoUseCase {
    User getUserInfo(String token);
}
