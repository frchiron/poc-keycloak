package com.example.sso.appc.application.port.in;

import com.example.sso.appc.domain.model.User;

public interface GetUserInfoUseCase {
    User getUserInfo(String token);
}
