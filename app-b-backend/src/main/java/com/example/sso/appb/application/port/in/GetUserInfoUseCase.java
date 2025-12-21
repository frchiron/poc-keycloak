package com.example.sso.appb.application.port.in;

import com.example.sso.appb.domain.model.User;

public interface GetUserInfoUseCase {
    User getUserInfo(String token);
}
