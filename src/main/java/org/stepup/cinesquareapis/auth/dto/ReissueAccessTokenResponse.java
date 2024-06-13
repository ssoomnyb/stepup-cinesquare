package org.stepup.cinesquareapis.auth.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ReissueAccessTokenResponse {
    private String accessToken;

    private String refreshToken;

    public ReissueAccessTokenResponse() {}

    public ReissueAccessTokenResponse(String accessToken, String refreshToken) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
    }
}