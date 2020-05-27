package com.fwchen.octopus.gateway;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fwchen.octopus.gateway.response.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthService {
    @Value("${jwt.secret.key}")
    private String secretKey;

    public String buildJWT(TokenResponse.AccessToken accessToken){
        Date now = new Date();
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create()
                .withIssuer(accessToken.iss)
                .withIssuedAt(now)
                .withJWTId(accessToken.jti)
                .withSubject(accessToken.sub)
                .withAudience(accessToken.aud)
                .withExpiresAt(new Date(now.getTime() + accessToken.exp))
                .withClaim("userId", accessToken.userId)
                .sign(algorithm);
    }
}
