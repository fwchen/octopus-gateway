package com.fwchen.octopus.gateway;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class AuthService {
    @Value("${jwt.secret.key}")
    private String secretKey;

    @Value("${jwt.issuer.name}")
    private String issuerName;

    @Value("${jwt.token.expire.time}")
    private long tokenExpireTime;

    public String buildJWT(String accessToken){
        Date now = new Date();
        Algorithm algorithm = Algorithm.HMAC256(secretKey);
        return JWT.create()
                .withIssuer(issuerName)
                .withIssuedAt(now)
                .withExpiresAt(new Date(now.getTime() + tokenExpireTime))
                .withClaim("accessToken", accessToken)
                .sign(algorithm);
    }
}
