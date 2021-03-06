package com.fwchen.octopus.gateway.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class AuthGatewayFilterFactory
    extends AbstractGatewayFilterFactory<AuthGatewayFilterFactory.Config> {

  @Value("${jwt.header.key}")
  private String headerKey;

  @Value("${jwt.secret.key}")
  private String secretKey;

  public AuthGatewayFilterFactory() {
    super(Config.class);
  }

  @Override
  public GatewayFilter apply(Config config) {
    return (exchange, chain) -> {
      String token = exchange.getRequest().getHeaders().getFirst(headerKey);
      if (token == null || token.isEmpty()) {
        return rejectUnAuthRequest(exchange);
      }
      try {
        DecodedJWT jwt = verifyJWT(token);
        String userId = verifyClaimUserID(jwt);
        String role = verifyClaimUserRole(jwt);
        ServerHttpRequest mutableReq =
            exchange
                .getRequest()
                .mutate()
                .header("X-App-Auth-UserID", userId)
                .header("X-App-Auth-Role", role)
                .build();
        ServerWebExchange mutableExchange = exchange.mutate().request(mutableReq).build();
        return chain.filter(mutableExchange);
      } catch (JWTVerificationException e) {
        return rejectUnAuthRequest(exchange);
      }
    };
  }

  private Mono<Void> rejectUnAuthRequest(ServerWebExchange exchange) {
    ServerHttpResponse response = exchange.getResponse();
    response.setStatusCode(HttpStatus.UNAUTHORIZED);
    return response.setComplete();
  }

  private String verifyClaimUserID(DecodedJWT jwt) {
    return jwt.getClaim("userId").asString();
  }

  private String verifyClaimUserRole(DecodedJWT jwt) {
    return jwt.getClaim("role").asString();
  }

  private DecodedJWT verifyJWT(String token) {
    Algorithm algorithm = Algorithm.HMAC256(secretKey);
    JWTVerifier verifier = JWT.require(algorithm).build();
    return verifier.verify(token);
  }

  public static class Config {}
}