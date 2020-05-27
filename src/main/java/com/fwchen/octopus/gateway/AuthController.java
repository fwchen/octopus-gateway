package com.fwchen.octopus.gateway;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fwchen.octopus.gateway.request.LoginRequest;
import com.fwchen.octopus.gateway.response.TokenResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

@RestController
public class AuthController {

    private String headerKey;

    WebClient client;
    AuthService authService;

    AuthController(AuthService authService, @Value("${app.service.account}") String coreServiceUrl, @Value("${jwt.header.key}") String headerKey) {
        this.client = WebClient.create(coreServiceUrl);
        this.authService = authService;
        this.headerKey = headerKey;
    }

    @PostMapping("/token")
    Mono<ResponseEntity<Void>> login(@RequestBody LoginRequest loginRequest) {
        return client
                .post()
                .uri("token-issuer")
                .body(Mono.just(Map.of("username", loginRequest.getUsername(), "password", loginRequest.getPassword())), Map.class)
                .exchange()
                .flatMap(clientResponse -> {
                    if (!clientResponse.statusCode().equals(HttpStatus.OK)) {
                        return Mono.just(ResponseEntity.status(clientResponse.rawStatusCode()).build());
                    }
                    ObjectMapper mapper = new ObjectMapper();

                    return clientResponse.bodyToMono(TokenResponse.class).flatMap(token -> {
                        String jwt = null;
                        try {
                            jwt = authService.buildJWT(mapper.writeValueAsString(token.accessToken));
                        } catch (JsonProcessingException e) {
                            e.printStackTrace();
                        }
                        return Mono.just(ResponseEntity.ok().header(headerKey, jwt).build());
                    });
                });
    }
}
