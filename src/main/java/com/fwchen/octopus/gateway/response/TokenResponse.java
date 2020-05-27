package com.fwchen.octopus.gateway.response;

public class TokenResponse {
  public AccessToken accessToken;

  public static class AccessToken {
    public String aud;
    public String iss;
    public String sub;
    public String jti;
    public long exp;
    public String userId;
  }
}
