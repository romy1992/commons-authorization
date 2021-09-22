package com.commons.authorization.controller;

import com.commons.authorization.security.model.UserModel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
@AllArgsConstructor
public class JwtTokenResponse implements Serializable {

  private static final long serialVersionUID = 8317676219297719109L;
  private String token;
  private UserModel model;

  public JwtTokenResponse(String token) {
    this.token = token;
  }
}
