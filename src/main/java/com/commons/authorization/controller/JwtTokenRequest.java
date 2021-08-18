package com.commons.authorization.controller;

import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;

@Getter
@Setter
public class JwtTokenRequest implements Serializable {

  private static final long serialVersionUID = -5616176897013108345L;

  private String email;
  private String password;
}
