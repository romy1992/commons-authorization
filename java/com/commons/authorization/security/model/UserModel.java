package com.commons.authorization.security.model;

import lombok.Getter;
import lombok.Setter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Getter
@Setter
public class UserModel {
  private UUID idUser;
  private String email;
  private String username;
  private String password;
  private boolean isLogged;
  private boolean isAdmin;
  private boolean isSuperAdmin;
  private LocalDateTime dateInscription;
  private Boolean active;
  private List<String> roles;
  private Boolean emailActive;
  private UUID tokenRefreshPwd;
}
