package com.commons.authorization.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource({"classpath:auth-local.properties"})
@Getter
@Setter
public class ConfigAuth {

  @Value("${configuration.api.srvUrl}")
  private String srvUrl;

  @Value("${configuration.api.userId}")
  private String userId;

  @Value("${configuration.api.password}")
  private String password;

  @Value("${configuration.api.protocol}")
  private String protocol;

  @Value("${configuration.api.server}")
  private String server;

  @Value("${configuration.api.port}")
  private String port;

  @Value("${configuration.api.srvUrlGetAll}")
  private String srvUrlGetAll;

  @Value("${configuration.api.srvUrlUpdate}")
  private String srvUrlUpdate;

  @Value("${configuration.api.srvUrlDelete}")
  private String srvUrlDelete;

  @Value("${configuration.api.srvUrlInsert}")
  private String srvUrlInsert;

  @Value("${configuration.api.srvUrlSearch}")
  private String srvUrlSearch;

  @Value("${security.api.auth.uri}")
  private String uri;

  @Value("${security.api.auth.refresh}")
  private String refresh;

  @Value("${security.api.auth.header}")
  private String header;

  @Value("${security.api.auth.prefix}")
  private String prefix;

  @Value("${security.api.auth.expiration}")
  private int expiration;

  @Value("${security.api.auth.secret}")
  private String secret;
}
