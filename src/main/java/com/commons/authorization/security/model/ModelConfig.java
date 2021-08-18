package com.commons.authorization.security.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties("configuration.api")
@Getter
@Setter
public class ModelConfig {

  private String srvUrl;

  private String userId;

  private String password;

  private String protocol;

  private String server;

  private String port;

  private String srvUrlGetAll;

  private String srvUrlUpdate;

  private String srvUrlDelete;

  private String srvUrlInsert;

  private String srvUrlSearch;
}
