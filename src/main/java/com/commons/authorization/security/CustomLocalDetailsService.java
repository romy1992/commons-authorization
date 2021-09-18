package com.commons.authorization.security;

import com.commons.authorization.security.message.ErrorMessage;
import com.commons.authorization.security.model.ModelConfig;
import com.commons.authorization.security.model.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.support.BasicAuthenticationInterceptor;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service("customLocalDetailsService")
public class CustomLocalDetailsService implements UserDetailsService {
  private static final Logger logger = LoggerFactory.getLogger(CustomLocalDetailsService.class);
  private static final String ERRORMESSAGE = ErrorMessage.CONNECT_FAILED;

  @Autowired private ModelConfig config;

  private String baseUrl;
  @Autowired private RestTemplate restTemplate;

  @PostConstruct
  public void setUp() {
    restTemplate = new RestTemplate();
    restTemplate
        .getInterceptors()
        .add(new BasicAuthenticationInterceptor(config.getUserId(), config.getPassword()));
    baseUrl = config.getProtocol() + config.getServer();

    if (config.getPort() != null) baseUrl += ":" + config.getPort();
  }

  @Override
  public UserDetails loadUserByUsername(String userId) throws UsernameNotFoundException {

    String errMsg;
    if (userId == null || userId.length() < 2) {
      errMsg = ErrorMessage.NAME_USER_NOT_VALID;
      logger.warn(errMsg);
      throw new UsernameNotFoundException(errMsg);
    }

    UserModel model = this.getHttpValue(userId);

    if (model == null) {
      errMsg = String.format(ErrorMessage.USER_NOT_FOUND, userId);
      logger.warn(errMsg);
      throw new UsernameNotFoundException(errMsg);
    }

    UserBuilder builder = User.withUsername(model.getEmail());
    builder.disabled(model.getActive());
    builder.password(model.getPassword());
    String[] profiles = model.getRoles().stream().map(a -> "ROLE_" + a).toArray(String[]::new);

    builder.authorities(profiles);

    return builder.build();
  }

  public UserModel getHttpValue(String userId) {
    try {
      return restTemplate.getForObject(
          Objects.requireNonNull(generatedURI(userId, config.getSrvUrl())), UserModel.class);
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return null;
    }
  }

  public List<UserModel> getAllUsers() {
    try {
      return restTemplate.getForObject(
          Objects.requireNonNull(generatedURI("", config.getSrvUrlGetAll())), List.class);
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return Collections.emptyList();
    }
  }

  public UserModel updateUsers(UserModel model) {
    String url = baseUrl + config.getSrvUrlUpdate();
    try {
      restTemplate.put(url, model, UserModel.class);
      return model;
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return null;
    }
  }

  public Boolean deleteUser(UUID idUser) {
    try {
      restTemplate.delete(Objects.requireNonNull(generatedURI(idUser, config.getSrvUrlDelete())));
      return true;
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return false;
    }
  }

  public UserModel insertUser(UserModel model) {
    try {
      return restTemplate.postForObject(
          Objects.requireNonNull(generatedURI("", config.getSrvUrlInsert())),
          model,
          UserModel.class);
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return null;
    }
  }

  public List<UserModel> search(String input) {
    try {
      return restTemplate.getForObject(
          Objects.requireNonNull(generatedURI(input, config.getSrvUrlSearch())), List.class);
    } catch (Exception e) {
      logger.warn(ERRORMESSAGE);
      return Collections.emptyList();
    }
  }

  private URI generatedURI(Object value, String basePath) {
    try {
      String srvUrl = baseUrl + basePath;
      return new URI(srvUrl + value);
    } catch (URISyntaxException e) {
      logger.warn("Error generated URI", e.getMessage());
      e.printStackTrace();
      return null;
    }
  }
}
