package com.commons.authorization.controller;

import com.commons.authorization.security.CustomLocalDetailsService;
import com.commons.authorization.security.JwtTokenUtil;
import com.commons.authorization.security.message.ErrorMessage;
import com.commons.authorization.security.model.UserModel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@RestController
@CrossOrigin(
    origins = {
      "http://localhost:4200",
      "http://localhost:8100",
      "http://localhost:8200",
      "http://localhost:8101",
      "http://localhost:8201"
    })
public class JwtAuthenticationRestController {

  private static final Logger logger =
      LoggerFactory.getLogger(JwtAuthenticationRestController.class);

  @Value("${security.api.auth.header}")
  private String tokenHeader;

  @Autowired private AuthenticationManager authenticationManager;
  @Autowired private JwtTokenUtil jwtTokenUtil;

  @Autowired
  @Qualifier("customUserDetailsService")
  private CustomLocalDetailsService userDetailsService;

  @PostMapping(value = "${security.api.auth.uri}")
  public ResponseEntity<?> createAuthenticationToken(
      @RequestBody JwtTokenRequest authenticationRequest) throws AuthenticationException {

    authenticate(authenticationRequest.getEmail(), authenticationRequest.getPassword());

    final UserDetails userDetails =
        userDetailsService.loadUserByUsername(authenticationRequest.getEmail());

    final String token = jwtTokenUtil.generateToken(userDetails);
    UserModel model = userDetailsService.getHttpValue(authenticationRequest.getEmail());

    return ResponseEntity.ok(new JwtTokenResponse(token, model));
  }

  @GetMapping(value = "${security.api.auth.uri}")
  public ResponseEntity<?> refreshAndGetAuthenticationToken(HttpServletRequest request) {
    String authToken = request.getHeader(tokenHeader);
    final String token = authToken.substring(7);

    if (jwtTokenUtil.canTokenBeRefreshed(token)) {
      String refreshedToken = jwtTokenUtil.refreshToken(token);

      return ResponseEntity.ok(new JwtTokenResponse(refreshedToken));
    } else {
      return ResponseEntity.badRequest().body(null);
    }
  }

  @GetMapping(value = "getAll")
  public ResponseEntity<List<UserModel>> getAll() {
    return ResponseEntity.ok(userDetailsService.getAllUsers());
  }

  @PostMapping(value = "save")
  public ResponseEntity<UserModel> insert(@RequestBody UserModel model) {
    return ResponseEntity.ok(userDetailsService.insertUser(model));
  }

  @PutMapping(value = "update")
  public ResponseEntity<UserModel> update(@RequestBody UserModel model) {
    return ResponseEntity.ok(userDetailsService.updateUsers(model));
  }

  @DeleteMapping(value = "delete/{id}")
  public ResponseEntity<Boolean> delete(@PathVariable(name = "id") UUID id) {
    return ResponseEntity.ok(userDetailsService.deleteUser(id));
  }

  @GetMapping(value = "search/{value}")
  public ResponseEntity<List<UserModel>> search(@PathVariable(value = "value") String input) {
    return ResponseEntity.ok(userDetailsService.search(input));
  }

  @GetMapping(value = "getLogin/{value}")
  public ResponseEntity<UserModel> getByEmail(@PathVariable(value = "value") String input) {
    return ResponseEntity.ok(userDetailsService.getHttpValue(input));
  }

  @ExceptionHandler({AuthenticationException.class})
  public ResponseEntity<String> handleAuthenticationException(AuthenticationException e) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
  }

  private void authenticate(String username, String password) {
    Objects.requireNonNull(username);
    Objects.requireNonNull(password);
    try {
      authenticationManager.authenticate(
          new UsernamePasswordAuthenticationToken(username, password));
    } catch (DisabledException e) {
      logger.warn(ErrorMessage.USER_DISABLED);
      throw new AuthenticationException(ErrorMessage.USER_DISABLED, e);
    } catch (BadCredentialsException e) {
      logger.warn(ErrorMessage.INVALID_CREDENTIALS);
      throw new AuthenticationException(ErrorMessage.INVALID_CREDENTIALS, e);
    }
  }
}
