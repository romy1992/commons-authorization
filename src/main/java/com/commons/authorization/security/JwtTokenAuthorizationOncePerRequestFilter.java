package com.commons.authorization.security;

import com.commons.authorization.security.message.ErrorMessage;
import io.jsonwebtoken.ExpiredJwtException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

@Component
public class JwtTokenAuthorizationOncePerRequestFilter extends OncePerRequestFilter {

  private final Logger logger = LoggerFactory.getLogger(this.getClass());

  @Autowired
  @Qualifier("customUserDetailsService")
  private UserDetailsService userDetailsService;

  @Autowired private JwtTokenUtil jwtTokenUtil;

  @Value("${security.api.auth.header}")
  private String tokenHeader;

  private String requestTokenHeader;

  public String getTokenAuth() {
    return requestTokenHeader;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    this.requestTokenHeader = request.getHeader(this.tokenHeader);

    // Get Token by cookie for Web Socket
    Enumeration<String> cookie = request.getHeaders("cookie");
    if (cookie.hasMoreElements() && requestTokenHeader == null) {
      String generatedToken = tokenWebSocket(cookie.nextElement());
      if (generatedToken != null && generatedToken.contains("X-Authorization=Bearer "))
        this.requestTokenHeader = generatedToken.replace("X-Authorization=", "");
      else this.requestTokenHeader = generatedToken;
    }

    String username = null;
    String jwtToken = null;

    if (requestTokenHeader != null && requestTokenHeader.contains("Bearer ")) {
      jwtToken = requestTokenHeader.substring(7);

      try {
        username = jwtTokenUtil.getUsernameFromToken(jwtToken);
      } catch (IllegalArgumentException e) {
        logger.error(ErrorMessage.UNABLE_TO_OBTAIN_USER_ID, e);
      } catch (ExpiredJwtException e) {
        logger.warn(ErrorMessage.TOKEN_EXPIRED, e);
      }
    } else {
      logger.warn(ErrorMessage.INVALID_TOKEN);
    }

    //        logger.debug("JWT_TOKEN_USERNAME_VALUE '{}'", username);

    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

      UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

      if (jwtTokenUtil.validateToken(jwtToken, userDetails)) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
            new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities());

        usernamePasswordAuthenticationToken.setDetails(
            new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
      }
    }

    chain.doFilter(request, response);
  }

  private String tokenWebSocket(String cookie) {
    List<String> splitString = Arrays.asList(cookie.split(";"));
    return splitString.stream()
        .filter(a -> a.contains("X-Authorization=Bearer ") || a.contains("Bearer "))
        .findFirst()
        .orElse(null);
  }
}
