package com.commons.authorization.config;

import com.commons.authorization.security.JwtTokenAuthorizationOncePerRequestFilter;
import com.commons.authorization.security.JwtUnAuthorizedResponseAuthenticationEntryPoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class JWTWebSecurityConfigForServices extends WebSecurityConfigurerAdapter {

  protected static final String USER = "USER";
  protected static final String ADMIN = "ADMIN";
  protected static final String SUPER_ADMIN = "SUPER_ADMIN";

  protected static final String BASE_URL = "/api/fn/resource/";
  protected static final String[] USER_ALL = {
    "/brk-profile/save/entity",
    "/api/saveAndInsertLocal",
    "/api/refreshPassword/**",
    "/api/messageForRefreshPassword/**",
    "/api/city/controller/isVerified",
    "/api/city/getAllLocalVerifiedFromCity",
    "/api/city/getLocalByNameAndAddress",
    "/api/city/getAllCoordinates"
  };
  protected static final String[] USER_MATCHER = {"/getLogin/**"};
  protected static final String[] ADMIN_MATCHER = {
    BASE_URL + "save/entity/",
    BASE_URL + "get/entity/**",
    BASE_URL + "update/entity",
    BASE_URL + "delete/entity/**",
    BASE_URL + "getAll/entities/"
  };
  protected static final String[] SUPER_ADMIN_MATCHER = {"/api/interceptor/to/update/**"};

  @Value("${security.api.auth.uri}")
  public String authenticationPath;

  @Autowired
  private JwtUnAuthorizedResponseAuthenticationEntryPoint
      jwtUnAuthorizedResponseAuthenticationEntryPoint;

  @Autowired private JwtTokenAuthorizationOncePerRequestFilter jwtAuthenticationTokenFilter;

  @Autowired
  @Qualifier("customUserDetailsService")
  private UserDetailsService userDetailsService;

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoderBean());
  }

  @Bean
  public PasswordEncoder passwordEncoderBean() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity httpSecurity) throws Exception {
    httpSecurity
        .csrf()
        .disable()
        .exceptionHandling()
        .authenticationEntryPoint(jwtUnAuthorizedResponseAuthenticationEntryPoint)
        .and()
        .sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests()
        .antMatchers(USER_ALL)
        .permitAll()
        .antMatchers(USER_MATCHER)
        .hasAnyRole(USER)
        .antMatchers(ADMIN_MATCHER)
        .hasAnyRole(ADMIN)
        .antMatchers(SUPER_ADMIN_MATCHER)
        .hasAnyRole(SUPER_ADMIN)
        .anyRequest()
        .authenticated();

    httpSecurity.addFilterBefore(
        jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);

    httpSecurity.headers().frameOptions().sameOrigin().cacheControl();
  }

  @Override
  public void configure(WebSecurity webSecurity) {
    webSecurity
        .ignoring()
        .antMatchers(HttpMethod.POST, authenticationPath)
        .antMatchers(HttpMethod.OPTIONS, "/**")
        .and()
        .ignoring()
        .antMatchers(HttpMethod.GET, "/")
        .antMatchers(HttpMethod.POST, "/")
        .antMatchers(HttpMethod.PUT, "/");
  }

  @Bean
  @Override
  public AuthenticationManager authenticationManagerBean() throws Exception {
    return super.authenticationManagerBean();
  }
}
