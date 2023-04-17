package io.jzheaux.springsecurity.resolutions;

import java.util.Collection;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType.BEARER;

@Component
public class UserRepositoryJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {
  private final UserRepository users;
  private final JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();

  public UserRepositoryJwtAuthenticationConverter(UserRepository users) {
    this.users = users;
    authoritiesConverter.setAuthorityPrefix("");
  }

  @Override
  public AbstractAuthenticationToken convert(Jwt jwt) {
    Optional<User> userOptional = users.findByUsername(jwt.getSubject());
    if (!userOptional.isPresent()) {
      throw new UsernameNotFoundException("no user");
    }
    OAuth2AccessToken credentials = new OAuth2AccessToken(BEARER, jwt.getTokenValue(), null, null);

    Collection<GrantedAuthority> authorities = this.authoritiesConverter.convert(jwt);
    authorities.retainAll(userOptional.get().getUserAuthorities().stream()
            .map(UserAuthority::getAuthority)
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    return new BearerTokenAuthentication(new UserOAuth2AuthenticatedPrincipal(userOptional.get(), jwt.getClaims(), authorities), credentials, authorities);
  }

  private static class UserOAuth2AuthenticatedPrincipal extends User
          implements OAuth2AuthenticatedPrincipal {

    private final Map<String, Object> attributes;
    private final Collection<GrantedAuthority> authorities;

    public UserOAuth2AuthenticatedPrincipal(User user, Map<String, Object> attributes, Collection<GrantedAuthority> authorities) {
      super(user);
      this.attributes = attributes;
      this.authorities = authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
      return this.attributes;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
      return this.authorities;
    }

    @Override
    public String getName() {
      return this.username;
    }
  }
}
