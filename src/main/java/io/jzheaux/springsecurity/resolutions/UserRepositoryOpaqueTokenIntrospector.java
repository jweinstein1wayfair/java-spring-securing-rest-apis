package io.jzheaux.springsecurity.resolutions;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

public class UserRepositoryOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
  private final OpaqueTokenIntrospector delegate;
  private final UserRepository users;

  public UserRepositoryOpaqueTokenIntrospector(OpaqueTokenIntrospector delegate, UserRepository users) {
    this.delegate = delegate;
    this.users = users;
  }

  @Override
  public OAuth2AuthenticatedPrincipal introspect(String token) {
    OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);
    Optional<User> userOptional = users.findByUsername(principal.getName());
    if (!userOptional.isPresent()) {
      throw new UsernameNotFoundException("no user");
    }
    List<GrantedAuthority> authorities = principal.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority).map(a -> a.substring(6)).map(SimpleGrantedAuthority::new)
            .collect(Collectors.toList());
    authorities.retainAll(userOptional.get().getUserAuthorities().stream()
            .map(UserAuthority::getAuthority)
            .map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
    boolean isPremium = "premium".equals(userOptional.get().getSubscription());
    boolean hasResolutionWrite = authorities.contains(new SimpleGrantedAuthority("resolution:write"));
    if (isPremium && hasResolutionWrite) {
      authorities.add(new SimpleGrantedAuthority("resolution:share"));
    }
    return new UserOAuth2AuthenticatedPrincipal(userOptional.get(), principal.getAttributes(), authorities);
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
