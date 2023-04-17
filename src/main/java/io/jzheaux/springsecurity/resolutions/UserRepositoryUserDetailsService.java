package io.jzheaux.springsecurity.resolutions;

import java.util.Collection;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class UserRepositoryUserDetailsService implements UserDetailsService {
  private final UserRepository users;

  public UserRepositoryUserDetailsService(UserRepository users) {
    this.users = users;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    return this.users.findByUsername(username)
            .map(u -> {
              Collection<GrantedAuthority> authorities = u.getUserAuthorities().stream().flatMap(
                      (ua -> Stream.concat("ROLE_ADMIN" .equals(ua.authority) ? Stream.of(
                              new SimpleGrantedAuthority("resolution:read"),
                              new SimpleGrantedAuthority("resolution:write")
                      ) : Stream.of(), Stream.of(new SimpleGrantedAuthority(ua.authority))))).collect(Collectors.toSet());
              return new User.BridgeUser(u, authorities);
            })
            .orElseThrow(() -> new UsernameNotFoundException("invalid user"));
  }
}
