package io.jzheaux.springsecurity.resolutions;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;


@Entity(name="users")
public class User implements Serializable {
  public User() {}

  public User(String username, String password) {
    this.id = UUID.randomUUID();
    this.username = username;
    this.password = password;
  }

  public User(User user) {
    this.id = user.id;
    this.username = user.username;
    this.password = user.password;
    this.enabled = user.enabled;
    this.fullName = user.fullName;
    this.userAuthorities = user.userAuthorities;
  }

  static class BridgeUser extends User implements UserDetails {
    private Collection<GrantedAuthority> authorities;

    public BridgeUser(User user, Collection<GrantedAuthority> authorities) {
      super(user);
      this.authorities = authorities;
    }

    public Collection<GrantedAuthority> getAuthorities() {
      return this.authorities;
    }

    @Override
    public String getPassword() {
      return password;
    }

    @Override
    public String getUsername() {
      return username;
    }

    public boolean isAccountNonExpired() {
      return this.enabled;
    }

    public boolean isAccountNonLocked() {
      return this.enabled;
    }

    public boolean isCredentialsNonExpired() {
      return this.enabled;
    }

    @Override
    public boolean isEnabled() {
      return this.enabled;
    }
  }

  @Id
  UUID id;

  @Column
  String username;

  @Column
  String password;

  @Column
  boolean enabled = true;

  @Column(name= "full_name")
  String fullName;

  @OneToMany(fetch=FetchType.EAGER, cascade=CascadeType.ALL)
  Collection<UserAuthority> userAuthorities = new ArrayList<>();

  public Collection<UserAuthority> getUserAuthorities() {
    return Collections.unmodifiableCollection(this.userAuthorities);
  }

  public void grantAuthority(String authority) {
    UserAuthority userAuthority = new UserAuthority(this, authority);
    this.userAuthorities.add(userAuthority);
  }

  public String getFullName() {
    return fullName;
  }

  public void setFullName(String fullName) {
    this.fullName = fullName;
  }
}