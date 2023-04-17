package io.jzheaux.springsecurity.resolutions;

import java.util.Optional;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.stereotype.Component;

@Component("post")
public class ResolutionAuthorizer {
  public boolean filter(MethodSecurityExpressionOperations operations) {
    if (operations.hasRole("ADMIN")) {
      return true;
    }
    return ((Resolution)operations.getFilterObject()).getOwner().equals(operations.getAuthentication().getName());
  }

  public boolean authorize(MethodSecurityExpressionOperations operations) {
    if (operations.hasRole("ADMIN")) {
      return true;
    }
    return ((Optional<Resolution>)operations.getReturnObject()).map(Resolution::getOwner).filter(owner -> owner.equals(operations.getAuthentication().getName())).isPresent();
  }
}
