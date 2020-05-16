package io.jzheaux.springsecurity.resolutions;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;

public class UserRepositoryOpaqueTokenIntrospector implements OpaqueTokenIntrospector {
	private final UserRepository users;
	private final OpaqueTokenIntrospector delegate;

	public UserRepositoryOpaqueTokenIntrospector(UserRepository users, OpaqueTokenIntrospector delegate) {
		this.users = users;
		this.delegate = delegate;
	}

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String token) {
		OAuth2AuthenticatedPrincipal principal = this.delegate.introspect(token);
		return this.users.findByUsername(principal.getName())
				.map(user -> {
					Collection<GrantedAuthority> authorities = new ArrayList<>();
					principal.getAuthorities().stream()
							.map(authority -> new SimpleGrantedAuthority(authority.getAuthority().substring(6)))
							.collect(Collectors.toCollection(() -> authorities));
					Collection<GrantedAuthority> userAuthorities = user.getUserAuthorities().stream()
							.map(authority -> new SimpleGrantedAuthority(authority.getAuthority()))
							.collect(Collectors.toList());
					authorities.retainAll(userAuthorities);
					if ("premium".equals(user.getSubscription()) &&
							authorities.contains(new SimpleGrantedAuthority("resolution:write"))) {
						authorities.add(new SimpleGrantedAuthority("resolution:share"));
					}
					return new DefaultOAuth2AuthenticatedPrincipal(principal.getAttributes(), authorities);
				})
				.orElseThrow(() -> new UsernameNotFoundException("no user"));
	}
}
