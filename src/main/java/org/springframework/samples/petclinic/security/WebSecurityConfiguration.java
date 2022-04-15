package org.springframework.samples.petclinic.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().anyRequest().authenticated().and()
			.formLogin(withDefaults());
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.ldapAuthentication()
			.userDnPatterns("uid={0},ou=people")
			.groupSearchBase("ou=groups")
//			.authoritiesMapper(authoritiesMapper())
			.contextSource()
			.url("ldap://localhost:8399/dc=springframework,dc=org")
			.and()
			.passwordCompare()
			.passwordEncoder(new BCryptPasswordEncoder())
			.passwordAttribute("userPassword");

		//example login: ben, password: benspassword
	}

	protected GrantedAuthoritiesMapper authoritiesMapper() {
		return authorities -> {
			Map<String, String> roleCodesMap = new HashMap<>();
			roleCodesMap.put("ROLE_MANAGERS", "ROLE_ADMIN");
			roleCodesMap.put("ROLE_DEVELOPERS", "ROLE_USER");

			return authorities.stream()
				.map(GrantedAuthority::getAuthority)
				.map(s -> roleCodesMap.getOrDefault(s, s))
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());
		};
	}
}
