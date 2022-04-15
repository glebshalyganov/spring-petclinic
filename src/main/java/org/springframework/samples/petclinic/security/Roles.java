package org.springframework.samples.petclinic.security;

import org.springframework.stereotype.Component;

@Component
public class Roles {

	public final String ADMIN = "ROLE_ADMIN";
	public final String USER = "ROLE_USER";
	public final String VET = "ROLE_VET";

}
