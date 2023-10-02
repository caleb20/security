package com.tesis.vacuna.security.dto;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtDto {

	private String token;
	private String bearer = "Bearer";
	private String dni;
	private String nombresApellidos;
	private Collection<? extends GrantedAuthority> authorities;

	public JwtDto(String token, String dni, String nombresApellidos,
			Collection<? extends GrantedAuthority> authorities) {
		this.token = token;
		this.dni = dni;
		this.nombresApellidos = nombresApellidos;
		this.authorities = authorities;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getBearer() {
		return bearer;
	}

	public void setBearer(String bearer) {
		this.bearer = bearer;
	}

	public String getDni() {
		return dni;
	}

	public void setDni(String dni) {
		this.dni = dni;
	}

	public String getNombresApellidos() {
		return nombresApellidos;
	}

	public void setNombresApellidos(String nombresApellidos) {
		this.nombresApellidos = nombresApellidos;
	}

	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	public void setAuthorities(Collection<? extends GrantedAuthority> authorities) {
		this.authorities = authorities;
	}

}
