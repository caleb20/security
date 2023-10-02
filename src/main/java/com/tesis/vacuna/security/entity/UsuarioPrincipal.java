package com.tesis.vacuna.security.entity;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class UsuarioPrincipal implements UserDetails {
	private String nombresApellidos;
	private String dni;
	private String email;
	private String fechaNacimiento;
	private Collection<? extends GrantedAuthority> authorities;

	public UsuarioPrincipal(String nombresApellidos, String dni, String email, String fechaNacimiento,
			Collection<? extends GrantedAuthority> authorities) {
		this.nombresApellidos = nombresApellidos;
		this.dni = dni;
		this.email = email;
		this.authorities = authorities;
		this.fechaNacimiento = fechaNacimiento;
	}

	public static UsuarioPrincipal build(Usuario usuario) {
		List<GrantedAuthority> authorities = usuario.getRoles().stream()
				.map(rol -> new SimpleGrantedAuthority(rol.getRolNombre().name())).collect(Collectors.toList());
		return new UsuarioPrincipal(usuario.getNombresApellidos(), usuario.getDni(), usuario.getEmail(),
				usuario.getFechaNacimiento(), authorities);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return authorities;
	}

	@Override
	public String getPassword() {
		return fechaNacimiento;
	}

	@Override
	public String getUsername() {
		return dni;
	}

	public String getFechaNacimiento() {
		return fechaNacimiento;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public String getNombre() {
		return nombresApellidos;
	}

	public String getEmail() {
		return email;
	}
}